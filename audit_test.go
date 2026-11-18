package contribution_test

import (
	"context"
	"encoding/json"
	"errors"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/auditquery"
	"strings"
	"testing"
	"time"
)

var auditor = contribution.Principal{Issuer: "urn:fixture", Subject: "auditor"}

type auditAwarePolicy struct{}

func (auditAwarePolicy) Authorize(_ context.Context, actor contribution.Principal, action string, a contribution.Access) error {
	switch {
	case action == "contributions.audit.read":
		if actor == auditor {
			return nil
		}
		return contribution.ErrDenied
	case strings.HasPrefix(action, "contributions.operations."):
		if actor == operator {
			return nil
		}
		return contribution.ErrDenied
	case action == "contributions.maintenance":
		if actor == system {
			return nil
		}
		return contribution.ErrDenied
	default:
		if actor == user && a.Owner == user {
			return nil
		}
		return contribution.ErrDenied
	}
}

func TestStructuredAuditDeniedAttemptsAndSnapshotPagination(t *testing.T) {
	h := newFixture(t)
	svc, err := contribution.New(h.repo, auditAwarePolicy{}, h.bridge, h.cfg)
	must(t, err)
	h.s = svc

	// 1. User creates a contribution -> contribution.requested (result=success)
	v := h.create(t, "one")
	h.clock.Add(time.Second)

	// 2. Unauthorized foreign user attempts Get & Command -> ErrDenied + denied audit rows!
	intruder := contribution.Principal{Issuer: "urn:other-school", Subject: "intruder"}
	if _, err := h.s.Get(h.ctx, intruder, v.ID); !errors.Is(err, contribution.ErrDenied) {
		t.Fatalf("expected ErrDenied on foreign Get, got %v", err)
	}
	h.clock.Add(time.Second)
	if _, err := h.s.Command(h.ctx, intruder, v.ID, "hijack", contribution.CommandRequest{Revision: v.Revision, Action: "pause"}); !errors.Is(err, contribution.ErrDenied) {
		t.Fatalf("expected ErrDenied on foreign Command, got %v", err)
	}
	h.clock.Add(time.Second)

	// 3. Exhaust worker retries so record enters blocked, then operator reads /operations and runs RetryOperation.
	h.bridge.fail = true
	for range 3 {
		_ = h.s.RunOne(h.ctx, "worker")
		h.clock.Add(10 * time.Second)
	}
	opsPage, err := h.s.Operations(h.ctx, operator, 20, "")
	must(t, err)
	if len(opsPage.Items) != 1 || opsPage.Items[0].State != "blocked" {
		t.Fatal(opsPage)
	}
	h.clock.Add(time.Second)

	retried, err := h.s.RetryOperation(h.ctx, operator, v.ID, "admin-retry-1", contribution.RetryRequest{Revision: v.Revision})
	must(t, err)
	if retried.Revision != v.Revision+1 {
		t.Fatal(retried)
	}
	h.clock.Add(time.Second)

	// Verify outbox contains distinct contribution.operation_retried event for administrator retry.
	events, err := h.repo.PendingEvents(h.ctx, 100)
	must(t, err)
	foundAdminRetried := false
	for _, ev := range events {
		if ev.Type == "contribution.operation_retried" && ev.Subject == v.ID {
			foundAdminRetried = true
		}
	}
	if !foundAdminRetried {
		t.Fatalf("expected contribution.operation_retried in outbox, got %+v", events)
	}

	// 4. Audit read permission isolation: contributor, system actor, and operations admin are ALL denied ReadAudit!
	baseReq := auditquery.Request{
		Scopes: []auditquery.Scope{{School: "*", Group: "*", Module: "storage-contribution"}},
		Until:  h.clock.Now().Add(time.Hour),
		Limit:  50,
	}
	for _, unauthorized := range []contribution.Principal{user, system, operator} {
		if _, err := h.s.ReadAudit(h.ctx, unauthorized, baseReq); !errors.Is(err, contribution.ErrDenied) {
			t.Fatalf("expected ErrDenied for %v reading audit, got %v", unauthorized, err)
		}
	}

	// 5. Dedicated auditor reads structured audit records with pagination, target/action/school filters, and snapshot isolation.
	page1, err := h.s.ReadAudit(h.ctx, auditor, auditquery.Request{
		Scopes: []auditquery.Scope{{School: "*", Group: "*", Module: "storage-contribution"}},
		Until:  h.clock.Now().Add(time.Hour),
		Limit:  2,
	})
	must(t, err)
	if len(page1.Records) != 2 || page1.Snapshot == "" {
		t.Fatalf("expected 2 records and snapshot token, got %+v", page1)
	}

	// Insert a late audit row AFTER page1's snapshot was captured; continuing with page1.Snapshot must exclude the late commit!
	h.clock.Add(time.Second)
	if _, err := h.s.Operations(h.ctx, user, 20, ""); !errors.Is(err, contribution.ErrDenied) {
		t.Fatal(err)
	}
	last := page1.Records[len(page1.Records)-1]
	page2, err := h.s.ReadAudit(h.ctx, auditor, auditquery.Request{
		Scopes:   []auditquery.Scope{{School: "*", Group: "*", Module: "storage-contribution"}},
		Until:    h.clock.Now().Add(time.Hour),
		Snapshot: page1.Snapshot,
		Before:   &auditquery.Position{Time: last.CreatedAt, Source: last.Source, ID: last.ID},
		Limit:    100,
	})
	must(t, err)
	allSnapshot := append(append([]auditquery.Record{}, page1.Records...), page2.Records...)

	// Check sanitized content and presence of expected actions/results.
	raw, err := json.Marshal(allSnapshot)
	must(t, err)
	if strings.Contains(string(raw), "fixture:one") || strings.Contains(string(raw), "credential") {
		t.Fatalf("sensitive data leaked in ReadAudit: %s", string(raw))
	}

	hasRetried := false
	hasOpsRead := false
	hasDeniedGet := false
	hasDeniedAuditRead := false
	for _, rec := range allSnapshot {
		if rec.Source != "storage-contribution" || rec.Scope.Module != "storage-contribution" {
			t.Fatalf("unexpected audit source/module: %+v", rec)
		}
		if rec.Action == "contribution.operation_retried" && rec.Target == v.ID && rec.Result == "success" {
			hasRetried = true
		}
		if rec.Action == "contributions.operations.read" && rec.Target == "operations" && rec.Result == "success" {
			hasOpsRead = true
		}
		if rec.Action == "contributions.read" && rec.Target == v.ID && rec.Result == "denied" && rec.Reason == "permission_denied" {
			hasDeniedGet = true
		}
		if rec.Action == "contributions.audit.read" && rec.Target == "audit" && rec.Result == "denied" {
			hasDeniedAuditRead = true
		}
	}
	if !hasRetried || !hasOpsRead || !hasDeniedGet || !hasDeniedAuditRead {
		t.Fatalf("missing expected audit entries: retried=%v opsRead=%v deniedGet=%v deniedAudit=%v records=%+v",
			hasRetried, hasOpsRead, hasDeniedGet, hasDeniedAuditRead, allSnapshot)
	}

	// Filter by target=v.ID and school=urn:fixture
	scopedTarget, err := h.s.ReadAudit(h.ctx, auditor, auditquery.Request{
		Scopes: []auditquery.Scope{{School: "urn:fixture", Group: "*", Module: "storage-contribution"}},
		Target: v.ID,
		Action: "contribution.operation_retried",
		Until:  h.clock.Now().Add(time.Hour),
		Limit:  10,
	})
	must(t, err)
	if len(scopedTarget.Records) != 1 || scopedTarget.Records[0].Target != v.ID {
		t.Fatalf("expected 1 filtered operation_retried record for %s, got %+v", v.ID, scopedTarget.Records)
	}

	// Retention DELETE via migration/admin connection invalidates existing snapshot token!
	_, err = h.admin.Exec(`DELETE FROM contribution.audit WHERE id=$1`, scopedTarget.Records[0].ID)
	must(t, err)
	if _, err := h.s.ReadAudit(h.ctx, auditor, auditquery.Request{
		Scopes:   []auditquery.Scope{{School: "*", Group: "*", Module: "storage-contribution"}},
		Until:    h.clock.Now().Add(time.Hour),
		Snapshot: page1.Snapshot,
		Limit:    10,
	}); !errors.Is(err, contribution.ErrUnavailable) {
		t.Fatalf("expected invalidated snapshot after retention delete, got %v", err)
	}
}
