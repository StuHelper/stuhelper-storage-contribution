package contribution_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/httpapi"
	"github.com/StuHelper/stuhelper-storage-contribution/sdk"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOperationsFilteringJobProgressAndMetricsSnapshot(t *testing.T) {
	h := newFixture(t)
	cfg := h.cfg
	cfg.Policy.Adapters = []string{"fixture", "secondary"}
	cfg.Policy.ExitTargetSeconds = 60
	svc, err := contribution.New(h.repo, h.policy, h.bridge, cfg)
	must(t, err)
	h.s = svc

	now := h.clock.Now()
	_, err = h.store.Register(h.ctx, system, "reg-sec", storage.Instance{
		ID: "sec-1", Adapter: "secondary", AccountDomain: "secondary:1", OwnerDomain: contribution.OwnerDomain(user),
		Ownership: "contributor", CredentialRef: "fixture", CredentialRevision: 1, Root: "isolated-sec-1",
		State: "paused", Authorized: true, Limit: 1 << 20, ExpiresAt: now.Add(2 * time.Hour),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now.Add(2 * time.Hour)}},
	})
	must(t, err)

	// 1. Active contribution on "fixture" with replica, then revoked -> cleanup_unconfirmed
	one := h.create(t, "one")
	h.run(t)
	sum := sha256.Sum256([]byte("m"))
	obj, err := h.store.Create(h.ctx, system, "obj-m", storage.CreateRequest{
		Size: 1, SHA256: hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, err)
	_, err = h.store.Ingest(h.ctx, system, obj.ID, "ing-m", strings.NewReader("m"))
	must(t, err)
	one = h.command(t, h.get(t, one.ID), "revoke")
	h.run(t)

	// 2. Active contribution on "secondary" -> exiting -> exit_overdue
	qSec := contribution.CreateRequest{
		InstanceID: "sec-1",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 50, Until: now.Add(3 * time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: cfg.Policy.Terms.Version, Digest: cfg.Policy.Terms.Digest},
	}
	sec, err := h.s.Create(h.ctx, user, "create-sec", qSec)
	must(t, err)
	h.run(t)
	sum2 := sha256.Sum256([]byte("n"))
	obj2, err := h.store.Create(h.ctx, system, "obj-n", storage.CreateRequest{
		Size: 1, SHA256: hex.EncodeToString(sum2[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, err)
	_, err = h.store.Ingest(h.ctx, system, obj2.ID, "ing-n", strings.NewReader("n"))
	must(t, err)
	sec = h.command(t, h.get(t, sec.ID), "exit")
	h.run(t)

	// 3. Contribution "two" fails 1 attempt (blocked contribution, job_state=pending, attempts=1),
	// while "three" exhausts all 3 attempts (blocked contribution, job_state=blocked, attempts=3).
	qTwo := h.request(t, "two")
	qThree := h.request(t, "three")
	two, err := h.s.Create(h.ctx, user, "create-two", qTwo)
	must(t, err)
	h.bridge.fail = true
	if err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, contribution.ErrUnavailable) {
		t.Fatal(err)
	}

	three, err := h.s.Create(h.ctx, user, "create-three", qThree)
	must(t, err)
	for range 3 {
		// Claim orders by available_at: keep advancing so both/three reach expected states.
		if err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, contribution.ErrUnavailable) {
			t.Fatal(err)
		}
		h.clock.Add(10 * time.Second)
	}
	// Run remaining attempts until queue drains (both two and three exhausted -> job_state=blocked).
	for range 4 {
		err := h.s.RunOne(h.ctx, "worker")
		if errors.Is(err, contribution.ErrNotFound) {
			break
		}
		h.clock.Add(10 * time.Second)
	}

	// Re-retry "two" once and fail once so "two" is state=blocked with job_state=pending (attempts=1),
	// whereas "three" is state=blocked with job_state=blocked (attempts=3)!
	retryTwo, err := h.s.RetryOperation(h.ctx, operator, two.ID, "op-retry-two", contribution.RetryRequest{Revision: h.get(t, two.ID).Revision})
	must(t, err)
	if retryTwo.JobState != "pending" || retryTwo.Attempts == nil || *retryTwo.Attempts != 0 || retryTwo.MaxAttempts == nil || *retryTwo.MaxAttempts != 3 {
		t.Fatalf("expected pending job metadata on RetryOperation, got %+v", retryTwo)
	}
	if err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, contribution.ErrUnavailable) {
		t.Fatal(err)
	}

	// Advance past ExitTargetSeconds (60s) while storage quota (5m) remains fresh so exit_overdue is recorded.
	h.bridge.fail = false
	h.clock.Add(90 * time.Second)
	// Run sec-1 refresh (and two's pending retry -> active!).
	for range 3 {
		err := h.s.RunOne(h.ctx, "worker")
		if errors.Is(err, contribution.ErrNotFound) {
			break
		}
	}

	// User Get/List must NOT expose internal job_state fields.
	userView := h.get(t, three.ID)
	if userView.JobState != "" || userView.Attempts != nil || userView.MaxAttempts != nil || userView.AvailableAt != nil {
		t.Fatalf("job fields leaked to contributor view: %+v", userView)
	}

	// Filter by state=blocked via HTTP SDK + test unknown/duplicate query param 400 rejection.
	handler, err := httpapi.New(h.s, tokenRoleAuth{})
	must(t, err)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	adminClient, err := sdk.NewClientWithResponses(srv.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer operator")
		return nil
	}))
	must(t, err)

	blockedState := sdk.ListContributionOperationsParamsStateBlocked
	blockedPage, err := adminClient.ListContributionOperationsWithResponse(h.ctx, &sdk.ListContributionOperationsParams{State: &blockedState})
	must(t, err)
	if blockedPage.StatusCode() != 200 || blockedPage.JSON200 == nil || len(blockedPage.JSON200.Items) != 1 {
		t.Fatalf("expected 1 blocked operation, got %d %s", blockedPage.StatusCode(), string(blockedPage.Body))
	}
	item := blockedPage.JSON200.Items[0]
	if item.Id != three.ID || item.JobState == nil || string(*item.JobState) != "blocked" || item.Attempts == nil || *item.Attempts != 3 || item.MaxAttempts == nil || *item.MaxAttempts != 3 {
		t.Fatalf("unexpected blocked job details: %+v", item)
	}

	// Filter by adapter=secondary & reason=exit_overdue
	secAdapter := "secondary"
	overdueReason := sdk.ExitOverdue
	secPage, err := adminClient.ListContributionOperationsWithResponse(h.ctx, &sdk.ListContributionOperationsParams{Adapter: &secAdapter, Reason: &overdueReason})
	must(t, err)
	if secPage.StatusCode() != 200 || secPage.JSON200 == nil || len(secPage.JSON200.Items) != 1 || secPage.JSON200.Items[0].Id != sec.ID {
		t.Fatalf("expected secondary exit_overdue item, got %d %s", secPage.StatusCode(), string(secPage.Body))
	}

	// Filter by dynamic reason=observation_stale on active contribution "two" after advancing clock > ObservationMaxAgeSeconds (2m).
	h.clock.Add(3 * time.Minute)
	staleReason := sdk.ObservationStale
	stalePage, err := adminClient.ListContributionOperationsWithResponse(h.ctx, &sdk.ListContributionOperationsParams{Reason: &staleReason})
	must(t, err)
	if stalePage.StatusCode() != 200 || stalePage.JSON200 == nil || len(stalePage.JSON200.Items) != 1 || stalePage.JSON200.Items[0].Id != two.ID {
		t.Fatalf("expected dynamic observation_stale filter to match two, got %d %s", stalePage.StatusCode(), string(stalePage.Body))
	}

	// Unknown or duplicate query parameters on /operations must return 400.
	for _, badPath := range []string{
		"/api/v1/storage-contributions/operations?sttae=blocked",
		"/api/v1/storage-contributions/operations?state=blocked&state=active",
		"/api/v1/storage-contributions/operations?reason=unknown_reason",
		"/api/v1/storage-contributions/policy?extra=1",
	} {
		req, err := http.NewRequestWithContext(h.ctx, "GET", srv.URL+badPath, nil)
		must(t, err)
		req.Header.Set("Authorization", "Bearer operator")
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Fatalf("expected 400 for %s, got %d", badPath, res.StatusCode)
		}
	}

	// MetricsSnapshot: denied for contributor, allowed for system actor and operator.
	if _, err := h.s.MetricsSnapshot(h.ctx, user); !errors.Is(err, contribution.ErrDenied) {
		t.Fatalf("expected contributor denied metrics, got %v", err)
	}
	sysMetrics, err := h.s.MetricsSnapshot(h.ctx, system)
	must(t, err)
	if sysMetrics.ByState["revoked"] != 1 || sysMetrics.ByState["exiting"] != 1 || sysMetrics.ByState["blocked"] != 1 || sysMetrics.ByState["active"] != 1 || sysMetrics.CleanupUnconfirmed != 1 || sysMetrics.ExitOverdue != 1 || sysMetrics.PendingOutbox == 0 || sysMetrics.ByJobState["blocked"] != 1 || sysMetrics.ByJobState["complete"] != 1 {
		t.Fatalf("unexpected metrics snapshot: %+v", sysMetrics)
	}
	httpMetrics, err := adminClient.GetContributionMetricsWithResponse(h.ctx)
	must(t, err)
	if httpMetrics.StatusCode() != 200 || httpMetrics.JSON200 == nil || httpMetrics.JSON200.CleanupUnconfirmed != 1 || httpMetrics.JSON200.ExitOverdue != 1 {
		t.Fatalf("unexpected HTTP metrics response: %d %s", httpMetrics.StatusCode(), string(httpMetrics.Body))
	}
}

type tokenRoleAuth struct{}

func (tokenRoleAuth) Authenticate(r *http.Request) (contribution.Principal, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer operator":
		return operator, nil
	case "Bearer fixture":
		return user, nil
	default:
		return contribution.Principal{}, contribution.ErrDenied
	}
}
