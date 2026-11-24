package contribution_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/httpapi"
	cp "github.com/StuHelper/stuhelper-storage-contribution/postgres"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type schoolScopedPolicy struct {
	school string
}

func (p schoolScopedPolicy) Authorize(_ context.Context, actor contribution.Principal, action string, a contribution.Access) error {
	if action == "contributions.maintenance" {
		if actor == system {
			return nil
		}
		return contribution.ErrDenied
	}
	if strings.HasPrefix(action, "contributions.operations.") {
		if actor.Subject != "school-admin" || actor.Issuer != p.school {
			return contribution.ErrDenied
		}
		// General capability check has empty Owner; record-level check enforces school match.
		if a.Owner.Valid() && a.Owner.Issuer != p.school {
			return contribution.ErrDenied
		}
		return nil
	}
	if !actor.Valid() || actor != a.Owner {
		return contribution.ErrDenied
	}
	return nil
}

func TestWorkerSchedulerBoundaryCasesAndRuntimePrivilegeChecks(t *testing.T) {
	h := newFixture(t)

	// 1. Verify URI DSN parsing compatibility alongside key-value DSN.
	rawDSN := os.Getenv("STUHELPER_CONTRIBUTION_TEST_DSN")
	parsedCfg, err := pgx.ParseConfig(rawDSN)
	must(t, err)
	if parsedCfg.Host != "" && !strings.HasPrefix(parsedCfg.Host, "/") {
		uriDSN := fmt.Sprintf("postgres://%s@%s:%d/postgres?sslmode=disable", parsedCfg.User, parsedCfg.Host, parsedCfg.Port)
		uriDB := openTestDB(t, uriDSN, "", "")
		defer uriDB.Close()
		must(t, uriDB.PingContext(h.ctx))
	}

	// 2. Verify httpapi unified pageSize(r) and duplicate/unknown query parameter 400 checks.
	handler, err := httpapi.New(h.s, fixtureAuth{})
	must(t, err)
	srv := httptest.NewServer(handler)
	defer srv.Close()
	for _, bad := range []string{
		"/api/v1/storage-contributions?limit=10&limit=20",
		"/api/v1/storage-contributions?limit=notanint",
		"/api/v1/storage-contributions?unknown=1",
		"/api/v1/storage-contributions/options?after=a&after=b",
	} {
		req, err := http.NewRequestWithContext(h.ctx, "GET", srv.URL+bad, nil)
		must(t, err)
		req.Header.Set("Authorization", "Bearer fixture")
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Fatalf("expected 400 for %s, got %d", bad, res.StatusCode)
		}
	}

	// 3. Configure quota conflict & exit_overdue boundary tests.
	cfg := h.cfg
	cfg.Policy.ExitTargetSeconds = 60
	svc, err := contribution.New(h.repo, h.policy, h.bridge, cfg)
	must(t, err)
	h.s = svc

	one := h.create(t, "one")
	qTwo := h.request(t, "two")
	qThree := h.request(t, "three")

	h.run(t)
	payload := strings.Repeat("d", 32)
	sum := sha256.Sum256([]byte(payload))
	obj, err := h.store.Create(h.ctx, system, "sched-obj", storage.CreateRequest{
		Size: 32, SHA256: hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, err)
	_, err = h.store.Ingest(h.ctx, system, obj.ID, "ing-sched", strings.NewReader(payload))
	must(t, err)
	// Sync observation so UsedBytes == 32
	one = h.command(t, h.get(t, one.ID), "pause")
	h.run(t)
	one = h.get(t, one.ID)
	if one.Observation == nil || one.Observation.UsedBytes != 32 {
		t.Fatalf("expected UsedBytes=32, got %+v", one.Observation)
	}
	tooSmall := one.Conditions
	tooSmall.LimitBytes = 16
	if _, err := h.s.Command(h.ctx, user, one.ID, "cfg-conflict", contribution.CommandRequest{
		Revision: one.Revision, Action: "configure", Conditions: &tooSmall,
	}); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected configure conflict below occupied bytes, got %v", err)
	}

	// Trigger exit and advance past ExitTargetSeconds (60s) while quota (5m) stays valid -> exit_overdue.
	one = h.command(t, one, "exit")
	h.run(t)
	h.clock.Add(90 * time.Second)
	h.run(t)
	overdue := h.get(t, one.ID)
	if overdue.State != "exiting" || overdue.Reason != "exit_overdue" {
		t.Fatalf("expected exiting with exit_overdue, got %+v", overdue)
	}

	// Clean up replica so "one" can finish exiting.
	_, err = h.store.Delete(h.ctx, system, obj.ID, "del-sched", obj.Revision)
	must(t, err)
	_, err = h.store.RunOne(h.ctx, "storage-worker")
	must(t, err)

	// 4. Worker scheduler: bounded concurrency, multi-page Sweep (batchSize=1), and graceful 15s Stop.
	now := h.clock.Now()
	qTwo.Conditions.Until = now.Add(65 * time.Second)
	qThree.Conditions.Until = now.Add(65 * time.Second)
	two, err := h.s.Create(h.ctx, user, "create-two", qTwo)
	must(t, err)
	three, err := h.s.Create(h.ctx, user, "create-three", qThree)
	must(t, err)

	w, err := contribution.NewWorker(h.s, contribution.WorkerConfig{
		ID:             "sched-worker",
		Concurrency:    2,
		PollInterval:   15 * time.Millisecond,
		MaxIdleBackoff: 60 * time.Millisecond,
		SweepInterval:  50 * time.Millisecond,
		SweepBatchSize: 1,
		ShutdownBudget: 15 * time.Second,
	})
	must(t, err)
	must(t, w.Start(h.ctx))
	// Duplicate Start must return ErrConflict.
	if err := w.Start(h.ctx); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate Start, got %v", err)
	}

	waitState := func(id, want string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if h.get(t, id).State == want {
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s to reach %s (got %+v)", id, want, h.get(t, id))
	}
	waitState(two.ID, "active")
	waitState(three.ID, "active")

	// Advance clock past two & three's Until (65s) so paginated Sweep (SweepBatchSize=1) converts both to exiting -> exited!
	h.clock.Add(2 * time.Minute)
	waitState(one.ID, "exited")
	waitState(two.ID, "exited")
	waitState(three.ID, "exited")

	snap := w.Snapshot()
	if snap.Completed == 0 || snap.Sweeps == 0 {
		t.Fatalf("expected completed jobs and sweeps in snapshot, got %+v", snap)
	}

	stopCtx, cancelStop := context.WithTimeout(h.ctx, 5*time.Second)
	defer cancelStop()
	must(t, w.Stop(stopCtx))
	select {
	case <-w.Done():
	case <-time.After(time.Second):
		t.Fatal("worker Done channel not closed after Stop")
	}
	if w.Snapshot().Running {
		t.Fatal("expected Running=false after Stop")
	}

	// 5. Cross-school administrator authorization boundary.
	schoolAUser := contribution.Principal{Issuer: "urn:school-a", Subject: "student-a"}
	schoolBUser := contribution.Principal{Issuer: "urn:school-b", Subject: "student-b"}
	schoolAAdmin := contribution.Principal{Issuer: "urn:school-a", Subject: "school-admin"}
	tBase := h.clock.Now()
	// Reset clock near wall time so provider.Verify accepts new instance registrations.
	realNow := time.Now().UTC()
	if realNow.After(tBase) {
		h.clock.Add(realNow.Sub(tBase))
	}
	// Create an isolated second fixture specifically for cross-school and CheckRuntime negative cases.
	h2 := newFixture(t)
	scopedSvc, err := contribution.New(h2.repo, schoolScopedPolicy{school: "urn:school-a"}, h2.bridge, h2.cfg)
	must(t, err)
	now2 := h2.clock.Now()
	for _, item := range []struct {
		id    string
		owner contribution.Principal
	}{
		{"inst-a", schoolAUser},
		{"inst-b", schoolBUser},
	} {
		_, err = h2.store.Register(h2.ctx, system, "reg-"+item.id, storage.Instance{
			ID: item.id, Adapter: "fixture", AccountDomain: "dom:" + item.id, OwnerDomain: contribution.OwnerDomain(item.owner),
			Ownership: "contributor", CredentialRef: "fixture", CredentialRevision: 1, Root: "root-" + item.id,
			State: "paused", Authorized: true, Limit: 0, ExpiresAt: now2.Add(2 * time.Hour),
			Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now2.Add(2 * time.Hour)}},
		})
		must(t, err)
	}
	ca, err := scopedSvc.Create(h2.ctx, schoolAUser, "create-a", contribution.CreateRequest{
		InstanceID: "inst-a",
		Conditions: contribution.Conditions{LimitBytes: 512, PersonalReserve: 0, Until: now2.Add(time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h2.cfg.Policy.Terms.Version, Digest: h2.cfg.Policy.Terms.Digest},
	})
	must(t, err)
	cb, err := scopedSvc.Create(h2.ctx, schoolBUser, "create-b", contribution.CreateRequest{
		InstanceID: "inst-b",
		Conditions: contribution.Conditions{LimitBytes: 512, PersonalReserve: 0, Until: now2.Add(time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h2.cfg.Policy.Terms.Version, Digest: h2.cfg.Policy.Terms.Digest},
	})
	must(t, err)
	h2.bridge.fail = true
	for range 8 {
		_ = scopedSvc.RunOne(h2.ctx, "worker")
		h2.clock.Add(10 * time.Second)
	}

	scopedPage, err := scopedSvc.Operations(h2.ctx, schoolAAdmin, 20, "")
	must(t, err)
	if len(scopedPage.Items) != 1 || scopedPage.Items[0].ID != ca.ID {
		t.Fatalf("expected school-a admin to see only school-a record %s, got %+v", ca.ID, scopedPage.Items)
	}
	if _, err := scopedSvc.RetryOperation(h2.ctx, schoolAAdmin, cb.ID, "foreign-retry", contribution.RetryRequest{Revision: cb.Revision}); !errors.Is(err, contribution.ErrDenied) {
		t.Fatalf("expected ErrDenied retrying foreign school record, got %v", err)
	}

	// 6. CheckRuntime negative cases on real PostgreSQL roles.
	var currentDB string
	must(t, h2.admin.QueryRow(`SELECT current_database()`).Scan(&currentDB))
	badCases := []struct {
		suffix string
		grant  string
	}{
		{"createdb", `ALTER ROLE %s CREATEDB`},
		{"schema_create", `GRANT CREATE ON SCHEMA contribution TO %s`},
		{"foreign_storage", `GRANT USAGE ON SCHEMA storage TO %s`},
		{"audit_update", `GRANT UPDATE ON contribution.audit TO %s`},
		{"audit_truncate", `GRANT TRUNCATE ON contribution.audit TO %s`},
	}
	for _, tc := range badCases {
		badRole := fmt.Sprintf("%s_bad_%s", currentDB, tc.suffix)
		_, err := h2.admin.Exec(fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; GRANT USAGE ON SCHEMA contribution TO %s; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA contribution TO %s; REVOKE UPDATE,DELETE,TRUNCATE ON contribution.audit FROM %s; `+tc.grant, badRole, badRole, badRole, badRole, badRole))
		must(t, err)
		badDB := openTestDB(t, rawDSN, currentDB, badRole)
		badRepo := &cp.Repository{DB: badDB}
		err = badRepo.CheckRuntime(h2.ctx)
		badDB.Close()
		_, dropErr := h2.admin.Exec(fmt.Sprintf(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA contribution FROM %s; REVOKE ALL PRIVILEGES ON SCHEMA contribution, storage FROM %s; DROP ROLE %s`, badRole, badRole, badRole))
		must(t, dropErr)
		if !errors.Is(err, contribution.ErrDenied) {
			t.Fatalf("expected CheckRuntime ErrDenied for %s, got %v", tc.suffix, err)
		}
	}
}
