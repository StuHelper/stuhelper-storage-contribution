package contribution_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	cp "github.com/StuHelper/stuhelper-storage-contribution/postgres"
	"strings"
	"sync"
	"testing"
	"time"
)

type faultStore struct {
	contribution.Store
	mu         sync.Mutex
	staleTimes int
	delay      time.Duration
	higherCtrl *storage.ContributionControl
}

func (f *faultStore) InspectContribution(ctx context.Context, p contribution.Principal, id, owner string) (storage.ContributionSnapshot, error) {
	f.mu.Lock()
	d := f.delay
	hc := f.higherCtrl
	f.mu.Unlock()
	if d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return storage.ContributionSnapshot{}, ctx.Err()
		}
	}
	snap, err := f.Store.InspectContribution(ctx, p, id, owner)
	if err == nil && hc != nil {
		c := *hc
		snap.Control = &c
	}
	return snap, err
}

func (f *faultStore) ApplyContribution(ctx context.Context, p contribution.Principal, id string, c storage.ContributionControl) (storage.ContributionSnapshot, error) {
	f.mu.Lock()
	if f.staleTimes > 0 {
		f.staleTimes--
		f.mu.Unlock()
		return storage.ContributionSnapshot{}, storage.ErrStale
	}
	f.mu.Unlock()
	return f.Store.ApplyContribution(ctx, p, id, c)
}

func TestExitCompletesWhenCustodyAuthorizationAlreadyExpired(t *testing.T) {
	h := newFixture(t)
	now := h.clock.Now()

	for _, id := range []string{"sim", "unapplied", "early"} {
		_, e := h.store.Register(h.ctx, system, "reg-"+id, storage.Instance{
			ID: id, Adapter: "fixture", AccountDomain: "fixture:" + id,
			OwnerDomain: contribution.OwnerDomain(user), Ownership: "contributor",
			CredentialRef: "fixture-" + id, CredentialRevision: 1, Root: "isolated-" + id,
			State: "paused", Authorized: true, Limit: 0, ExpiresAt: now.Add(time.Hour),
			Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now.Add(time.Hour)}},
		})
		must(t, e)
	}

	// 1. Custody ExpiresAt == Consent Until == now + 1h, activated with zero replicas.
	vSim, e := h.s.Create(h.ctx, user, "create-sim", contribution.CreateRequest{
		InstanceID: "sim",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 0, Until: now.Add(time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest},
	})
	must(t, e)
	h.run(t)

	// 2. Custody ExpiresAt == +1h, Consent Until == +2h, activated with zero replicas.
	vEarly, e := h.s.Create(h.ctx, user, "create-early", contribution.CreateRequest{
		InstanceID: "early",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 0, Until: now.Add(2 * time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest},
	})
	must(t, e)
	h.run(t)

	// 3. Created but never applied before custody expires (Control == nil).
	vUnapplied, e := h.s.Create(h.ctx, user, "create-unapplied", contribution.CreateRequest{
		InstanceID: "unapplied",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 0, Until: now.Add(time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest},
	})
	must(t, e)

	// Advance past +1h so custody ExpiresAt is expired for all three, and Until is expired for sim & unapplied.
	h.clock.Add(61 * time.Minute)
	_, e = h.s.Sweep(h.ctx, 100, "")
	must(t, e)
	vEarly = h.get(t, vEarly.ID)
	vEarly = h.command(t, vEarly, "exit")

	for range 6 {
		err := h.s.RunOne(h.ctx, "worker")
		if errors.Is(err, contribution.ErrNotFound) {
			break
		}
		if !errors.Is(err, contribution.ErrDenied) {
			must(t, err)
		}
	}

	if got := h.get(t, vSim.ID); got.State != "exited" || got.Reason != "" || got.AppliedRevision != 1 {
		t.Fatalf("expected sim exited cleanly after simultaneous expiry, got state=%s reason=%s", got.State, got.Reason)
	}
	if got := h.get(t, vUnapplied.ID); got.State != "exited" || got.Reason != "" || got.AppliedRevision != 0 {
		t.Fatalf("expected unapplied exited cleanly without storage Control, got state=%s reason=%s", got.State, got.Reason)
	}

	// The earlier worker permanently blocked these jobs. Upgrade and repeat the migration.
	must(t, h.repo.Transaction(h.ctx, func(tx contribution.Transaction) error {
		j, err := tx.Job(vEarly.ID)
		if err != nil {
			return err
		}
		j.State = "blocked"
		return tx.SaveJob(j)
	}))
	for range 2 {
		_, e = h.admin.Exec(cp.Schema)
		must(t, e)
	}

	// early still has Control.Until > now on storage@v0.1.0, so once Until passes (+60m) periodic poll completes exit without password renewal.
	h.clock.Add(60 * time.Minute)
	for range 4 {
		err := h.s.RunOne(h.ctx, "worker")
		if errors.Is(err, contribution.ErrNotFound) {
			break
		}
	}
	if got := h.get(t, vEarly.ID); got.State != "exited" || got.Reason != "" {
		t.Fatalf("expected early exited once consent Until passed, got state=%s reason=%s", got.State, got.Reason)
	}
}

func TestHeartbeatPollDoesNotAmplifyOutboxAndAudit(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.run(t)
	v = h.get(t, v.ID)
	initialUpdated := v.UpdatedAt
	initialObserved := v.Observation.ObservedAt

	var initialOutbox, initialAudit int
	must(t, h.admin.QueryRow(`SELECT (SELECT count(*) FROM contribution.outbox),(SELECT count(*) FROM contribution.audit)`).Scan(&initialOutbox, &initialAudit))
	if initialOutbox != 2 || initialAudit != 2 {
		t.Fatalf("expected 2 initial events/audits, got %d/%d", initialOutbox, initialAudit)
	}

	for range 3 {
		h.clock.Add(time.Minute)
		h.run(t)
	}
	after := h.get(t, v.ID)
	if initialObserved == nil || after.Observation.ObservedAt == nil || !after.Observation.ObservedAt.Equal(*initialObserved) {
		t.Fatalf("heartbeat changed quota read time: %v vs %v", after.Observation.ObservedAt, initialObserved)
	}
	must(t, h.repo.Transaction(h.ctx, func(tx contribution.Transaction) error {
		r, err := tx.Record(v.ID)
		if err == nil && !r.SnapshotAt.After(*initialObserved) {
			t.Errorf("heartbeat did not refresh the internal snapshot: %v", r.SnapshotAt)
		}
		return err
	}))
	if !after.UpdatedAt.Equal(initialUpdated) {
		t.Fatalf("pure heartbeat poll mutated UpdatedAt: %v vs %v", after.UpdatedAt, initialUpdated)
	}
	var heartOutbox, heartAudit int
	must(t, h.admin.QueryRow(`SELECT (SELECT count(*) FROM contribution.outbox),(SELECT count(*) FROM contribution.audit)`).Scan(&heartOutbox, &heartAudit))
	if heartOutbox != 2 || heartAudit != 2 {
		t.Fatalf("heartbeat polls wrote redundant outbox/audit rows: %d/%d", heartOutbox, heartAudit)
	}

	// Material fact change (new replica / used bytes) MUST still emit outbox and audit.
	sum := sha256.Sum256([]byte("m"))
	obj, e := h.store.Create(h.ctx, system, "file-mat", storage.CreateRequest{
		Size: 1, SHA256: hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, e)
	_, e = h.store.Ingest(h.ctx, system, obj.ID, "write-mat", strings.NewReader("m"))
	must(t, e)
	h.clock.Add(time.Minute)
	h.run(t)
	var changedOutbox, changedAudit int
	must(t, h.admin.QueryRow(`SELECT (SELECT count(*) FROM contribution.outbox),(SELECT count(*) FROM contribution.audit)`).Scan(&changedOutbox, &changedAudit))
	if changedOutbox != 3 || changedAudit != 3 {
		t.Fatalf("expected material change to emit 3rd event/audit, got %d/%d", changedOutbox, changedAudit)
	}
}

func TestStaleStorageRevisionRetriesBeforeBlocking(t *testing.T) {
	h := newFixture(t)
	fs := &faultStore{Store: h.bridge, staleTimes: 1}
	svc, e := contribution.New(h.repo, h.policy, fs, h.cfg)
	must(t, e)
	h.s = svc

	// 1. Single transient storage.ErrStale race retries automatically and activates.
	v := h.create(t, "one")
	if err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected ErrConflict on transient stale race, got %v", err)
	}
	h.clock.Add(3 * time.Second)
	h.run(t)
	if got := h.get(t, v.ID); got.State != "active" || got.AppliedRevision != 1 {
		t.Fatalf("expected automatic recovery to active after transient ErrStale, got %+v", got)
	}

	// 2. If storage already holds a higher Control.Revision, block immediately without futile retries.
	v2 := h.create(t, "two")
	fs.mu.Lock()
	fs.higherCtrl = &storage.ContributionControl{ID: v2.ID, Revision: 99, State: "paused"}
	fs.mu.Unlock()
	if err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected ErrConflict on higher remote revision, got %v", err)
	}
	h.clock.Add(10 * time.Second)
	if err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, contribution.ErrNotFound) {
		t.Fatalf("expected immediate job block on higher remote revision, got %v", err)
	}
}

func TestSynchronizeTimeoutRecordsReasonAndBackoffWithoutShutdownAbort(t *testing.T) {
	h := newFixture(t)
	cfg := h.cfg
	cfg.OperationTimeout = time.Second
	cfg.Lease = 30 * time.Second
	fs := &faultStore{Store: h.bridge}
	svc, e := contribution.New(h.repo, h.policy, fs, cfg)
	must(t, e)
	h.s = svc

	v := h.create(t, "one")
	fs.delay = 1200 * time.Millisecond
	err := h.s.RunOne(h.ctx, "worker")
	if !errors.Is(err, contribution.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable when store times out while caller ctx is active, got %v", err)
	}
	got := h.get(t, v.ID)
	if got.State != "blocked" || got.Reason != "storage_unavailable" {
		t.Fatalf("expected blocked/storage_unavailable recorded after store timeout, got state=%s reason=%s", got.State, got.Reason)
	}
	// Backoff is 2s (not full 30s Lease!): once store recovers, +3s RunOne activates immediately.
	fs.mu.Lock()
	fs.delay = 0
	fs.mu.Unlock()
	h.clock.Add(3 * time.Second)
	h.run(t)
	if got = h.get(t, v.ID); got.State != "active" {
		t.Fatalf("expected recovery after 2s backoff instead of 30s lease wait, got %+v", got)
	}

	// Shutdown cancellation on caller runCtx must still return context.Canceled without detached writes.
	v2 := h.create(t, "two")
	fs.mu.Lock()
	fs.delay = 500 * time.Millisecond
	fs.mu.Unlock()
	shutCtx, cancelShut := context.WithTimeout(h.ctx, 100*time.Millisecond)
	defer cancelShut()
	if err = h.s.RunOne(shutCtx, "worker"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected caller context cancellation error during shutdown, got %v", err)
	}
	if got2 := h.get(t, v2.ID); got2.State != "pending" {
		t.Fatalf("expected canceled caller context to leave record pending under lease, got %+v", got2)
	}
}

func TestSweepSkipsUnexpiredRowLocksAndPrunesReplayBacklog(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.run(t)

	// Hold FOR UPDATE lock on unexpired contribution in a separate connection.
	tx, e := h.admin.BeginTx(h.ctx, nil)
	must(t, e)
	defer tx.Rollback()
	var raw string
	must(t, tx.QueryRow(`SELECT id FROM contribution.contributions WHERE id=$1 FOR UPDATE`, v.ID).Scan(&raw))

	// Insert more expired receipts than one bounded cleanup can process.
	past := h.clock.Now().Add(-time.Minute)
	_, e = h.admin.Exec(`INSERT INTO contribution.replays(key,expires_at,data)
    SELECT 'exp-' || i,$1,'{}'::jsonb FROM generate_series(1,1250) i`, past)
	must(t, e)

	sweepCtx, cancel := context.WithTimeout(h.ctx, 600*time.Millisecond)
	defer cancel()
	next, e := h.s.Sweep(sweepCtx, 100, "")
	if e != nil {
		t.Fatalf("Sweep blocked on unexpired locked row or failed: %v", e)
	}
	if next == "" {
		t.Fatal("cleanup backlog lost its continuation")
	}
	next, e = h.s.Sweep(sweepCtx, 100, next)
	must(t, e)
	if next != "" {
		t.Fatal(next)
	}
	var remaining int
	must(t, h.admin.QueryRow(`SELECT count(*) FROM contribution.replays WHERE expires_at <= $1`, h.clock.Now()).Scan(&remaining))
	if remaining != 0 {
		t.Fatalf("expected all expired replays pruned after continuation, %d remained", remaining)
	}
}
