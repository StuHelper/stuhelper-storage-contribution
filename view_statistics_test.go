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

type skewStore struct {
	contribution.Store
	mu       sync.Mutex
	skew     time.Duration
	override *storage.ContributionSnapshot
}

func (s *skewStore) InspectContribution(ctx context.Context, p contribution.Principal, id, owner string) (storage.ContributionSnapshot, error) {
	s.mu.Lock()
	ov := s.override
	skew := s.skew
	s.mu.Unlock()
	if ov != nil && ov.InstanceID == id {
		out := *ov
		out.ObservedAt = out.ObservedAt.Add(skew)
		return out, nil
	}
	snap, err := s.Store.InspectContribution(ctx, p, id, owner)
	snap.ObservedAt = snap.ObservedAt.Add(skew)
	return snap, err
}

func (s *skewStore) ApplyContribution(ctx context.Context, p contribution.Principal, id string, c storage.ContributionControl) (storage.ContributionSnapshot, error) {
	snap, err := s.Store.ApplyContribution(ctx, p, id, c)
	s.mu.Lock()
	skew := s.skew
	s.mu.Unlock()
	snap.ObservedAt = snap.ObservedAt.Add(skew)
	return snap, err
}

func TestRevokeExcludesCleanRecordAndTracksUnconfirmedCleanup(t *testing.T) {
	h := newFixture(t)
	ss := &skewStore{Store: h.bridge}
	svc, e := contribution.New(h.repo, h.policy, ss, h.cfg)
	must(t, e)
	h.s = svc

	// 1. Clean revoke with zero replicas/usage must not lock public statistics to partial.
	v1 := h.create(t, "clean-revoke")
	h.run(t)
	v1 = h.get(t, v1.ID)
	v1 = h.command(t, v1, "revoke")
	h.run(t)
	v1 = h.get(t, v1.ID)
	if v1.State != "revoked" || v1.Reason != "" {
		t.Fatalf("expected clean revoked state, got %+v", v1)
	}
	stats, e := h.s.Statistics(h.ctx)
	must(t, e)
	if stats.Contributions != 0 || stats.FreshObservations != 0 || stats.Status != "current" {
		t.Fatalf("clean revoked record polluted public statistics: %+v", stats)
	}

	// 2. Revoke while holding a replica keeps read-only observation polling until ledger clears.
	now := h.clock.Now()
	_, e = h.store.Register(h.ctx, system, "register-dirty", storage.Instance{
		ID: "dirty", Adapter: "fixture", AccountDomain: "fixture:dirty",
		OwnerDomain: contribution.OwnerDomain(user), Ownership: "contributor",
		CredentialRef: "fixture-dirty", CredentialRevision: 1, Root: "isolated-dirty",
		State: "paused", Authorized: true, Limit: 1 << 20, ExpiresAt: now.Add(4 * time.Hour),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now.Add(4 * time.Hour)}},
	})
	must(t, e)
	v2, e := h.s.Create(h.ctx, user, "create-dirty", contribution.CreateRequest{
		InstanceID: "dirty",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 100, Until: now.Add(2 * time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest},
	})
	must(t, e)
	h.run(t)
	v2 = h.get(t, v2.ID)

	sum := sha256.Sum256([]byte("z"))
	obj, e := h.store.Create(h.ctx, system, "file-dirty", storage.CreateRequest{
		Size: 1, SHA256: hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, e)
	_, e = h.store.Ingest(h.ctx, system, obj.ID, "write-dirty", strings.NewReader("z"))
	must(t, e)

	v2 = h.command(t, v2, "revoke")
	h.run(t)
	v2 = h.get(t, v2.ID)
	if v2.State != "revoked" || v2.Reason != "cleanup_unconfirmed" {
		t.Fatalf("expected revoked with cleanup_unconfirmed, got %+v", v2)
	}

	// If observation becomes stale, stale UsedBytes must not be counted and status becomes partial.
	h.clock.Add(3 * time.Minute)
	staleStats, e := h.s.Statistics(h.ctx)
	must(t, e)
	if staleStats.Status != "partial" || staleStats.UsedBytes != 0 {
		t.Fatalf("expected stale cleanup_unconfirmed to report partial with 0 fresh used bytes, got %+v", staleStats)
	}

	// Jobs stopped by the previous worker must resume after upgrade, exactly once.
	must(t, h.repo.Transaction(h.ctx, func(tx contribution.Transaction) error {
		j, e := tx.Job(v2.ID)
		if e != nil {
			return e
		}
		j.State = "complete"
		return tx.SaveJob(j)
	}))
	for range 2 {
		_, e = h.admin.Exec(cp.Schema)
		must(t, e)
	}
	// Simulate storage ledger completing repair/cleanup to zero; periodic read-only RunOne clears cleanup_unconfirmed.
	snap, e := h.store.InspectContribution(h.ctx, system, "dirty", contribution.OwnerDomain(user))
	must(t, e)
	snap.RemainingReplicas = 0
	snap.UsedBytes = 0
	snap.ReservedBytes = 0
	snap.ObservedAt = h.clock.Now()
	ss.mu.Lock()
	ss.override = &snap
	ss.mu.Unlock()

	h.run(t)
	v2 = h.get(t, v2.ID)
	if v2.State != "revoked" || v2.Reason != "" || v2.Observation.RemainingReplicas != 0 || v2.Observation.UsedBytes != 0 {
		t.Fatalf("expected cleanup_unconfirmed to clear once ledger reached zero, got %+v", v2)
	}
	// Job must now be complete (no further RunOne work).
	h.clock.Add(2 * time.Minute)
	if e = h.s.RunOne(h.ctx, "worker"); !errors.Is(e, contribution.ErrNotFound) {
		t.Fatalf("expected completed job after cleanup zeroed, got %v", e)
	}
	finalStats, e := h.s.Statistics(h.ctx)
	must(t, e)
	if finalStats.Contributions != 0 || finalStats.UsedBytes != 0 || finalStats.Status != "current" {
		t.Fatalf("expected clean statistics after revoked ledger zeroed, got %+v", finalStats)
	}
}

func TestViewDynamicReasonsClockSkewAndExitOverdue(t *testing.T) {
	h := newFixture(t)

	// Config with ObservationMaxAgeSeconds < 2*RefreshInterval must be rejected to prevent boundary flapping.
	badCfg := h.cfg
	badCfg.RefreshInterval = time.Minute
	badCfg.Policy.ObservationMaxAgeSeconds = 60
	if _, e := contribution.New(h.repo, h.policy, h.bridge, badCfg); !errors.Is(e, contribution.ErrInput) {
		t.Fatalf("expected ErrInput when ObservationMaxAgeSeconds < 2*RefreshInterval, got %v", e)
	}

	ss := &skewStore{Store: h.bridge, skew: 500 * time.Millisecond}
	svc, e := contribution.New(h.repo, h.policy, ss, h.cfg)
	must(t, e)
	h.s = svc

	// 1. +500ms clock skew from storage must still be treated as current, not observation_stale.
	now := h.clock.Now()
	_, e = h.store.Register(h.ctx, system, "register-skew", storage.Instance{
		ID: "skew", Adapter: "fixture", AccountDomain: "fixture:skew",
		OwnerDomain: contribution.OwnerDomain(user), Ownership: "contributor",
		CredentialRef: "fixture-skew", CredentialRevision: 1, Root: "isolated-skew",
		State: "paused", Authorized: true, Limit: 1 << 20, ExpiresAt: now.Add(6 * time.Hour),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now.Add(6 * time.Hour)}},
	})
	must(t, e)
	v, e := h.s.Create(h.ctx, user, "create-skew", contribution.CreateRequest{
		InstanceID: "skew",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 0, Until: now.Add(5 * time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest},
	})
	must(t, e)
	h.run(t)
	v = h.get(t, v.ID)
	if v.State != "active" || v.Reason != "" || v.Observation.AvailableBytes != 1024 {
		t.Fatalf("expected active with 1024 available under +500ms clock skew, got %+v (obs=%+v)", v, v.Observation)
	}

	// 2. When QuotaExpiresAt expires while ObservedAt is freshly polled, Reason must be capacity_unknown (not observation_stale).
	ss.mu.Lock()
	ss.skew = 0
	ss.mu.Unlock()
	h.clock.Add(2 * time.Hour) // QuotaExpiresAt in storage default is 1h, while ExpiresAt=6h and Until=5h.
	h.run(t)
	v = h.get(t, v.ID)
	if v.State != "active" || v.Reason != "capacity_unknown" || v.Observation.AvailableBytes != 0 {
		t.Fatalf("expected active with capacity_unknown and 0 available_bytes, got state=%s reason=%s avail=%d",
			v.State, v.Reason, v.Observation.AvailableBytes)
	}

	// 3. Paused contribution with expired QuotaExpiresAt but fresh ObservedAt must not mark Statistics partial.
	v = h.command(t, v, "pause")
	h.run(t)
	stats, e := h.s.Statistics(h.ctx)
	must(t, e)
	if stats.Status != "current" || stats.Contributions != 1 || stats.FreshObservations != 1 {
		t.Fatalf("paused contribution with fresh observation and expired quota marked partial: %+v", stats)
	}
}

func TestExitOverdueDynamicViewAndExpiredQuota(t *testing.T) {
	h := newFixture(t)
	now2 := h.clock.Now()
	_, e := h.store.Register(h.ctx, system, "register-overdue", storage.Instance{
		ID: "overdue", Adapter: "fixture", AccountDomain: "fixture:overdue",
		OwnerDomain: contribution.OwnerDomain(user), Ownership: "contributor",
		CredentialRef: "fixture-overdue", CredentialRevision: 1, Root: "isolated-overdue",
		State: "paused", Authorized: true, Limit: 1 << 20, ExpiresAt: now2.Add(6 * time.Hour),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now2.Add(6 * time.Hour)}},
	})
	must(t, e)
	ve, e := h.s.Create(h.ctx, user, "create-overdue", contribution.CreateRequest{
		InstanceID: "overdue",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 0, Until: now2.Add(5 * time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest},
	})
	must(t, e)
	h.run(t)
	sum := sha256.Sum256([]byte("q"))
	obj, e := h.store.Create(h.ctx, system, "file-overdue", storage.CreateRequest{
		Size: 1, SHA256: hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, e)
	_, e = h.store.Ingest(h.ctx, system, obj.ID, "write-overdue", strings.NewReader("q"))
	must(t, e)

	ve = h.get(t, ve.ID)
	ve = h.command(t, ve, "exit")
	h.run(t)
	ve = h.get(t, ve.ID)
	if ve.State != "exiting" || ve.Reason != "" {
		t.Fatalf("expected exiting without reason initially, got %+v", ve)
	}

	// An old worker might have persisted a quota warning while already draining.
	must(t, h.repo.Transaction(h.ctx, func(tx contribution.Transaction) error {
		r, e := tx.Record(ve.ID)
		if e != nil {
			return e
		}
		r.View.Reason = "capacity_unknown"
		return tx.SaveRecord(r)
	}))
	// Advance past ExitTargetSeconds (1h) AND QuotaExpiresAt BEFORE next worker run: Get must dynamically report exit_overdue.
	h.clock.Add(65 * time.Minute)
	dynamicView := h.get(t, ve.ID)
	if dynamicView.Reason != "exit_overdue" {
		t.Fatalf("expected dynamic exit_overdue before worker poll, got %q", dynamicView.Reason)
	}

	// Worker poll with expired QuotaExpiresAt on exiting instance must keep exit_overdue, not capacity_unknown.
	h.run(t)
	polledView := h.get(t, ve.ID)
	if polledView.Reason != "exit_overdue" {
		t.Fatalf("expected exit_overdue after worker poll with expired quota, got %q", polledView.Reason)
	}
}
