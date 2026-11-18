package contribution_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingRepository struct {
	contribution.Repository
	scans     atomic.Int64
	scanHook  func()
	afterScan func()
}

type countingTransaction struct {
	contribution.Transaction
	parent *countingRepository
}

func (r *countingRepository) Transaction(ctx context.Context, fn func(contribution.Transaction) error) error {
	return r.Repository.Transaction(ctx, func(tx contribution.Transaction) error {
		return fn(&countingTransaction{Transaction: tx, parent: r})
	})
}

func (t *countingTransaction) Scan(n int, after string) ([]contribution.Record, error) {
	t.parent.scans.Add(1)
	if hook := t.parent.scanHook; hook != nil {
		hook()
	}
	rows, err := t.Transaction.Scan(n, after)
	if t.parent.afterScan != nil {
		t.parent.afterScan()
	}
	return rows, err
}

func TestStatisticsSingleflightCacheAndVerifiedByteHours(t *testing.T) {
	h := newFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var hookOnce sync.Once
	counting := &countingRepository{
		Repository: h.repo,
		scanHook: func() {
			hookOnce.Do(func() {
				close(entered)
				<-release
			})
		},
	}
	cfg := h.cfg
	cfg.StatisticsCacheTTL = 5 * time.Second
	cfg.RefreshInterval = time.Minute
	cfg.Policy.ObservationMaxAgeSeconds = 120
	svc, err := contribution.New(counting, h.policy, h.bridge, cfg)
	must(t, err)
	h.s = svc

	// 1. Concurrent anonymous Statistics calls coalesce into a single DB Scan (singleflight),
	// and subsequent calls within 5s TTL hit cache without scanning DB again.
	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			_, err := h.s.Statistics(h.ctx)
			errs <- err
		})
	}
	<-entered
	// Give remaining goroutines a brief moment to join the in-flight call.
	time.Sleep(15 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		must(t, err)
	}
	if got := counting.scans.Load(); got != 1 {
		t.Fatalf("expected 1 coalesced Statistics scan across %d concurrent callers, got %d", callers, got)
	}

	// Within 5s TTL: cached result returned without hitting DB.
	h.clock.Add(3 * time.Second)
	_, err = h.s.Statistics(h.ctx)
	must(t, err)
	if got := counting.scans.Load(); got != 1 {
		t.Fatalf("expected cache hit within 5s TTL, got %d scans", got)
	}

	// Past 5s TTL: cache expires via controllable clock and refreshes.
	h.clock.Add(3 * time.Second)
	_, err = h.s.Statistics(h.ctx)
	must(t, err)
	if got := counting.scans.Load(); got != 2 {
		t.Fatalf("expected cache refresh after TTL expiry, got %d scans", got)
	}

	// Mutation/RunOne actively invalidates cache immediately even at the same clock instant.
	req := h.request(t, "one")
	req.Conditions.LimitBytes = 3600 // 3600 bytes -> 1 byte-second/s = 1 byte-hour per second!
	req.Conditions.PersonalReserve = 0
	v, err := h.s.Create(h.ctx, user, "create-one", req)
	must(t, err)
	if v.VerifiedActiveSeconds == nil || *v.VerifiedActiveSeconds != 0 || *v.VerifiedAvailableByteHours != 0 || *v.VerifiedUsedByteHours != 0 {
		t.Fatalf("expected initial verified counters to be 0, got %+v", v)
	}
	statsAfterCreate, err := h.s.Statistics(h.ctx)
	must(t, err)
	if statsAfterCreate.Contributions != 1 || statsAfterCreate.DeclaredBytes != 3600 {
		t.Fatalf("expected immediate cache invalidation after Create, got %+v", statsAfterCreate)
	}

	// 2. Verified active seconds and byte-hours accumulation across valid active windows.
	h.run(t)                           // First active observation at T
	payload := strings.Repeat("u", 60) // 60 bytes -> 60 * 60s = 3600 byte-seconds = 1 used byte-hour per minute!
	sum := sha256.Sum256([]byte(payload))
	obj, err := h.store.Create(h.ctx, system, "verified-obj", storage.CreateRequest{
		Size: 60, SHA256: hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, err)
	_, err = h.store.Ingest(h.ctx, system, obj.ID, "ing-verified", strings.NewReader(payload))
	must(t, err)

	// Window 1 (60s): prev had UsedBytes=0, AvailableBytes=3600; curr has UsedBytes=60, AvailableBytes=3540.
	// Conservative min(prev, curr): Used=0, Available=3540 -> 3540 * 60 = 212400 byte-secs = 59 byte-hours (rem 0).
	h.clock.Add(time.Minute)
	h.run(t)
	v = h.get(t, v.ID)
	if *v.VerifiedActiveSeconds != 60 || *v.VerifiedAvailableByteHours != 59 || *v.VerifiedUsedByteHours != 0 {
		t.Fatalf("unexpected window 1 verified usage: active=%d avail=%d used=%d", *v.VerifiedActiveSeconds, *v.VerifiedAvailableByteHours, *v.VerifiedUsedByteHours)
	}

	// Window 2 (60s): both endpoints have UsedBytes=60, AvailableBytes=3540 -> +60s, +59 avail byte-hours, +1 used byte-hour!
	h.clock.Add(time.Minute)
	h.run(t)
	v = h.get(t, v.ID)
	if *v.VerifiedActiveSeconds != 120 || *v.VerifiedAvailableByteHours != 118 || *v.VerifiedUsedByteHours != 1 {
		t.Fatalf("unexpected window 2 verified usage: active=%d avail=%d used=%d", *v.VerifiedActiveSeconds, *v.VerifiedAvailableByteHours, *v.VerifiedUsedByteHours)
	}

	// Gap exceeding ObservationMaxAgeSeconds (120s) MUST NOT credit unverified offline duration!
	h.clock.Add(130 * time.Second)
	h.run(t)
	v = h.get(t, v.ID)
	if *v.VerifiedActiveSeconds != 120 || *v.VerifiedAvailableByteHours != 118 || *v.VerifiedUsedByteHours != 1 {
		t.Fatalf("stale gap must not accumulate verified usage: active=%d avail=%d used=%d", *v.VerifiedActiveSeconds, *v.VerifiedAvailableByteHours, *v.VerifiedUsedByteHours)
	}

	// Paused contributions do NOT accumulate verified active metrics, and never decrease existing totals.
	v = h.command(t, v, "pause")
	h.run(t)
	h.clock.Add(time.Minute)
	v = h.get(t, v.ID)
	if *v.VerifiedActiveSeconds != 120 || *v.VerifiedAvailableByteHours != 118 || *v.VerifiedUsedByteHours != 1 {
		t.Fatalf("paused state altered verified totals: %+v", v)
	}

	// Admin Operations view omits personal verified_* fields.
	ops, err := h.s.Operations(h.ctx, operator, 20, "")
	must(t, err)
	opsRaw, err := json.Marshal(ops)
	must(t, err)
	if bytes.Contains(opsRaw, []byte("verified_active_seconds")) {
		t.Fatalf("personal verified metrics leaked to admin Operations: %s", string(opsRaw))
	}
}

func TestStatisticsAfterMutationDoesNotJoinPreviousScan(t *testing.T) {
	h := newFixture(t)
	captured, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	counted := &countingRepository{Repository: h.repo, afterScan: func() {
		if first.CompareAndSwap(false, true) {
			close(captured)
			<-release
		}
	}}
	svc, err := contribution.New(counted, h.policy, h.bridge, h.cfg)
	must(t, err)
	old := make(chan error, 1)
	go func() { _, e := svc.Statistics(h.ctx); old <- e }()
	<-captured
	var closeOnce sync.Once
	unblock := func() { closeOnce.Do(func() { close(release) }) }
	defer unblock()
	_, err = svc.Create(h.ctx, user, "fresh-statistics", h.request(t, "one"))
	must(t, err)
	ctx, cancel := context.WithTimeout(h.ctx, 2*time.Second)
	defer cancel()
	latest, err := svc.Statistics(ctx)
	must(t, err)
	if latest.Contributions != 1 {
		t.Fatal(latest)
	}
	unblock()
	must(t, <-old)
}
