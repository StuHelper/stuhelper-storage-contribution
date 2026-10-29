package contribution_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	cp "github.com/StuHelper/stuhelper-storage-contribution/postgres"
	sp "github.com/StuHelper/stuhelper-storage/postgres"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var user = contribution.Principal{Issuer: "urn:fixture", Subject: "owner"}
var system = contribution.Principal{Issuer: "urn:fixture:contribution", Subject: "service"}
var operator = contribution.Principal{Issuer: "urn:fixture", Subject: "operator"}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type policy struct {
	mu     sync.Mutex
	denied map[string]bool
}

func (p *policy) Authorize(_ context.Context, actor contribution.Principal, action string, a contribution.Access) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.denied[action] {
		return contribution.ErrDenied
	}
	if strings.HasPrefix(action, "contributions.operations.") {
		if actor == operator {
			return nil
		}
		return contribution.ErrDenied
	}
	if action == "contributions.maintenance" {
		if actor == system {
			return nil
		}
		return contribution.ErrDenied
	}
	if actor != user || a.Owner != user {
		return contribution.ErrDenied
	}
	return nil
}
func (p *policy) deny(action string, on bool) { p.mu.Lock(); p.denied[action] = on; p.mu.Unlock() }

type storagePolicy struct{}

func (storagePolicy) Authorize(_ context.Context, p storage.Principal, action, id string, protection storage.Protection) error {
	if p != system {
		return storage.ErrDenied
	}
	return nil
}

type provider struct {
	mu     sync.Mutex
	files  map[string][]byte
	writes map[string]int
	hook   func()
}

func (p *provider) Verify(_ context.Context, i storage.Instance) (storage.InstanceEvidence, error) {
	return storage.InstanceEvidence{AccountDomain: "fixture:" + i.ID, ProviderFree: 1 << 20, VerifiedAt: time.Now()}, nil
}
func (p *provider) Resolve(context.Context, storage.Instance) (storage.Driver, error) { return p, nil }
func (p *provider) Find(_ context.Context, i storage.Instance, intent string, _ storage.Locator) (storage.Locator, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.files[i.ID+":"+intent]; !ok {
		return storage.Locator{}, storage.ErrNotFound
	}
	return storage.Locator{ID: intent}, nil
}
func (p *provider) Write(_ context.Context, i storage.Instance, intent string, size int64, r io.Reader, checkpoint func(storage.Locator) error) (storage.Locator, error) {
	loc := storage.Locator{ID: intent}
	if e := checkpoint(loc); e != nil {
		return loc, e
	}
	b, e := io.ReadAll(io.LimitReader(r, size+1))
	if e != nil {
		return loc, e
	}
	if int64(len(b)) != size {
		return loc, storage.ErrIntegrity
	}
	p.mu.Lock()
	p.files[i.ID+":"+intent] = b
	p.writes[i.ID]++
	p.mu.Unlock()
	return loc, nil
}
func (p *provider) Read(_ context.Context, i storage.Instance, l storage.Locator, w io.Writer) (int64, error) {
	p.mu.Lock()
	b, ok := p.files[i.ID+":"+l.ID]
	b = bytes.Clone(b)
	hook := p.hook
	p.hook = nil
	p.mu.Unlock()
	if !ok {
		return 0, storage.ErrNotFound
	}
	if hook != nil {
		hook()
	}
	n, e := w.Write(b)
	return int64(n), e
}
func (p *provider) Remove(_ context.Context, i storage.Instance, l storage.Locator) error {
	p.mu.Lock()
	delete(p.files, i.ID+":"+l.ID)
	p.mu.Unlock()
	return nil
}

type bridge struct {
	*storage.Service
	mu     sync.Mutex
	lost   bool
	fail   bool
	before func()
}

func (b *bridge) ApplyContribution(ctx context.Context, p storage.Principal, id string, c storage.ContributionControl) (storage.ContributionSnapshot, error) {
	b.mu.Lock()
	hook := b.before
	b.before = nil
	lost := b.lost
	b.lost = false
	fail := b.fail
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	if fail {
		return storage.ContributionSnapshot{}, storage.ErrUnavailable
	}
	v, e := b.Service.ApplyContribution(ctx, p, id, c)
	if e == nil && lost {
		return v, storage.ErrUnavailable
	}
	return v, e
}

type fixture struct {
	s         *contribution.Service
	store     *storage.Service
	bridge    *bridge
	repo      *cp.Repository
	db, admin *sql.DB
	policy    *policy
	clock     *clock
	cfg       contribution.Config
	ctx       context.Context
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("STUHELPER_CONTRIBUTION_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	control, e := sql.Open("pgx", dsn)
	must(t, e)
	var random [8]byte
	_, e = rand.Read(random[:])
	must(t, e)
	name := "contribution_test_" + hex.EncodeToString(random[:])
	role := name + "_contrib"
	storageRole := name + "_storage"
	_, e = control.Exec(`CREATE DATABASE ` + name)
	must(t, e)
	admin, e := sql.Open("pgx", dsn+" dbname="+name)
	must(t, e)
	_, e = admin.Exec(cp.Schema + sp.Schema + `CREATE SCHEMA billing; REVOKE ALL ON SCHEMA billing FROM PUBLIC; CREATE TABLE billing.private(id int);`)
	must(t, e)
	_, e = admin.Exec(fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
 GRANT USAGE ON SCHEMA contribution TO %s; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA contribution TO %s; REVOKE UPDATE,DELETE ON contribution.audit FROM %s;
 GRANT USAGE ON SCHEMA storage TO %s; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA storage TO %s; REVOKE UPDATE,DELETE ON storage.audit FROM %s;
 REVOKE ALL ON SCHEMA public FROM PUBLIC;`, role, storageRole, role, role, role, storageRole, storageRole, storageRole))
	must(t, e)
	db, e := sql.Open("pgx", dsn+" dbname="+name+" user="+role)
	must(t, e)
	db.SetMaxOpenConns(12)
	sd, e := sql.Open("pgx", dsn+" dbname="+name+" user="+storageRole)
	must(t, e)
	sd.SetMaxOpenConns(12)
	c := &clock{t: time.Now().UTC()}
	p := &provider{files: map[string][]byte{}, writes: map[string]int{}}
	sr := &sp.Repository{DB: sd}
	must(t, sr.CheckRuntime(context.Background()))
	st, e := storage.New(sr, storagePolicy{}, p, p, storage.Config{Clock: c.Now, MaxObjectSize: 1 << 20, TemporaryDirectory: t.TempDir(), ParallelTransfers: 2, Lease: time.Minute, VerificationAge: time.Hour, MaxAttempts: 3})
	must(t, e)
	a := &policy{denied: map[string]bool{}}
	repo := &cp.Repository{DB: db}
	must(t, repo.CheckRuntime(context.Background()))
	cfg := contribution.Config{Policy: contribution.Policy{Terms: contribution.Terms{Version: "fixture-v1", Digest: strings.Repeat("a", 64), URL: "https://fixture.invalid/terms"}, Adapters: []string{"fixture"}, MinBytes: 1, MaxBytes: 1 << 20, MinTermSeconds: 60, MaxTermSeconds: 86400, ExitTargetSeconds: 3600, MaxPerOwner: 10, ObservationMaxAgeSeconds: 120}, Actor: system, Clock: c.Now, OperationTimeout: 5 * time.Second, Lease: time.Minute, RefreshInterval: time.Minute, MaxAttempts: 3, MaxContributions: 100}
	b := &bridge{Service: st}
	s, e := contribution.New(repo, a, b, cfg)
	must(t, e)
	h := &fixture{s, st, b, repo, db, admin, a, c, cfg, context.Background()}
	t.Cleanup(func() {
		must(t, st.Close(context.Background()))
		db.Close()
		sd.Close()
		admin.Close()
		_, e := control.Exec(`DROP DATABASE ` + name + ` WITH (FORCE)`)
		if e != nil {
			t.Error(e)
		}
		_, e = control.Exec(`DROP ROLE ` + role + `, ` + storageRole)
		if e != nil {
			t.Error(e)
		}
		control.Close()
	})
	return h
}
func (h *fixture) request(t *testing.T, id string) contribution.CreateRequest {
	t.Helper()
	now := h.clock.Now()
	_, e := h.store.Register(h.ctx, system, "register-"+id, storage.Instance{ID: id, Adapter: "fixture", AccountDomain: "fixture:" + id, OwnerDomain: contribution.OwnerDomain(user), Ownership: "contributor", CredentialRef: "fixture", CredentialRevision: 1, Root: "isolated-" + id, State: "paused", Authorized: true, Limit: 1 << 20, ExpiresAt: now.Add(2 * time.Hour), Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now.Add(2 * time.Hour)}}})
	must(t, e)
	return contribution.CreateRequest{InstanceID: id, Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 100, Until: now.Add(time.Hour)}, Consent: contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest}}
}
func (h *fixture) create(t *testing.T, id string) contribution.View {
	t.Helper()
	v, e := h.s.Create(h.ctx, user, "create-"+id, h.request(t, id))
	must(t, e)
	return v
}
func (h *fixture) run(t *testing.T) { t.Helper(); must(t, h.s.RunOne(h.ctx, "worker")) }
func (h *fixture) get(t *testing.T, id string) contribution.View {
	t.Helper()
	v, e := h.s.Get(h.ctx, user, id)
	must(t, e)
	return v
}
func (h *fixture) command(t *testing.T, v contribution.View, action string) contribution.View {
	t.Helper()
	out, e := h.s.Command(h.ctx, user, v.ID, fmt.Sprintf("%s-%d", action, v.Revision), contribution.CommandRequest{Revision: v.Revision, Action: action})
	must(t, e)
	return out
}

func TestConsentOwnershipAndConcurrentIdempotency(t *testing.T) {
	h := newFixture(t)
	q := h.request(t, "one")
	invalid := q
	invalid.Consent.Accepted = false
	if _, e := h.s.Create(h.ctx, user, "invalid", invalid); !errors.Is(e, contribution.ErrInput) {
		t.Fatal(e)
	}
	foreign := user
	foreign.Issuer = "urn:other-school"
	if _, e := h.s.Create(h.ctx, foreign, "foreign", q); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan contribution.View, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { v, e := h.s.Create(h.ctx, user, "same", q); results <- v; errs <- e })
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		must(t, e)
	}
	var id string
	for v := range results {
		if id != "" && id != v.ID {
			t.Fatal("duplicate contribution")
		}
		id = v.ID
		if v.State != "pending" || v.AppliedRevision != 0 {
			t.Fatal(v)
		}
	}
	q.Conditions.LimitBytes++
	if _, e := h.s.Create(h.ctx, user, "same", q); !errors.Is(e, contribution.ErrConflict) {
		t.Fatal(e)
	}
	var records, events, audits, jobs int
	must(t, h.admin.QueryRow(`SELECT (SELECT count(*) FROM contribution.contributions),(SELECT count(*) FROM contribution.outbox),(SELECT count(*) FROM contribution.audit),(SELECT count(*) FROM contribution.jobs)`).Scan(&records, &events, &audits, &jobs))
	if records != 1 || events != 1 || audits != 1 || jobs != 1 {
		t.Fatal(records, events, audits, jobs)
	}
	h.policy.deny("contributions.create", true)
	q.Conditions.LimitBytes--
	if _, e := h.s.Create(h.ctx, user, "same", q); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal("revoked permission replay", e)
	}
	if _, e := h.s.Get(h.ctx, foreign, id); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal(e)
	}
	if _, e := h.s.List(h.ctx, user, 101, ""); !errors.Is(e, contribution.ErrInput) {
		t.Fatal(e)
	}
}
func TestPauseRenewExitAndActualReplicaCleanup(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.run(t)
	v = h.get(t, v.ID)
	if v.State != "active" || v.AppliedRevision != 1 || v.Observation.AvailableBytes != 1024 {
		t.Fatal(v)
	}
	v = h.command(t, v, "pause")
	if v.State != "pending" || v.DesiredState != "paused" || v.Observation.AvailableBytes != 0 {
		t.Fatal(v)
	}
	h.run(t)
	v = h.get(t, v.ID)
	if v.State != "paused" {
		t.Fatal(v)
	}
	v = h.command(t, v, "resume")
	h.run(t)
	v = h.get(t, v.ID)
	c := v.Conditions
	c.Until = c.Until.Add(time.Hour)
	consent := contribution.Consent{Accepted: true, Version: v.Consent.Version, Digest: v.Consent.Digest}
	var e error
	v, e = h.s.Command(h.ctx, user, v.ID, "renew", contribution.CommandRequest{Revision: v.Revision, Action: "renew", Conditions: &c, Consent: &consent})
	must(t, e)
	h.run(t)
	v = h.get(t, v.ID)
	sum := sha256.Sum256([]byte("x"))
	object, e := h.store.Create(h.ctx, system, "file", storage.CreateRequest{Size: 1, SHA256: hex.EncodeToString(sum[:]), Protection: storage.Protection{Class: "public", Scope: "school", Public: true}})
	must(t, e)
	_, e = h.store.Ingest(h.ctx, system, object.ID, "write", strings.NewReader("x"))
	must(t, e)
	v = h.command(t, v, "exit")
	h.run(t)
	v = h.get(t, v.ID)
	if v.State != "exiting" || v.Observation.UsedBytes != 1 || v.Observation.RemainingReplicas != 1 || v.ExitTargetAt == nil {
		t.Fatal(v)
	}
	if _, e = h.s.Command(h.ctx, user, v.ID, "resume-exit", contribution.CommandRequest{Revision: v.Revision, Action: "resume"}); !errors.Is(e, contribution.ErrConflict) {
		t.Fatal(e)
	}
	_, e = h.store.Delete(h.ctx, system, object.ID, "delete", object.Revision)
	must(t, e)
	_, e = h.store.RunOne(h.ctx, "storage-worker")
	must(t, e)
	h.clock.Add(time.Minute)
	h.run(t)
	v = h.get(t, v.ID)
	if v.State != "exited" || v.Observation.RemainingReplicas != 0 || v.Observation.UsedBytes != 0 {
		t.Fatal(v)
	}
}
func TestLostResponseAndLateWorkerCannotUndoPause(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.bridge.lost = true
	if e := h.s.RunOne(h.ctx, "first"); !errors.Is(e, contribution.ErrUnavailable) {
		t.Fatal(e)
	}
	bound, e := h.store.InspectContribution(h.ctx, system, "one", contribution.OwnerDomain(user))
	must(t, e)
	if bound.Control == nil || bound.Control.Revision != 1 {
		t.Fatal(bound)
	}
	h.clock.Add(3 * time.Second)
	h.run(t)
	after, e := h.store.InspectContribution(h.ctx, system, "one", contribution.OwnerDomain(user))
	must(t, e)
	if bound.Revision != after.Revision || h.get(t, v.ID).State != "active" {
		t.Fatal("lost response duplicated storage effect")
	}
	second := h.create(t, "two")
	h.bridge.before = func() { h.command(t, second, "pause"); must(t, h.s.RunOne(h.ctx, "new-worker")) }
	if e = h.s.RunOne(h.ctx, "late-worker"); !errors.Is(e, contribution.ErrConflict) {
		t.Fatal("stale worker", e)
	}
	current, e := h.store.InspectContribution(h.ctx, system, "two", contribution.OwnerDomain(user))
	must(t, e)
	if current.State != "paused" || current.Control.Revision != 2 || h.get(t, second.ID).State != "paused" {
		t.Fatal(current)
	}
}
func TestExpiryStatisticsAndPermanentBinding(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.run(t)
	stats, e := h.s.Statistics(h.ctx)
	must(t, e)
	if stats.DeclaredBytes != 1024 || stats.AvailableBytes != 1024 || stats.Status != "current" {
		t.Fatal(stats)
	}
	h.clock.Add(3 * time.Minute)
	stats, e = h.s.Statistics(h.ctx)
	must(t, e)
	if stats.AvailableBytes != 0 || stats.Status != "partial" {
		t.Fatal(stats)
	}
	h.clock.Add(time.Hour)
	_, e = h.s.Sweep(h.ctx, 100, "")
	must(t, e)
	v = h.get(t, v.ID)
	if v.DesiredState != "exiting" || v.State != "pending" {
		t.Fatal(v)
	}
	h.run(t)
	if h.get(t, v.ID).State != "exited" {
		t.Fatal(h.get(t, v.ID))
	}
	h.clock.Add(24 * time.Hour)
	_, e = h.s.Sweep(h.ctx, 100, "")
	must(t, e)
	var count int
	must(t, h.admin.QueryRow(`SELECT count(*) FROM contribution.replays`).Scan(&count))
	if count != 0 {
		t.Fatal("replay cleanup", count)
	}
	// The storage binding remains permanent even though the response expired.
	q := contribution.CreateRequest{InstanceID: "one", Conditions: contribution.Conditions{LimitBytes: 1024, Until: h.clock.Now().Add(time.Hour)}, Consent: contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest}}
	if _, e = h.s.Create(h.ctx, user, "create-one", q); !errors.Is(e, contribution.ErrConflict) {
		t.Fatal(e)
	}
	must(t, h.admin.QueryRow(`SELECT count(*) FROM contribution.contributions`).Scan(&count))
	if count != 1 {
		t.Fatal(count)
	}
}
func TestBoundedRetriesRevokeAndDatabaseIsolation(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.bridge.fail = true
	for range 3 {
		if e := h.s.RunOne(h.ctx, "worker"); !errors.Is(e, contribution.ErrUnavailable) {
			t.Fatal(e)
		}
		h.clock.Add(10 * time.Second)
	}
	if e := h.s.RunOne(h.ctx, "worker"); !errors.Is(e, contribution.ErrNotFound) {
		t.Fatal("retry limit", e)
	}
	v = h.get(t, v.ID)
	if v.State != "blocked" {
		t.Fatal(v)
	}
	h.bridge.fail = false
	v = h.command(t, v, "retry")
	h.run(t)
	v = h.get(t, v.ID)
	v = h.command(t, v, "revoke")
	h.run(t)
	v = h.get(t, v.ID)
	if v.State != "revoked" {
		t.Fatal(v)
	}
	if _, e := h.s.Command(h.ctx, user, v.ID, "resume", contribution.CommandRequest{Revision: v.Revision, Action: "resume"}); !errors.Is(e, contribution.ErrConflict) {
		t.Fatal(e)
	}
	for _, sql := range []string{`SELECT * FROM storage.instances`, `SELECT * FROM billing.private`, `CREATE TABLE contribution.forbidden(id int)`, `UPDATE contribution.audit SET data='{}'`, `DELETE FROM contribution.audit`} {
		if _, e := h.db.Exec(sql); e == nil {
			t.Fatal("runtime escaped scope", sql)
		}
	}
	events, e := h.repo.PendingEvents(h.ctx, 100)
	must(t, e)
	if len(events) == 0 {
		t.Fatal("missing outbox")
	}
	for _, event := range events {
		if event.SpecVersion != "1.0" || event.Data.Revision < 1 {
			t.Fatal(event)
		}
		b, e := json.Marshal(event)
		must(t, e)
		if bytes.Contains(b, []byte("issuer")) || bytes.Contains(b, []byte("fixture:")) {
			t.Fatal("private identity leaked")
		}
		must(t, h.repo.AcknowledgeEvent(h.ctx, event.ID))
	}
	events, e = h.repo.PendingEvents(h.ctx, 100)
	must(t, e)
	if len(events) != 0 {
		t.Fatal(events)
	}
}
