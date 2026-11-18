package contribution_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	cp "github.com/StuHelper/stuhelper-storage-contribution/postgres"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

func TestOutboxOrderingExclusionBackoffAndNotify(t *testing.T) {
	h := newFixture(t)
	h.repo.Now = h.clock.Now
	dsn := os.Getenv("STUHELPER_CONTRIBUTION_TEST_DSN")
	var dbName string
	must(t, h.admin.QueryRow(`SELECT current_database()`).Scan(&dbName))

	listenConn, e := pgx.Connect(h.ctx, dsn+" dbname="+dbName)
	must(t, e)
	defer listenConn.Close(h.ctx)
	_, e = listenConn.Exec(h.ctx, `LISTEN `+contribution.OutboxChannel)
	must(t, e)

	// Rolled-back or rejected mutations must not emit pg_notify or persist outbox rows.
	bad := h.request(t, "rollback-inst")
	bad.Consent.Accepted = false
	if _, e = h.s.Create(h.ctx, user, "bad-create", bad); !errors.Is(e, contribution.ErrInput) {
		t.Fatal("expected ErrInput, got", e)
	}
	waitShort, cancelShort := context.WithTimeout(h.ctx, 80*time.Millisecond)
	_, notifyErr := listenConn.WaitForNotification(waitShort)
	cancelShort()
	if notifyErr == nil {
		t.Fatal("rolled-back or rejected request triggered outbox notification")
	}

	// Generate multiple revisions on the same subject so SHA-256 event IDs are non-monotonic.
	first := h.create(t, "one")
	waitNotify, cancelNotify := context.WithTimeout(h.ctx, time.Second)
	note, notifyErr := listenConn.WaitForNotification(waitNotify)
	cancelNotify()
	if notifyErr != nil || note.Channel != contribution.OutboxChannel {
		t.Fatalf("missing pg_notify on %s: %v", contribution.OutboxChannel, notifyErr)
	}

	h.run(t)
	first = h.get(t, first.ID)
	for range 4 {
		first = h.command(t, first, "pause")
		h.run(t)
		first = h.get(t, first.ID)
		first = h.command(t, first, "resume")
		h.run(t)
		first = h.get(t, first.ID)
	}
	second := h.create(t, "two")

	events, e := h.repo.PendingEvents(h.ctx, 100)
	must(t, e)
	if len(events) < 11 {
		t.Fatalf("expected >= 11 events, got %d", len(events))
	}
	lastRev := map[string]int64{}
	for i, ev := range events {
		if prev := lastRev[ev.Subject]; ev.Data.Revision <= prev {
			t.Fatalf("outbox broke per-subject revision order at %d for %s: rev %d after %d", i, ev.Subject, ev.Data.Revision, prev)
		}
		lastRev[ev.Subject] = ev.Data.Revision
	}

	// Subject exclusion in PendingOutbox prevents head-of-line blocking before LIMIT.
	filtered, e := h.repo.PendingOutbox(h.ctx, 1, []string{first.ID})
	must(t, e)
	if len(filtered) != 1 || filtered[0].Subject != second.ID {
		t.Fatalf("expected second subject when excluding first, got %+v", filtered)
	}

	// Failing first subject's head event suppresses all later events of first subject
	// while allowing second subject to proceed without head-of-line starvation.
	headFirst := events[0]
	if headFirst.Subject != first.ID || headFirst.Data.Revision != 1 {
		t.Fatalf("unexpected head event: %+v", headFirst)
	}
	must(t, h.repo.FailEvent(h.ctx, headFirst.ID, "downstream_unavailable", h.clock.Now()))
	unblocked, e := h.repo.PendingEvents(h.ctx, 5)
	must(t, e)
	if len(unblocked) != 1 || unblocked[0].Subject != second.ID {
		t.Fatalf("blocked subject either leaked later revision or starved second subject: %+v", unblocked)
	}

	// After 5s backoff expires, headFirst becomes deliverable again in order.
	h.clock.Add(6 * time.Second)
	resumed, e := h.repo.PendingEvents(h.ctx, 2)
	must(t, e)
	if len(resumed) < 2 || resumed[0].ID != headFirst.ID || resumed[0].Data.Revision != 1 {
		t.Fatalf("expected headFirst rev 1 after backoff, got %+v", resumed)
	}

	// Failing past 24h promotes the event to manual handling until explicitly retried.
	h.clock.Add(24 * time.Hour)
	must(t, h.repo.FailEvent(h.ctx, headFirst.ID, "persistent_failure", h.clock.Now()))
	h.clock.Add(2 * time.Hour)
	manualBlocked, e := h.repo.PendingEvents(h.ctx, 5)
	must(t, e)
	for _, ev := range manualBlocked {
		if ev.Subject == first.ID {
			t.Fatalf("manual event subject leaked before explicit retry: %+v", ev)
		}
	}
	retryListener, e := pgx.Connect(h.ctx, dsn+" dbname="+dbName)
	must(t, e)
	defer retryListener.Close(h.ctx)
	_, e = retryListener.Exec(h.ctx, `LISTEN `+contribution.OutboxChannel)
	must(t, e)
	must(t, h.repo.RetryEvent(h.ctx, headFirst.ID, h.clock.Now()))
	waitRetry, cancelRetry := context.WithTimeout(h.ctx, time.Second)
	_, e = retryListener.WaitForNotification(waitRetry)
	cancelRetry()
	must(t, e)
	afterRetry, e := h.repo.PendingEvents(h.ctx, 2)
	must(t, e)
	if len(afterRetry) == 0 || afterRetry[0].ID != headFirst.ID {
		t.Fatalf("expected manual event restored after RetryEvent, got %+v", afterRetry)
	}

	// AcknowledgeEvent / ConfirmOutbox returns ErrNotFound on unknown ID and is idempotent on repeat confirm.
	if e = h.repo.AcknowledgeEvent(h.ctx, "missing-event-id"); !errors.Is(e, contribution.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown event id, got %v", e)
	}
	must(t, h.repo.ConfirmOutbox(h.ctx, headFirst.ID))
	var firstSentAt, secondSentAt time.Time
	must(t, h.admin.QueryRow(`SELECT sent_at FROM contribution.outbox WHERE id=$1`, headFirst.ID).Scan(&firstSentAt))
	h.clock.Add(time.Minute)
	must(t, h.repo.ConfirmOutbox(h.ctx, headFirst.ID))
	must(t, h.admin.QueryRow(`SELECT sent_at FROM contribution.outbox WHERE id=$1`, headFirst.ID).Scan(&secondSentAt))
	if !firstSentAt.Equal(secondSentAt) {
		t.Fatalf("idempotent ConfirmOutbox overwrote sent_at: %v vs %v", firstSentAt, secondSentAt)
	}
}

func TestRuntimePrivilegeIsolationChecks(t *testing.T) {
	h := newFixture(t)
	dsn := os.Getenv("STUHELPER_CONTRIBUTION_TEST_DSN")
	var dbName string
	must(t, h.admin.QueryRow(`SELECT current_database()`).Scan(&dbName))

	checkRole := func(name, setupSQL string) error {
		t.Helper()
		role := dbName + "_" + name
		_, e := h.admin.Exec(fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT USAGE ON SCHEMA contribution TO %s;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA contribution TO %s;
REVOKE UPDATE,DELETE ON contribution.audit FROM %s;
%s`, role, role, role, role, fmt.Sprintf(setupSQL, role)))
		must(t, e)
		t.Cleanup(func() {
			_, _ = h.admin.Exec(`REVOKE ALL ON ALL TABLES IN SCHEMA contribution FROM ` + role)
			_, _ = h.admin.Exec(`REVOKE ALL ON SCHEMA contribution FROM ` + role)
			_, _ = h.admin.Exec(`DROP OWNED BY ` + role)
			_, _ = h.admin.Exec(`DROP ROLE IF EXISTS ` + role)
		})
		db, e := sql.Open("pgx", dsn+" dbname="+dbName+" user="+role)
		must(t, e)
		defer db.Close()
		return (&cp.Repository{DB: db}).CheckRuntime(h.ctx)
	}

	if e := checkRole("truncate_audit", `GRANT TRUNCATE ON contribution.audit TO %s;`); !errors.Is(e, contribution.ErrDenied) {
		t.Fatalf("expected ErrDenied when runtime has TRUNCATE on contribution.audit, got %v", e)
	}
	if e := checkRole("create_schema", `GRANT CREATE ON SCHEMA contribution TO %s;`); !errors.Is(e, contribution.ErrDenied) {
		t.Fatalf("expected ErrDenied when runtime has CREATE on contribution schema, got %v", e)
	}
	_, e := h.admin.Exec(`CREATE SCHEMA IF NOT EXISTS reviews; REVOKE ALL ON SCHEMA reviews FROM PUBLIC;`)
	must(t, e)
	if e := checkRole("foreign_reviews", `GRANT USAGE ON SCHEMA reviews TO %s;`); !errors.Is(e, contribution.ErrDenied) {
		t.Fatalf("expected ErrDenied when runtime has USAGE on reviews schema, got %v", e)
	}
	_, e = h.admin.Exec(`CREATE SCHEMA pgtools`)
	must(t, e)
	if e := checkRole("additional_schema", `GRANT USAGE ON SCHEMA pgtools TO %s;`); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal(e)
	}
	if e := checkRole("foreign_create", `GRANT CREATE ON SCHEMA reviews TO %s;`); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal(e)
	}
	if e := checkRole("public_usage", `GRANT USAGE ON SCHEMA public TO %s;`); !errors.Is(e, contribution.ErrDenied) {
		t.Fatalf("expected ErrDenied when runtime has USAGE on public schema, got %v", e)
	}
	if e := checkRole("missing_delete", `REVOKE DELETE ON contribution.replays FROM %s;`); !errors.Is(e, contribution.ErrDenied) {
		t.Fatalf("expected ErrDenied when runtime lacks DELETE on contribution.replays, got %v", e)
	}
}

func TestLegacyPendingEventsMigrateInRevisionOrder(t *testing.T) {
	h := newFixture(t)
	// The former schema persisted only the envelope and delivery flag.
	for _, rev := range []int64{3, 1, 2} {
		ev := contribution.Event{ID: fmt.Sprint(rev), Subject: "legacy", Data: contribution.EventData{Revision: rev}}
		raw, e := json.Marshal(ev)
		must(t, e)
		_, e = h.admin.Exec(`INSERT INTO contribution.outbox(id,data,delivered) VALUES ($1,$2,$3)`, ev.ID, string(raw), rev == 2)
		must(t, e)
	}
	for range 2 {
		_, e := h.admin.Exec(cp.Schema)
		must(t, e)
	}
	events, e := h.repo.PendingEvents(h.ctx, 100)
	must(t, e)
	if len(events) != 2 || events[0].Data.Revision != 1 || events[1].Data.Revision != 3 {
		t.Fatal(events)
	}
}
