// Package postgres owns contribution metadata and its independent runtime identity.
package postgres

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed schema.sql
var Schema string

var _ contribution.OutboxReader = (*Repository)(nil)

type Repository struct {
	DB  *sql.DB
	Now func() time.Time
}

func (r *Repository) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

type transaction struct {
	tx  *sql.Tx
	ctx context.Context
}

func (t *transaction) Record(id string) (contribution.Record, error) {
	return read[contribution.Record](t, `SELECT data FROM contribution.contributions WHERE id=$1 FOR UPDATE`, id)
}

// Sweep revisits busy rows in the next pass without blocking receipt cleanup.
func (t *transaction) TrySweepRecord(id string) (contribution.Record, error) {
	return read[contribution.Record](t, `SELECT data FROM contribution.contributions WHERE id=$1 FOR UPDATE SKIP LOCKED`, id)
}
func (t *transaction) SaveRecord(r contribution.Record) error {
	return t.save(`INSERT INTO contribution.contributions(id,owner_key,instance_id,data) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, r, r.View.ID, contribution.OwnerDomain(r.Owner), r.InstanceID)
}
func (t *transaction) List(p contribution.Principal, n int, after string) ([]contribution.Record, error) {
	return list[contribution.Record](t, `SELECT data FROM contribution.contributions WHERE owner_key=$1 AND id>$2 ORDER BY id LIMIT $3`, contribution.OwnerDomain(p), after, n)
}
func (t *transaction) Scan(n int, after string) ([]contribution.Record, error) {
	return list[contribution.Record](t, `SELECT data FROM contribution.contributions WHERE id>$1 ORDER BY id LIMIT $2`, after, n)
}
func (t *transaction) ScanFiltered(n int, after, state, reason, adapter string) ([]contribution.Record, error) {
	return list[contribution.Record](t, `SELECT data FROM contribution.contributions WHERE id>$1 AND ($2='' OR data->'View'->>'state'=$2) AND ($3='' OR data->'View'->>'reason'=$3) AND ($4='' OR data->'View'->>'adapter'=$4) ORDER BY id LIMIT $5`, after, state, reason, adapter, n)
}
func (t *transaction) BoundInstances(p contribution.Principal, ids []string) (map[string]bool, error) {
	out := make(map[string]bool)
	rows, err := t.tx.QueryContext(t.ctx, `SELECT instance_id FROM contribution.contributions WHERE owner_key=$1 AND instance_id=ANY($2::text[])`, contribution.OwnerDomain(p), ids)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, safe(err)
		}
		out[id] = true
	}
	return out, safe(rows.Err())
}
func (t *transaction) Counts(p contribution.Principal) (total, owned int, err error) {
	err = t.tx.QueryRowContext(t.ctx, `SELECT count(*) FILTER(WHERE COALESCE(data->'View'->>'state','')<>'exited'),count(*) FILTER(WHERE owner_key=$1 AND COALESCE(data->'View'->>'state','')<>'exited') FROM contribution.contributions`, contribution.OwnerDomain(p)).Scan(&total, &owned)
	return total, owned, safe(err)
}
func (t *transaction) OwnerActivations(p contribution.Principal, since time.Time) (int, error) {
	var count int
	err := t.tx.QueryRowContext(t.ctx, `SELECT COALESCE(sum((SELECT count(*) FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(data->'Activations')='array' THEN data->'Activations' ELSE '[]'::jsonb END) ts WHERE ts::timestamptz>$2)),0) FROM contribution.contributions WHERE owner_key=$1`, contribution.OwnerDomain(p), since).Scan(&count)
	return count, safe(err)
}
func (t *transaction) Job(id string) (contribution.Job, error) {
	return read[contribution.Job](t, `SELECT data FROM contribution.jobs WHERE id=$1 FOR UPDATE`, id)
}
func (t *transaction) JobsByIDs(ids []string) (map[string]contribution.Job, error) {
	out := map[string]contribution.Job{}
	if len(ids) == 0 {
		return out, nil
	}
	items, err := list[contribution.Job](t, `SELECT data FROM contribution.jobs WHERE id=ANY($1::text[])`, ids)
	if err != nil {
		return nil, err
	}
	for _, j := range items {
		out[j.ID] = j
	}
	return out, nil
}
func (t *transaction) PendingOutboxBySubject(ids []string) (map[string]int, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT subject,count(*) FROM contribution.outbox WHERE subject=ANY($1::text[]) AND NOT delivered AND sent_at IS NULL GROUP BY subject`, ids)
	if err != nil {
		return nil, safe(err)
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var subject string
		var count int
		if err = rows.Scan(&subject, &count); err != nil {
			return nil, safe(err)
		}
		counts[subject] = count
	}
	return counts, safe(rows.Err())
}
func (t *transaction) SaveJob(j contribution.Job) error {
	return t.save(`INSERT INTO contribution.jobs(id,state,available_at,lease_until,data) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET state=excluded.state,available_at=excluded.available_at,lease_until=excluded.lease_until,data=excluded.data`, j, j.ID, j.State, j.AvailableAt, j.LeaseUntil)
}
func (t *transaction) Replay(key string) (contribution.Replay, error) {
	return read[contribution.Replay](t, `SELECT data FROM contribution.replays WHERE key=$1`, key)
}
func (t *transaction) SaveReplay(r contribution.Replay) error {
	return t.save(`INSERT INTO contribution.replays(key,expires_at,data) VALUES($1,$2,$3) ON CONFLICT(key) DO UPDATE SET expires_at=excluded.expires_at,data=excluded.data`, r, r.Key, r.ExpiresAt)
}
func (t *transaction) PruneReplaysCount(now time.Time, n int) (int, error) {
	res, e := t.tx.ExecContext(t.ctx, `DELETE FROM contribution.replays WHERE key IN (SELECT key FROM contribution.replays WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, now, n)
	if e != nil {
		return 0, safe(e)
	}
	c, e := res.RowsAffected()
	return int(c), safe(e)
}
func (t *transaction) PruneReplays(now time.Time, n int) error {
	_, e := t.PruneReplaysCount(now, n)
	return e
}
func (t *transaction) Event(e contribution.Event) error {
	if e.ID == "" || len(e.ID) > 200 || e.Subject == "" || len(e.Subject) > 512 {
		return contribution.ErrInput
	}
	if err := t.save(`INSERT INTO contribution.outbox(id,subject,data) VALUES($1,$2,$3)`, e, e.ID, e.Subject); err != nil {
		return err
	}
	if _, err := t.tx.ExecContext(t.ctx, `SELECT pg_notify($1,'')`, contribution.OutboxChannel); err != nil {
		return safe(err)
	}
	school := e.School
	if school == "" {
		school = "*"
	}
	return t.save(`INSERT INTO contribution.audit(id,reason,result,data) VALUES($1,'','success',$2)`, struct {
		Event  contribution.Event     `json:"event"`
		Actor  contribution.Principal `json:"actor"`
		School string                 `json:"school"`
	}{e, e.Actor, school}, e.ID)
}
func (t *transaction) Audit(a contribution.AuditEntry) error {
	result := a.Result
	if result == "" {
		result = "unknown"
	}
	school := a.School
	if school == "" {
		school = "*"
	}
	target := a.Target
	if target == "" {
		target = "unknown"
	}
	return t.save(`INSERT INTO contribution.audit(id,reason,result,data) VALUES($1,$2,$3,$4)`, struct {
		Actor  contribution.Principal `json:"actor"`
		Action string                 `json:"action"`
		Target string                 `json:"target"`
		School string                 `json:"school"`
		Time   time.Time              `json:"time"`
	}{a.Actor, a.Action, target, school, a.Time.UTC()}, a.ID, a.Reason, result)
}
func (r *Repository) Claim(ctx context.Context, worker string, now time.Time, lease time.Duration) (contribution.Job, error) {
	var out contribution.Job
	e := r.Transaction(ctx, func(tx contribution.Transaction) error {
		j, e := read[contribution.Job](tx.(*transaction), `SELECT data FROM contribution.jobs WHERE (state='pending' AND available_at<=$1) OR (state='running' AND lease_until<=$1) ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1`, now)
		if e != nil {
			return e
		}
		j.Generation++
		j.Attempts++
		j.LeaseOwner = worker
		j.LeaseUntil = now.Add(lease)
		j.State = "running"
		out = j
		return tx.SaveJob(j)
	})
	return out, e
}

const pendingOutboxSQL = `SELECT o.data FROM contribution.outbox o WHERE NOT o.delivered AND o.sent_at IS NULL AND NOT o.manual AND o.available_at<=$3 AND NOT (COALESCE(NULLIF(o.subject,''),o.data->>'subject')=ANY(COALESCE($2::text[],ARRAY[]::text[]))) AND NOT EXISTS (SELECT 1 FROM contribution.outbox b WHERE NOT b.delivered AND b.sent_at IS NULL AND COALESCE(NULLIF(b.subject,''),b.data->>'subject')=COALESCE(NULLIF(o.subject,''),o.data->>'subject') AND (b.manual OR b.available_at>$3) AND b.seq<=o.seq) ORDER BY o.seq ASC LIMIT $1`

func (r *Repository) PendingOutbox(ctx context.Context, limit int, excludeSubjects []string) ([]contribution.Event, error) {
	if limit < 1 || limit > 100 || len(excludeSubjects) > 1000 {
		return nil, contribution.ErrInput
	}
	if excludeSubjects == nil {
		excludeSubjects = []string{}
	}
	var out []contribution.Event
	now := r.now()
	e := r.Transaction(ctx, func(tx contribution.Transaction) error {
		var err error
		out, err = list[contribution.Event](tx.(*transaction), pendingOutboxSQL, limit, excludeSubjects, now)
		return err
	})
	return out, e
}
func (r *Repository) PendingEvents(ctx context.Context, n int) ([]contribution.Event, error) {
	return r.PendingOutbox(ctx, n, nil)
}
func (r *Repository) ConfirmOutbox(ctx context.Context, id string) error {
	if id == "" || len(id) > 200 {
		return contribution.ErrInput
	}
	res, e := r.DB.ExecContext(ctx, `UPDATE contribution.outbox SET delivered=true,sent_at=COALESCE(sent_at,$2),manual=false WHERE id=$1`, id, r.now())
	if e != nil {
		return safe(e)
	}
	n, e := res.RowsAffected()
	if e != nil {
		return safe(e)
	}
	if n == 0 {
		return contribution.ErrNotFound
	}
	return nil
}
func (r *Repository) AcknowledgeEvent(ctx context.Context, id string) error {
	return r.ConfirmOutbox(ctx, id)
}

// FailEvent records a delivery failure with exponential backoff (5s to 1h) and
// promotes the event to manual handling once 24h have elapsed since first failure.
func (r *Repository) FailEvent(ctx context.Context, id, reason string, now time.Time) error {
	if id == "" || len(id) > 200 || !utf8.ValidString(reason) {
		return contribution.ErrInput
	}
	if len(reason) > 200 {
		reason = reason[:200]
		for !utf8.ValidString(reason) {
			reason = reason[:len(reason)-1]
		}
	}
	now = now.UTC()
	return r.Transaction(ctx, func(tx contribution.Transaction) error {
		t := tx.(*transaction)
		var delivered bool
		var sentAt, firstFailed sql.NullTime
		var attempts int
		e := t.tx.QueryRowContext(t.ctx, `SELECT delivered,sent_at,attempts,first_failed_at FROM contribution.outbox WHERE id=$1 FOR UPDATE`, id).Scan(&delivered, &sentAt, &attempts, &firstFailed)
		if e != nil {
			return safe(e)
		}
		if delivered || sentAt.Valid {
			return contribution.ErrConflict
		}
		first := now
		if firstFailed.Valid {
			first = firstFailed.Time.UTC()
		}
		attempts++
		shift := min(attempts-1, 10)
		backoff := min(5*time.Second*time.Duration(1<<shift), time.Hour)
		manual := !now.Before(first.Add(24 * time.Hour))
		_, e = t.tx.ExecContext(t.ctx, `UPDATE contribution.outbox SET attempts=$2,first_failed_at=$3,available_at=$4,manual=$5,last_error=$6 WHERE id=$1`, id, attempts, first, now.Add(backoff), manual, reason)
		return safe(e)
	})
}

// RetryEvent clears manual/backoff state on an undelivered outbox event by its original ID.
func (r *Repository) RetryEvent(ctx context.Context, id string, now time.Time) error {
	if id == "" || len(id) > 200 {
		return contribution.ErrInput
	}
	var notification any
	err := r.DB.QueryRowContext(ctx, `UPDATE contribution.outbox SET manual=false,available_at=$2
      WHERE id=$1 AND NOT delivered AND sent_at IS NULL RETURNING pg_notify($3,'')`, id, now.UTC(), contribution.OutboxChannel).Scan(&notification)
	return safe(err)
}

func (r *Repository) CheckRuntime(ctx context.Context) error {
	var super, createDB, createRole, bypassRLS, ownerSchema, useSchema, createSchema, foreignAccess bool
	e := r.DB.QueryRowContext(ctx, `SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,(SELECT nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_namespace WHERE nspname='contribution'),has_schema_privilege(current_user,'contribution','USAGE'),has_schema_privilege(current_user,'contribution','CREATE'),EXISTS(SELECT 1 FROM pg_namespace WHERE nspname<>'contribution' AND nspname<>'information_schema' AND NOT starts_with(nspname,'pg_') AND has_schema_privilege(current_user,oid,'USAGE,CREATE')) FROM pg_roles WHERE rolname=current_user`).Scan(&super, &createDB, &createRole, &bypassRLS, &ownerSchema, &useSchema, &createSchema, &foreignAccess)
	if e != nil || super || createDB || createRole || bypassRLS || ownerSchema || !useSchema || createSchema || foreignAccess {
		return contribution.ErrDenied
	}
	var readAudit, writeAudit, changeAudit bool
	e = r.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'contribution.audit','SELECT'),has_table_privilege(current_user,'contribution.audit','INSERT'),has_table_privilege(current_user,'contribution.audit','UPDATE,DELETE,TRUNCATE')`).Scan(&readAudit, &writeAudit, &changeAudit)
	if e != nil || !readAudit || !writeAudit || changeAudit {
		return contribution.ErrDenied
	}
	var readEpoch, changeEpoch bool
	e = r.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,'contribution.audit_retention','SELECT'),has_table_privilege(current_user,'contribution.audit_retention','INSERT,UPDATE,DELETE,TRUNCATE')`).Scan(&readEpoch, &changeEpoch)
	if e != nil || !readEpoch || changeEpoch {
		return contribution.ErrDenied
	}
	for _, table := range []string{"contributions", "jobs", "replays", "outbox"} {
		for _, priv := range strings.Split("SELECT,INSERT,UPDATE,DELETE", ",") {
			var allowed bool
			if e = r.DB.QueryRowContext(ctx, `SELECT has_table_privilege(current_user,$1,$2)`, "contribution."+table, priv).Scan(&allowed); e != nil || !allowed {
				return contribution.ErrDenied
			}
		}
	}
	return nil
}
func safe(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, sql.ErrNoRows) {
		return contribution.ErrNotFound
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return e
	}
	var pg *pgconn.PgError
	if errors.As(e, &pg) && (pg.Code == "23505" || pg.Code == "40001" || pg.Code == "40P01") {
		return contribution.ErrConflict
	}
	return contribution.ErrUnavailable
}
func (r *Repository) Transaction(ctx context.Context, run func(contribution.Transaction) error) error {
	tx, e := r.DB.BeginTx(ctx, nil)
	if e != nil {
		return safe(e)
	}
	defer tx.Rollback()
	if e = run(&transaction{tx, ctx}); e != nil {
		return e
	}
	return safe(tx.Commit())
}
func (t *transaction) Lock(key string) error {
	_, e := t.tx.ExecContext(t.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "stuhelper-contribution:"+key)
	return safe(e)
}
func read[T any](t *transaction, q string, args ...any) (T, error) {
	var v T
	var b []byte
	e := t.tx.QueryRowContext(t.ctx, q, args...).Scan(&b)
	if e != nil {
		return v, safe(e)
	}
	if json.Unmarshal(b, &v) != nil {
		return v, contribution.ErrUnavailable
	}
	return v, nil
}
func list[T any](t *transaction, q string, args ...any) ([]T, error) {
	rows, e := t.tx.QueryContext(t.ctx, q, args...)
	if e != nil {
		return nil, safe(e)
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var b []byte
		var v T
		if rows.Scan(&b) != nil || json.Unmarshal(b, &v) != nil {
			return nil, contribution.ErrUnavailable
		}
		out = append(out, v)
	}
	return out, safe(rows.Err())
}
func (t *transaction) save(q string, v any, args ...any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return contribution.ErrInput
	}
	args = append(args, string(b))
	_, e = t.tx.ExecContext(t.ctx, q, args...)
	return safe(e)
}

func (t *transaction) UnsettledOwnerClosures(p contribution.Principal, limit int) ([]contribution.Record, error) {
	return list[contribution.Record](t, `SELECT c.data FROM contribution.contributions c LEFT JOIN contribution.jobs j ON j.id=c.id
        WHERE c.owner_key=$1 AND c.data->'View'->>'state'<>'exited' AND (
        c.data->'View'->>'state'='revoked' AND c.data->'View'->>'desired_state'='revoked'
        AND (c.data->'View'->>'applied_revision')::bigint=(c.data->'View'->>'revision')::bigint AND COALESCE(j.state,'')='complete') IS NOT TRUE
        ORDER BY CASE WHEN c.data->'View'->>'desired_state'='revoked' THEN 1 ELSE 0 END,c.id LIMIT $2`, contribution.OwnerDomain(p), limit)
}
