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
	"time"
)

//go:embed schema.sql
var Schema string

type Repository struct{ DB *sql.DB }
type transaction struct {
	tx  *sql.Tx
	ctx context.Context
}

func (t *transaction) Record(id string) (contribution.Record, error) {
	return read[contribution.Record](t, `SELECT data FROM contribution.contributions WHERE id=$1 FOR UPDATE`, id)
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
func (t *transaction) Counts(p contribution.Principal) (total, owned int, err error) {
	err = t.tx.QueryRowContext(t.ctx, `SELECT count(*),count(*) FILTER(WHERE owner_key=$1) FROM contribution.contributions`, contribution.OwnerDomain(p)).Scan(&total, &owned)
	return total, owned, safe(err)
}
func (t *transaction) Job(id string) (contribution.Job, error) {
	return read[contribution.Job](t, `SELECT data FROM contribution.jobs WHERE id=$1 FOR UPDATE`, id)
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
func (t *transaction) PruneReplays(now time.Time, n int) error {
	_, e := t.tx.ExecContext(t.ctx, `DELETE FROM contribution.replays WHERE key IN (SELECT key FROM contribution.replays WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, now, n)
	return safe(e)
}
func (t *transaction) Event(e contribution.Event) error {
	if err := t.save(`INSERT INTO contribution.outbox(id,data) VALUES($1,$2)`, e, e.ID); err != nil {
		return err
	}
	return t.save(`INSERT INTO contribution.audit(id,data) VALUES($1,$2)`, struct {
		Event contribution.Event     `json:"event"`
		Actor contribution.Principal `json:"actor"`
	}{e, e.Actor}, e.ID)
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
func (r *Repository) PendingEvents(ctx context.Context, n int) ([]contribution.Event, error) {
	if n < 1 || n > 100 {
		return nil, contribution.ErrInput
	}
	var out []contribution.Event
	e := r.Transaction(ctx, func(tx contribution.Transaction) error {
		var e error
		out, e = list[contribution.Event](tx.(*transaction), `SELECT data FROM contribution.outbox WHERE NOT delivered ORDER BY id LIMIT $1`, n)
		return e
	})
	return out, e
}
func (r *Repository) AcknowledgeEvent(ctx context.Context, id string) error {
	_, e := r.DB.ExecContext(ctx, `UPDATE contribution.outbox SET delivered=true WHERE id=$1`, id)
	return safe(e)
}
func (r *Repository) CheckRuntime(ctx context.Context) error {
	var super, createDB, createRole, ownerSchema, foreignAccess bool
	e := r.DB.QueryRowContext(ctx, `SELECT rolsuper,rolcreatedb,rolcreaterole,(SELECT nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_namespace WHERE nspname='contribution'),EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('storage','media','billing') AND has_schema_privilege(current_user,oid,'USAGE')) FROM pg_roles WHERE rolname=current_user`).Scan(&super, &createDB, &createRole, &ownerSchema, &foreignAccess)
	if e != nil || super || createDB || createRole || ownerSchema || foreignAccess {
		return contribution.ErrDenied
	}
	var readAudit, writeAudit, changeAudit bool
	e = r.DB.QueryRowContext(ctx, `SELECT has_table_privilege('contribution.audit','SELECT'),has_table_privilege('contribution.audit','INSERT'),has_table_privilege('contribution.audit','UPDATE,DELETE')`).Scan(&readAudit, &writeAudit, &changeAudit)
	if e != nil || !readAudit || !writeAudit || changeAudit {
		return contribution.ErrDenied
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
