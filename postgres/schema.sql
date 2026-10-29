CREATE SCHEMA IF NOT EXISTS contribution;
CREATE TABLE IF NOT EXISTS contribution.contributions (
 id text PRIMARY KEY, owner_key text NOT NULL, instance_id text NOT NULL UNIQUE, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS contribution_owner ON contribution.contributions(owner_key,id);
CREATE TABLE IF NOT EXISTS contribution.jobs (
 id text PRIMARY KEY REFERENCES contribution.contributions(id), state text NOT NULL,
 available_at timestamptz NOT NULL, lease_until timestamptz NOT NULL, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS contribution_jobs_claim ON contribution.jobs(state,available_at,lease_until);
CREATE TABLE IF NOT EXISTS contribution.replays (key text PRIMARY KEY, expires_at timestamptz NOT NULL, data jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS contribution_replays_expiry ON contribution.replays(expires_at);
CREATE TABLE IF NOT EXISTS contribution.outbox (id text PRIMARY KEY, data jsonb NOT NULL, delivered boolean NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS contribution_outbox_pending ON contribution.outbox(id) WHERE NOT delivered;
CREATE TABLE IF NOT EXISTS contribution.audit (id text PRIMARY KEY, data jsonb NOT NULL);
REVOKE ALL ON SCHEMA contribution FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA contribution FROM PUBLIC;
