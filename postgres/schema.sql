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
CREATE TABLE IF NOT EXISTS contribution.outbox (
 id text PRIMARY KEY, seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE, subject text NOT NULL DEFAULT '',
 data jsonb NOT NULL, delivered boolean NOT NULL DEFAULT false, sent_at timestamptz,
 attempts integer NOT NULL DEFAULT 0, first_failed_at timestamptz,
 available_at timestamptz NOT NULL DEFAULT '-infinity', manual boolean NOT NULL DEFAULT false,
 last_error text NOT NULL DEFAULT ''
);
ALTER TABLE contribution.outbox ADD COLUMN IF NOT EXISTS seq bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE contribution.outbox ADD COLUMN IF NOT EXISTS subject text NOT NULL DEFAULT '';
ALTER TABLE contribution.outbox ADD COLUMN IF NOT EXISTS sent_at timestamptz;
ALTER TABLE contribution.outbox ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0;
ALTER TABLE contribution.outbox ADD COLUMN IF NOT EXISTS first_failed_at timestamptz;
ALTER TABLE contribution.outbox ADD COLUMN IF NOT EXISTS available_at timestamptz NOT NULL DEFAULT '-infinity';
ALTER TABLE contribution.outbox ADD COLUMN IF NOT EXISTS manual boolean NOT NULL DEFAULT false;
ALTER TABLE contribution.outbox ADD COLUMN IF NOT EXISTS last_error text NOT NULL DEFAULT '';
-- Old rows received identity values in heap order. Reassign them once in
-- envelope revision order before enabling delivery with the new reader.
DO $$
DECLARE legacy record;
BEGIN
 FOR legacy IN SELECT id, data->>'subject' AS subject FROM contribution.outbox
               WHERE subject='' ORDER BY data->>'subject', (data->'data'->>'revision')::bigint
 LOOP
  UPDATE contribution.outbox SET subject=legacy.subject, seq=DEFAULT WHERE id=legacy.id;
 END LOOP;
END $$;
DROP INDEX IF EXISTS contribution.contribution_outbox_pending;
CREATE INDEX IF NOT EXISTS contribution_outbox_pending ON contribution.outbox(seq) WHERE NOT delivered AND sent_at IS NULL AND NOT manual;
CREATE INDEX IF NOT EXISTS contribution_outbox_subject ON contribution.outbox(subject,seq) WHERE NOT delivered AND sent_at IS NULL;
CREATE TABLE IF NOT EXISTS contribution.audit (id text PRIMARY KEY, data jsonb NOT NULL);
REVOKE ALL ON SCHEMA contribution FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA contribution FROM PUBLIC;

-- Previous versions marked these reconciliation jobs complete before cleanup.
UPDATE contribution.jobs j
SET state = 'pending', data = j.data || '{"State":"pending","Attempts":0}'::jsonb
FROM contribution.contributions c
WHERE j.id = c.id AND j.state = 'complete'
  AND c.data->'View'->>'state' = 'revoked'
  AND c.data->'View'->>'reason' = 'cleanup_unconfirmed';
