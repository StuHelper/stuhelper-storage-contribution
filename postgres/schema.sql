CREATE SCHEMA IF NOT EXISTS contribution;
CREATE TABLE IF NOT EXISTS contribution.contributions (
 id text PRIMARY KEY, owner_key text NOT NULL, instance_id text NOT NULL UNIQUE, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS contribution_owner ON contribution.contributions(owner_key,id);
CREATE INDEX IF NOT EXISTS contribution_state_id ON contribution.contributions((data->'View'->>'state'),id);
CREATE INDEX IF NOT EXISTS contribution_reason_id ON contribution.contributions((data->'View'->>'reason'),id);
CREATE INDEX IF NOT EXISTS contribution_adapter_id ON contribution.contributions((data->'View'->>'adapter'),id);
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
CREATE TABLE IF NOT EXISTS contribution.audit (
 id text PRIMARY KEY,
 data jsonb NOT NULL,
 reason text NOT NULL DEFAULT '',
 result text NOT NULL DEFAULT 'success' CHECK(result IN ('success','denied','failed','unknown')),
 recorded_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
 audit_actor text NOT NULL DEFAULT 'unknown',
 audit_target text NOT NULL DEFAULT 'unknown',
 audit_action text NOT NULL DEFAULT 'unknown',
 audit_school text NOT NULL DEFAULT '*',
 audit_group text NOT NULL DEFAULT '*',
 audit_time timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS reason text NOT NULL DEFAULT '';
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS result text NOT NULL DEFAULT 'success';
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS recorded_xid xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS audit_actor text NOT NULL DEFAULT 'unknown';
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS audit_target text NOT NULL DEFAULT 'unknown';
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS audit_action text NOT NULL DEFAULT 'unknown';
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS audit_school text NOT NULL DEFAULT '*';
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS audit_group text NOT NULL DEFAULT '*';
ALTER TABLE contribution.audit ADD COLUMN IF NOT EXISTS audit_time timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS contribution.audit_retention(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), revision bigint NOT NULL DEFAULT 0);
INSERT INTO contribution.audit_retention(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION contribution.audit_project() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 NEW.audit_actor=CASE WHEN COALESCE(NEW.data->'actor'->>'issuer','')='' OR COALESCE(NEW.data->'actor'->>'subject','')='' THEN 'unknown' ELSE translate(rtrim(replace(encode(convert_to(NEW.data->'actor'->>'issuer','UTF8'),'base64'),E'\n',''),'='),'+/','-_')||':'||translate(rtrim(replace(encode(convert_to(NEW.data->'actor'->>'subject','UTF8'),'base64'),E'\n',''),'='),'+/','-_') END;
 NEW.audit_target=COALESCE(NULLIF(NEW.data->'event'->>'subject',''),NULLIF(NEW.data->>'target',''),'unknown');
 NEW.audit_action=COALESCE(NULLIF(NEW.data->'event'->>'type',''),NULLIF(NEW.data->>'action',''),'unknown');
 NEW.audit_school=COALESCE(NULLIF(NEW.data->>'school',''),NULLIF(NEW.audit_school,''),'*');
 NEW.audit_time=COALESCE((NEW.data->'event'->>'time')::timestamptz,(NEW.data->>'time')::timestamptz,now());
 RETURN NEW;
END $$;
CREATE OR REPLACE TRIGGER contribution_audit_project BEFORE INSERT OR UPDATE ON contribution.audit FOR EACH ROW EXECUTE FUNCTION contribution.audit_project();
-- Historical envelopes predate the projection columns. Scope comes from
-- the owning contribution when it is still present, including worker events.
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM contribution.audit WHERE audit_action='unknown' AND COALESCE(data->'event'->>'type',data->>'action','') <> '') THEN
  UPDATE contribution.audit a SET audit_school=COALESCE(NULLIF(a.data->>'school',''),
    (SELECT c.data->'Owner'->>'issuer' FROM contribution.contributions c WHERE c.id=a.data->'event'->>'subject'),'*')
  WHERE audit_action='unknown' AND COALESCE(data->'event'->>'type',data->>'action','') <> '';
 END IF;
END $$;
CREATE OR REPLACE FUNCTION contribution.audit_invalidate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN UPDATE contribution.audit_retention SET revision=revision+1 WHERE singleton; RETURN NULL; END $$;
REVOKE ALL ON FUNCTION contribution.audit_invalidate() FROM PUBLIC;
CREATE OR REPLACE TRIGGER contribution_audit_invalidate AFTER UPDATE OR DELETE OR TRUNCATE ON contribution.audit FOR EACH STATEMENT EXECUTE FUNCTION contribution.audit_invalidate();
CREATE INDEX IF NOT EXISTS contribution_audit_query_order ON contribution.audit(audit_time DESC,(id::text) COLLATE "C" DESC);
CREATE INDEX IF NOT EXISTS contribution_audit_target_order ON contribution.audit(audit_target,audit_time DESC,(id::text) COLLATE "C" DESC);

REVOKE ALL ON SCHEMA contribution FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA contribution FROM PUBLIC;

-- Previous versions marked these reconciliation jobs complete before cleanup.
UPDATE contribution.jobs j
SET state = 'pending', data = j.data || '{"State":"pending","Attempts":0}'::jsonb
FROM contribution.contributions c
WHERE j.id = c.id AND j.state = 'complete'
  AND c.data->'View'->>'state' = 'revoked'
  AND c.data->'View'->>'reason' = 'cleanup_unconfirmed';

-- Resume exits that the previous worker stopped permanently upon custody expiry.
UPDATE contribution.jobs j
SET state = 'pending', data = j.data || '{"State":"pending","Attempts":0}'::jsonb
FROM contribution.contributions c
WHERE c.id = j.id AND j.state = 'blocked'
  AND c.data->'View'->>'desired_state' = 'exiting'
  AND c.data->'View'->>'reason' = 'authorization_required';
