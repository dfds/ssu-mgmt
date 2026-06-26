-- ssu-mgmt self-audit: the console records its own API usage as a first-class
-- source. Every intentful authenticated API call (query, export, entity inspect,
-- graph, actors list, alert triage) is written here by the `audit_usage`
-- middleware via the bg batch writer, and surfaces in `ssumgmt_events` as a
-- distinct source = 'ssu-mgmt' (the existing self-service branch hardcodes
-- 'selfservice', so the tool's own activity needs its own table to read back as
-- its own source). Unlike the self-service branch this carries a real
-- `status`/`level`, so console 403/500s show up as failures.

CREATE TABLE IF NOT EXISTS ssumgmt_audit (
    id            bigserial   PRIMARY KEY,
    message_id    text        NOT NULL UNIQUE,
    ts            timestamptz NOT NULL,
    actor         text,
    action        text        NOT NULL,
    method        text,
    path          text,
    status_code   int,
    status        text        NOT NULL DEFAULT 'success',  -- success | failure
    level         text        NOT NULL DEFAULT 'info',      -- info | warn | error
    source_ip     text,
    role          text,
    request_data  jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Mirrors the sibling source tables' index set: a created_at index for the
-- retention sweep, a ts index for time-ordered reads, and btree indexes on the
-- view-projected order columns (actor/action, resource = path) so a
-- source-filtered ORDER BY uses an index scan + incremental sort (Phase 7 shape).
CREATE INDEX IF NOT EXISTS idx_ssumgmt_audit_created_at ON ssumgmt_audit (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ssumgmt_audit_ts         ON ssumgmt_audit (ts DESC);
CREATE INDEX IF NOT EXISTS idx_ssumgmt_audit_actor      ON ssumgmt_audit (actor);
CREATE INDEX IF NOT EXISTS idx_ssumgmt_audit_action     ON ssumgmt_audit (action);
CREATE INDEX IF NOT EXISTS idx_ssumgmt_audit_path       ON ssumgmt_audit (path);

-- Re-emit the union view with a 4th branch for the new source. Column set/types
-- are unchanged, so CREATE OR REPLACE succeeds and `src/db/views.rs` is untouched.
CREATE OR REPLACE VIEW ssumgmt_events AS
    SELECT
        'selfservice'::text             AS source,
        s.id::text                      AS uid,
        s.timestamp AT TIME ZONE 'UTC'  AS ts,
        s.principal                     AS actor,
        s.action                        AS action,
        s.service                       AS resource,
        NULL::text                      AS source_ip,
        'info'::text                    AS level,
        'success'::text                 AS status,
        s.request_data                  AS raw,
        NULL::text                      AS role,
        NULL::text                      AS identity_source,
        NULL::text                      AS account_id,
        NULL::text                      AS caller_account_id
    FROM audit_records_selfservice s
    UNION ALL
    SELECT
        'cloudtrail'::text,
        c.event_id,
        c.event_time,
        COALESCE(c.principal_name, c.principal_arn),
        c.event_name,
        c.event_source,
        c.source_ip,
        CASE WHEN c.error_code IS NOT NULL THEN 'error'   ELSE 'info'    END,
        CASE WHEN c.error_code IS NOT NULL THEN 'failure' ELSE 'success' END,
        c.raw,
        c.assumed_role_arn,
        c.identity_source,
        c.recipient_account_id,
        c.user_identity_account_id
    FROM cloudtrail_events c
    UNION ALL
    SELECT
        'github'::text,
        g.document_id,
        g.event_time,
        g.actor,
        g.action,
        COALESCE(g.repo, g.org),
        g.source_ip,
        'info'::text,
        'success'::text,
        g.raw,
        NULL::text,
        NULL::text,
        NULL::text,
        NULL::text
    FROM github_audit_events g
    UNION ALL
    SELECT
        'ssu-mgmt'::text,
        a.id::text,
        a.ts,
        a.actor,
        a.action,
        a.path,
        a.source_ip,
        a.level,
        a.status,
        a.request_data,
        a.role,
        NULL::text,
        NULL::text,
        NULL::text
    FROM ssumgmt_audit a;

-- Reconcile the pre-existing triage self-audit rows (written by the now-removed
-- `write_triage_audit` into audit_records_selfservice with service='ssu-mgmt')
-- into the new dedicated table so all self-audit lives under the one source.
INSERT INTO ssumgmt_audit (message_id, ts, actor, action, method, path, status_code, status, level, request_data, created_at)
    SELECT s.message_id,
           s.timestamp  AT TIME ZONE 'UTC',
           s.principal,
           s.action,
           s.method,
           s.path,
           200,
           'success',
           'info',
           s.request_data,
           s.created_at AT TIME ZONE 'UTC'
    FROM audit_records_selfservice s
    WHERE s.service = 'ssu-mgmt'
    ON CONFLICT (message_id) DO NOTHING;

DELETE FROM audit_records_selfservice WHERE service = 'ssu-mgmt';
