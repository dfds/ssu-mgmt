-- Restore the 3-branch union view (verbatim from 2026-06-21_rework_schema), then
-- drop the dedicated table. Non-destructive to the other source/derived tables.
-- Triage rows migrated into ssumgmt_audit by up.sql are not restored into
-- audit_records_selfservice (acceptable: ephemeral self-audit).
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
    FROM github_audit_events g;

DROP TABLE IF EXISTS ssumgmt_audit;
