CREATE INDEX IF NOT EXISTS idx_audit_ss_created_at ON audit_records_selfservice (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ss_timestamp ON audit_records_selfservice (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ss_principal ON audit_records_selfservice (principal);
CREATE INDEX IF NOT EXISTS idx_audit_ss_service ON audit_records_selfservice (service);

DROP INDEX IF EXISTS audit_records_selfservice_id;

CREATE TABLE IF NOT EXISTS cloudtrail_events
(
    event_id              text        not null,
    event_time            timestamptz not null,
    event_name            text        not null,
    event_source          text        not null,
    aws_region            text,
    recipient_account_id  text,
    principal_arn         text,
    principal_type        text,
    principal_name        text,
    source_ip             text,
    user_agent            text,
    error_code            text,
    read_only             boolean,
    management_event      boolean,
    s3_object_key         text,
    raw                   jsonb       not null,
    created_at            timestamptz not null default now(),
    assumed_role_arn      text,
    identity_source       text,
    user_identity_account_id text,
    PRIMARY KEY (event_id, event_time)
) PARTITION BY RANGE (event_time);

CREATE TABLE IF NOT EXISTS cloudtrail_events_default
    PARTITION OF cloudtrail_events DEFAULT;

CREATE INDEX IF NOT EXISTS idx_cloudtrail_event_time     ON cloudtrail_events (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_principal_name ON cloudtrail_events (principal_name);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_event_name     ON cloudtrail_events (event_name);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_error_code     ON cloudtrail_events (error_code);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_source_ip      ON cloudtrail_events (source_ip);

CREATE INDEX IF NOT EXISTS idx_cloudtrail_assumed_role_arn ON cloudtrail_events (assumed_role_arn);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_identity_source  ON cloudtrail_events (identity_source);

CREATE INDEX IF NOT EXISTS idx_cloudtrail_recipient_account_id     ON cloudtrail_events (recipient_account_id);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_user_identity_account_id ON cloudtrail_events (user_identity_account_id);

CREATE INDEX IF NOT EXISTS idx_ct_actor_order    ON cloudtrail_events ((COALESCE(principal_name, principal_arn)));
CREATE INDEX IF NOT EXISTS idx_ct_resource_order ON cloudtrail_events (event_source);

CREATE INDEX IF NOT EXISTS idx_cloudtrail_principal_arn ON cloudtrail_events (principal_arn);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_created_at    ON cloudtrail_events (created_at);
ALTER TABLE cloudtrail_events ALTER COLUMN principal_arn SET STATISTICS 1000;

CREATE INDEX IF NOT EXISTS idx_cloudtrail_caller_account_backfill
    ON cloudtrail_events (event_time)
    WHERE user_identity_account_id IS NULL
      AND (raw #>> '{userIdentity,accountId}') IS NOT NULL;

-- ---------------------------------------------------------------------------
-- GitHub Enterprise audit-log events.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS github_audit_events
(
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    document_id text        not null UNIQUE,
    event_time  timestamptz not null,
    action      text        not null,
    actor       text,
    actor_id    text,
    org         text,
    repo        text,
    source_ip   text,
    user_agent  text,
    raw         jsonb       not null,
    created_at  timestamptz not null default now()
);

CREATE INDEX IF NOT EXISTS idx_github_event_time ON github_audit_events (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_github_actor      ON github_audit_events (actor);
CREATE INDEX IF NOT EXISTS idx_github_action     ON github_audit_events (action);
CREATE INDEX IF NOT EXISTS idx_github_org        ON github_audit_events (org);

CREATE INDEX IF NOT EXISTS idx_gh_actor_order    ON github_audit_events (actor);
CREATE INDEX IF NOT EXISTS idx_gh_action_order   ON github_audit_events (action);
CREATE INDEX IF NOT EXISTS idx_gh_resource_order ON github_audit_events ((COALESCE(repo, org)));

CREATE INDEX IF NOT EXISTS idx_ss_actor_order    ON audit_records_selfservice (principal);
CREATE INDEX IF NOT EXISTS idx_ss_action_order   ON audit_records_selfservice (action);
CREATE INDEX IF NOT EXISTS idx_ss_resource_order ON audit_records_selfservice (service);
CREATE INDEX IF NOT EXISTS idx_audit_ss_ts_utc
    ON audit_records_selfservice (("timestamp" AT TIME ZONE 'UTC') DESC);

CREATE TABLE IF NOT EXISTS ingest_watermarks
(
    source          text PRIMARY KEY,
    last_object_key text,
    last_event_at   timestamptz,
    last_cursor     text,
    objects_scanned bigint      not null default 0,
    events_applied  bigint      not null default 0,
    last_run_at     timestamptz,
    last_run_error  text
);

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

CREATE TABLE IF NOT EXISTS actors (
    id           TEXT PRIMARY KEY,
    email        TEXT,
    display_name TEXT,
    team         TEXT,
    kind         TEXT NOT NULL DEFAULT 'unresolved',  -- person | service | unresolved
    first_seen   TIMESTAMPTZ,
    last_active  TIMESTAMPTZ,
    sources      TEXT[] NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    origins      TEXT[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS actors_kind_idx ON actors (kind);
CREATE INDEX IF NOT EXISTS actors_last_active_idx ON actors (last_active DESC);
CREATE INDEX IF NOT EXISTS idx_actors_origins ON actors USING gin (origins);

CREATE TABLE IF NOT EXISTS actor_aliases (
    alias    TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    kind     TEXT,  -- email | arn | github | principal | upn
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS actor_aliases_actor_idx ON actor_aliases (actor_id);

CREATE TABLE IF NOT EXISTS risk_scores (
    actor_id    TEXT PRIMARY KEY REFERENCES actors(id) ON DELETE CASCADE,
    score       INTEGER NOT NULL DEFAULT 0,
    label       TEXT NOT NULL DEFAULT 'low',  -- critical | high | medium | low
    components  JSONB NOT NULL DEFAULT '{}',
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS risk_scores_score_idx ON risk_scores (score DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,  -- critical | high | medium | low
    title       TEXT NOT NULL,
    description TEXT,
    actor_id    TEXT REFERENCES actors(id) ON DELETE SET NULL,
    source      TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_count BIGINT NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'open',  -- open | acked | resolved
    evidence    JSONB NOT NULL DEFAULT '{}',
    acked_by    TEXT,
    acked_at    TIMESTAMPTZ,
    resolved_by TEXT,
    resolved_at TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_status_idx ON alerts (status);
CREATE INDEX IF NOT EXISTS alerts_severity_idx ON alerts (severity);
CREATE INDEX IF NOT EXISTS alerts_actor_idx ON alerts (actor_id);
CREATE INDEX IF NOT EXISTS alerts_last_seen_idx ON alerts (last_seen DESC);

CREATE TABLE IF NOT EXISTS sessions (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_key  TEXT NOT NULL UNIQUE,
    actor_id     TEXT REFERENCES actors(id) ON DELETE SET NULL,
    source       TEXT NOT NULL,
    device       TEXT,
    source_ip    TEXT,
    location     TEXT,
    started_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    event_count  BIGINT NOT NULL DEFAULT 1,
    status       TEXT NOT NULL DEFAULT 'active',  -- active | closed | flagged
    flag_reason  TEXT
);
CREATE INDEX IF NOT EXISTS sessions_actor_idx ON sessions (actor_id);
CREATE INDEX IF NOT EXISTS sessions_last_seen_idx ON sessions (last_seen_at DESC);

CREATE TABLE IF NOT EXISTS grants (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    grant_key    TEXT NOT NULL UNIQUE,
    actor_id     TEXT REFERENCES actors(id) ON DELETE CASCADE,
    system       TEXT NOT NULL,  -- aws | github | selfservice
    role         TEXT NOT NULL,
    scope        TEXT,
    severity     TEXT NOT NULL DEFAULT 'low',
    privileged   BOOLEAN NOT NULL DEFAULT false,
    granted_at   TIMESTAMPTZ,
    granted_by   TEXT,
    source_event TEXT,
    revoked_at   TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS grants_actor_idx ON grants (actor_id);
CREATE INDEX IF NOT EXISTS grants_privileged_idx ON grants (privileged);

CREATE TABLE IF NOT EXISTS anomalies (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,   -- volume_spike | new_source | new_country | off_hours_spike
    actor_id    TEXT REFERENCES actors(id) ON DELETE CASCADE,
    severity    TEXT NOT NULL DEFAULT 'low',  -- low | medium
    score       DOUBLE PRECISION NOT NULL DEFAULT 0,
    baseline    DOUBLE PRECISION,
    observed    DOUBLE PRECISION,
    title       TEXT NOT NULL,
    detail      TEXT,
    evidence    JSONB NOT NULL DEFAULT '{}',
    event_time  TIMESTAMPTZ NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS anomalies_actor_idx ON anomalies (actor_id);
CREATE INDEX IF NOT EXISTS anomalies_kind_idx ON anomalies (kind);
CREATE INDEX IF NOT EXISTS anomalies_event_time_idx ON anomalies (event_time DESC);

CREATE TABLE IF NOT EXISTS webidentity_session_subjects (
    session_arn text        PRIMARY KEY,
    subject     text        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS leader_leases (
    scope       TEXT PRIMARY KEY,
    holder_id   TEXT        NOT NULL,
    fence_token BIGINT      NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL,
    renewed_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS actor_source_first_seen (
    actor      TEXT        NOT NULL,
    source     TEXT        NOT NULL,
    first_ts   TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (actor, source)
);

INSERT INTO actor_source_first_seen (actor, source, first_ts)
SELECT actor, source, min(ts) AS first_ts
FROM (
    SELECT principal AS actor, 'selfservice'::text AS source, (timestamp AT TIME ZONE 'UTC') AS ts
        FROM audit_records_selfservice
    UNION ALL
    SELECT COALESCE(principal_name, principal_arn), 'cloudtrail', event_time
        FROM cloudtrail_events
    UNION ALL
    SELECT actor, 'github', event_time
        FROM github_audit_events
) x
WHERE actor IS NOT NULL
GROUP BY actor, source
ON CONFLICT (actor, source) DO NOTHING;

INSERT INTO ingest_watermarks (source, last_event_at, last_run_at, objects_scanned, events_applied)
VALUES ('siem_first_seen', now() - interval '5 minutes', now(), 0, 0)
ON CONFLICT (source) DO UPDATE SET
    last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at),
    last_run_at   = now();

CREATE TABLE IF NOT EXISTS actor_daily_counts (
    actor      TEXT        NOT NULL,
    day        DATE        NOT NULL,
    n          BIGINT      NOT NULL DEFAULT 0,
    hourly     BIGINT[]    NOT NULL,   -- 24 elements; hourly[h+1] = count in UTC hour h
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (actor, day)
);

WITH boundary AS (SELECT now() - interval '15 minutes' AS b),
ev AS (
    SELECT principal AS actor,
           date_trunc('day', timestamp AT TIME ZONE 'UTC')::date AS day,
           extract(hour FROM (timestamp AT TIME ZONE 'UTC'))::int AS h
      FROM audit_records_selfservice, boundary
      WHERE created_at <= boundary.b AT TIME ZONE 'UTC'
    UNION ALL
    SELECT COALESCE(principal_name, principal_arn),
           date_trunc('day', event_time)::date,
           extract(hour FROM event_time)::int
      FROM cloudtrail_events, boundary
      WHERE created_at <= boundary.b
    UNION ALL
    SELECT actor,
           date_trunc('day', event_time)::date,
           extract(hour FROM event_time)::int
      FROM github_audit_events, boundary
      WHERE created_at <= boundary.b
),
per_hour AS (
    SELECT actor, day, h, count(*)::bigint AS cnt
      FROM ev WHERE actor IS NOT NULL GROUP BY actor, day, h
),
keys AS (SELECT DISTINCT actor, day FROM per_hour),
filled AS (
    SELECT k.actor, k.day, g.h, COALESCE(ph.cnt, 0) AS cnt
      FROM keys k
      CROSS JOIN generate_series(0, 23) g(h)
      LEFT JOIN per_hour ph ON ph.actor = k.actor AND ph.day = k.day AND ph.h = g.h
)
INSERT INTO actor_daily_counts (actor, day, n, hourly)
SELECT actor, day, sum(cnt)::bigint, array_agg(cnt ORDER BY h)
  FROM filled GROUP BY actor, day
ON CONFLICT (actor, day) DO NOTHING;

INSERT INTO ingest_watermarks (source, last_event_at, last_run_at, objects_scanned, events_applied)
VALUES ('siem_daily_counts', now() - interval '15 minutes', now(), 0, 0)
ON CONFLICT (source) DO UPDATE SET
    last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at),
    last_run_at   = now();

CREATE MATERIALIZED VIEW IF NOT EXISTS event_timeline_daily AS
    SELECT
        date_trunc('day', ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket,
        source,
        count(*)::bigint AS count
    FROM ssumgmt_events
    GROUP BY 1, 2
    WITH DATA;

CREATE UNIQUE INDEX IF NOT EXISTS event_timeline_daily_pk ON event_timeline_daily (bucket, source);

ANALYZE cloudtrail_events;
