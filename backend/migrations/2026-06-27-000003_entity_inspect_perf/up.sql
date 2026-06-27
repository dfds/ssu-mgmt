ALTER TABLE actor_daily_counts ADD COLUMN IF NOT EXISTS failed BIGINT NOT NULL DEFAULT 0;

WITH w AS (
    SELECT last_event_at AS b FROM ingest_watermarks WHERE source = 'siem_daily_counts'
),
f AS (
    SELECT COALESCE(principal_name, principal_arn) AS actor,
           date_trunc('day', event_time)::date     AS day,
           count(*)::bigint                          AS failed
      FROM cloudtrail_events, w
     WHERE error_code IS NOT NULL
       AND created_at <= w.b
     GROUP BY 1, 2
)
UPDATE actor_daily_counts c
   SET failed = f.failed
  FROM f
 WHERE f.actor = c.actor AND f.day = c.day;

CREATE INDEX IF NOT EXISTS idx_ct_actor_time
    ON cloudtrail_events_default (COALESCE(principal_name, principal_arn), event_time DESC);

CREATE INDEX IF NOT EXISTS idx_ss_actor_time
    ON audit_records_selfservice (principal, ((timestamp AT TIME ZONE 'UTC')) DESC);
