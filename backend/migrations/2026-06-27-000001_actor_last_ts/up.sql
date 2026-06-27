ALTER TABLE actor_source_first_seen ADD COLUMN IF NOT EXISTS last_ts TIMESTAMPTZ;

UPDATE actor_source_first_seen f
SET last_ts = agg.last_ts
FROM (
    SELECT actor, source, max(ts) AS last_ts
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
) agg
WHERE f.actor = agg.actor AND f.source = agg.source;
