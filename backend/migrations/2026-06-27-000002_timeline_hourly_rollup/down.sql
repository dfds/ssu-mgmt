DROP VIEW IF EXISTS event_timeline_daily;

CREATE MATERIALIZED VIEW IF NOT EXISTS event_timeline_daily AS
    SELECT
        date_trunc('day', ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket,
        source,
        count(*)::bigint AS count
    FROM ssumgmt_events
    GROUP BY 1, 2
    WITH DATA;
CREATE UNIQUE INDEX IF NOT EXISTS event_timeline_daily_pk
    ON event_timeline_daily (bucket, source);

DROP MATERIALIZED VIEW IF EXISTS event_timeline_hourly;
