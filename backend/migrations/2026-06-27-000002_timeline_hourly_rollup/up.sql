CREATE MATERIALIZED VIEW IF NOT EXISTS event_timeline_hourly AS
    SELECT
        date_trunc('hour', ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket,
        source,
        count(*)::bigint AS count
    FROM ssumgmt_events
    GROUP BY 1, 2
    WITH DATA;

-- Unique index required for REFRESH MATERIALIZED VIEW CONCURRENTLY.
CREATE UNIQUE INDEX IF NOT EXISTS event_timeline_hourly_pk
    ON event_timeline_hourly (bucket, source);

-- Daily rollup is now derived from the hourly matview (tiny: ≤ window_days×24
-- rows per source), not a second full scan of the union view.
DROP MATERIALIZED VIEW IF EXISTS event_timeline_daily;
CREATE VIEW event_timeline_daily AS
    SELECT
        date_trunc('day', bucket AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket,
        source,
        sum(count)::bigint AS count
    FROM event_timeline_hourly
    GROUP BY 1, 2;
