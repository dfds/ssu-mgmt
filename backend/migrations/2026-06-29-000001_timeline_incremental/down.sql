DROP VIEW IF EXISTS event_timeline_daily;
DROP TABLE IF EXISTS event_timeline_hourly;

CREATE MATERIALIZED VIEW event_timeline_hourly AS
    SELECT
        date_trunc('hour', ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket,
        source,
        count(*)::bigint AS count
    FROM ssumgmt_events
    GROUP BY 1, 2
    WITH DATA;

CREATE UNIQUE INDEX event_timeline_hourly_pk
    ON event_timeline_hourly (bucket, source);

CREATE VIEW event_timeline_daily AS
    SELECT
        date_trunc('day', bucket AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket,
        source,
        sum(count)::bigint AS count
    FROM event_timeline_hourly
    GROUP BY 1, 2;
