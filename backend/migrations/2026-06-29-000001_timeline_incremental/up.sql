DROP VIEW IF EXISTS event_timeline_daily;

CREATE TABLE event_timeline_hourly_tbl AS
    SELECT bucket, source, count FROM event_timeline_hourly;

DROP MATERIALIZED VIEW IF EXISTS event_timeline_hourly;

ALTER TABLE event_timeline_hourly_tbl RENAME TO event_timeline_hourly;
ALTER TABLE event_timeline_hourly
    ALTER COLUMN bucket SET NOT NULL,
    ALTER COLUMN source SET NOT NULL,
    ALTER COLUMN count  SET NOT NULL;
ALTER TABLE event_timeline_hourly ADD PRIMARY KEY (bucket, source);

CREATE VIEW event_timeline_daily AS
    SELECT
        date_trunc('day', bucket AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket,
        source,
        sum(count)::bigint AS count
    FROM event_timeline_hourly
    GROUP BY 1, 2;
