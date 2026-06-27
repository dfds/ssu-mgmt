CREATE INDEX IF NOT EXISTS idx_cloudtrail_failures_event_time
    ON cloudtrail_events (event_time DESC)
    WHERE error_code IS NOT NULL;
