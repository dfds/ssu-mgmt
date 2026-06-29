CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_identity_source_null
    ON cloudtrail_events (event_time DESC)
    WHERE identity_source IS NULL;
