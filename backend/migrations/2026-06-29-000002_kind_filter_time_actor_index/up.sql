CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_time_actor
    ON cloudtrail_events_default (event_time DESC, (COALESCE(principal_name, principal_arn)));
