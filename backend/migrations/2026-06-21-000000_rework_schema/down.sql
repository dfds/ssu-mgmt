DROP MATERIALIZED VIEW IF EXISTS event_timeline_daily;

DROP TABLE IF EXISTS actor_daily_counts;
DELETE FROM ingest_watermarks WHERE source = 'siem_daily_counts';
DROP TABLE IF EXISTS actor_source_first_seen;
DELETE FROM ingest_watermarks WHERE source = 'siem_first_seen';

DROP TABLE IF EXISTS leader_leases;
DROP TABLE IF EXISTS webidentity_session_subjects;

DROP VIEW IF EXISTS ssumgmt_events;

DROP TABLE IF EXISTS anomalies;
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS risk_scores;
DROP TABLE IF EXISTS actor_aliases;
DROP TABLE IF EXISTS actors;

DROP TABLE IF EXISTS ingest_watermarks;
DROP TABLE IF EXISTS github_audit_events;
DROP TABLE IF EXISTS cloudtrail_events;

DROP INDEX IF EXISTS idx_audit_ss_ts_utc;
DROP INDEX IF EXISTS idx_ss_resource_order;
DROP INDEX IF EXISTS idx_ss_action_order;
DROP INDEX IF EXISTS idx_ss_actor_order;
DROP INDEX IF EXISTS idx_audit_ss_created_at;
DROP INDEX IF EXISTS idx_audit_ss_timestamp;
DROP INDEX IF EXISTS idx_audit_ss_principal;
DROP INDEX IF EXISTS idx_audit_ss_service;

CREATE UNIQUE INDEX IF NOT EXISTS audit_records_selfservice_id ON audit_records_selfservice (id);
