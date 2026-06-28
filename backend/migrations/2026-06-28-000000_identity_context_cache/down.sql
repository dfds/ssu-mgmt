DROP TABLE IF EXISTS actor_identity_context;
DELETE FROM ingest_watermarks WHERE source = 'siem_identity_context';
