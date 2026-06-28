CREATE TABLE IF NOT EXISTS actor_identity_context (
    actor            TEXT        NOT NULL,
    identity_source  TEXT        NOT NULL,
    assumed_role_arn TEXT        NOT NULL,
    last_ts          TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (actor, identity_source, assumed_role_arn)
);

INSERT INTO actor_identity_context (actor, identity_source, assumed_role_arn, last_ts)
SELECT COALESCE(principal_name, principal_arn) AS actor,
       COALESCE(identity_source, '')           AS identity_source,
       COALESCE(assumed_role_arn, '')          AS assumed_role_arn,
       max(event_time)                          AS last_ts
FROM cloudtrail_events
WHERE COALESCE(principal_name, principal_arn) IS NOT NULL
  AND (identity_source IS NOT NULL OR assumed_role_arn IS NOT NULL)
GROUP BY 1, 2, 3
ON CONFLICT (actor, identity_source, assumed_role_arn) DO NOTHING;

INSERT INTO ingest_watermarks (source, last_event_at, last_run_at, objects_scanned, events_applied)
VALUES ('siem_identity_context', now() - interval '5 minutes', now(), 0, 0)
ON CONFLICT (source) DO UPDATE SET
    last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at),
    last_run_at   = now();
