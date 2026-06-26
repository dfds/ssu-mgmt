use anyhow::Context;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use diesel::PgConnection;

/// Derive AWS grants from the trailing `window_days` of CloudTrail IAM events.
/// Returns the number of grant rows inserted/updated.
pub fn derive(conn: &mut PgConnection, window_days: i64) -> anyhow::Result<usize> {
    let floor = Utc::now() - Duration::days(window_days.max(1));

    let n = diesel::sql_query(
        "INSERT INTO grants \
           (grant_key, actor_id, system, role, scope, severity, privileged, granted_at, granted_by, source_event, updated_at) \
         SELECT DISTINCT ON (g.grant_key) \
           g.grant_key, g.actor_id, g.system, g.role, g.scope, g.severity, g.privileged, \
           g.granted_at, g.granted_by, g.source_event, now() \
         FROM ( \
         SELECT \
           'aws:' || COALESCE(aa.actor_id, tgt.target) || ':' || tgt.role || ':' || COALESCE(tgt.scope, '') AS grant_key, \
           aa.actor_id, \
           'aws' AS system, \
           tgt.role, \
           tgt.scope, \
           CASE WHEN tgt.privileged THEN 'high' ELSE 'low' END AS severity, \
           tgt.privileged, \
           tgt.event_time AS granted_at, \
           tgt.granted_by, \
           tgt.event_id AS source_event \
         FROM ( \
           SELECT \
             event_id, \
             event_time, \
             principal_name AS granted_by, \
             CASE event_name \
               WHEN 'AddUserToGroup' THEN raw->'requestParameters'->>'userName' \
               ELSE COALESCE(raw->'requestParameters'->>'userName', raw->'requestParameters'->>'roleName') \
             END AS target, \
             CASE event_name \
               WHEN 'AddUserToGroup' THEN 'group:' || COALESCE(raw->'requestParameters'->>'groupName', '?') \
               WHEN 'PutUserPolicy'  THEN 'inline:' || COALESCE(raw->'requestParameters'->>'policyName', '?') \
               WHEN 'PutRolePolicy'  THEN 'inline:' || COALESCE(raw->'requestParameters'->>'policyName', '?') \
               ELSE COALESCE(raw->'requestParameters'->>'policyArn', raw->'requestParameters'->>'policyName', event_name) \
             END AS role, \
             recipient_account_id AS scope, \
             ( \
               COALESCE(raw->'requestParameters'->>'policyArn', '')  ~* 'Admin|PowerUser|FullAccess' \
               OR COALESCE(raw->'requestParameters'->>'policyName', '') ~* 'Admin|PowerUser|FullAccess' \
               OR event_name IN ('AttachUserPolicy','AttachRolePolicy','PutUserPolicy','PutRolePolicy') \
             ) AS privileged \
           FROM cloudtrail_events \
           WHERE event_name IN ('AttachUserPolicy','AttachRolePolicy','PutUserPolicy','PutRolePolicy','AddUserToGroup') \
             AND event_time >= $1 \
             AND error_code IS NULL \
         ) tgt \
         LEFT JOIN actor_aliases aa ON aa.alias = tgt.target \
         WHERE tgt.target IS NOT NULL \
         ) g \
         ORDER BY g.grant_key, g.granted_at DESC \
         ON CONFLICT (grant_key) DO UPDATE SET \
           granted_at   = GREATEST(grants.granted_at, EXCLUDED.granted_at), \
           granted_by   = COALESCE(EXCLUDED.granted_by, grants.granted_by), \
           source_event = EXCLUDED.source_event, \
           privileged   = EXCLUDED.privileged, \
           severity     = EXCLUDED.severity, \
           actor_id     = COALESCE(EXCLUDED.actor_id, grants.actor_id), \
           updated_at   = now()",
    )
    .bind::<Timestamptz, _>(floor)
    .execute(conn)
    .context("derive grants")?;

    Ok(n)
}
