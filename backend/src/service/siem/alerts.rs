use anyhow::Context;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Double, Text, Timestamptz};
use diesel::PgConnection;

/// Run every detection rule + post-processing (session flagging, auto-resolve).
/// Returns the number of alert rows inserted/updated by the rules.
pub fn evaluate(conn: &mut PgConnection, siem: &crate::misc::config::SiemConfig) -> anyhow::Result<usize> {
    let now = Utc::now();
    let window_floor = now - Duration::days(siem.window_days.max(1));
    let h24 = now - Duration::hours(24);
    let dormant_floor = now - Duration::days(siem.dormant_days.max(1));
    let ohs = siem.off_hours_start as f64;
    let ohe = siem.off_hours_end as f64;

    let mut touched = 0usize;

    conn.transaction::<_, anyhow::Error, _>(|conn| {
        // Rule: console_login_bruteforce
        touched += diesel::sql_query(
            "INSERT INTO alerts (fingerprint, rule_id, severity, title, description, actor_id, source, first_seen, last_seen, event_count, status, evidence, updated_at) \
             SELECT \
               'console_login_bruteforce:' || COALESCE(c.principal_name, '?') || ':' || COALESCE(c.source_ip, '?') || ':' || to_char(date_trunc('day', c.event_time), 'YYYY-MM-DD'), \
               'console_login_bruteforce', 'high', 'Repeated failed console logins', \
               COALESCE(c.principal_name, '?') || ' had ' || count(*) || ' failed ConsoleLogin attempts from ' || COALESCE(c.source_ip, 'unknown'), \
               aa.actor_id, 'cloudtrail', min(c.event_time), max(c.event_time), count(*), 'open', \
               jsonb_build_object('ip', c.source_ip, 'count', count(*)), now() \
             FROM cloudtrail_events c \
             LEFT JOIN actor_aliases aa ON aa.alias = COALESCE(c.principal_name, c.principal_arn) \
             WHERE c.event_name = 'ConsoleLogin' \
               AND (c.raw->'responseElements'->>'ConsoleLogin' = 'Failure' OR c.error_code IS NOT NULL) \
               AND c.event_time >= $1 \
             GROUP BY c.principal_name, c.source_ip, date_trunc('day', c.event_time), aa.actor_id \
             HAVING count(*) >= $2 \
             ON CONFLICT (fingerprint) DO UPDATE SET \
               last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen), event_count = EXCLUDED.event_count, \
               description = EXCLUDED.description, evidence = EXCLUDED.evidence, severity = EXCLUDED.severity, \
               status = CASE WHEN alerts.status = 'resolved' AND EXCLUDED.last_seen > COALESCE(alerts.resolved_at, alerts.last_seen) THEN 'open' ELSE alerts.status END, updated_at = now()",
        )
        .bind::<Timestamptz, _>(window_floor)
        .bind::<BigInt, _>(siem.bruteforce_threshold.max(1))
        .execute(conn)
        .context("rule console_login_bruteforce")?;

        // Rule: off_hours_key_creation
        touched += diesel::sql_query(
            "INSERT INTO alerts (fingerprint, rule_id, severity, title, description, actor_id, source, first_seen, last_seen, event_count, status, evidence, updated_at) \
             SELECT \
               'off_hours_key_creation:' || c.event_id, 'off_hours_key_creation', 'medium', 'Access key created during off-hours', \
               COALESCE(c.principal_name, '?') || ' created an access key at ' || to_char(c.event_time, 'HH24:MI') || ' UTC', \
               aa.actor_id, 'cloudtrail', c.event_time, c.event_time, 1, 'open', \
               jsonb_build_object('event_id', c.event_id, 'hour', EXTRACT(hour FROM c.event_time)), now() \
             FROM cloudtrail_events c \
             LEFT JOIN actor_aliases aa ON aa.alias = COALESCE(c.principal_name, c.principal_arn) \
             WHERE c.event_name = 'CreateAccessKey' AND c.error_code IS NULL AND c.event_time >= $1 \
               AND (EXTRACT(hour FROM c.event_time) >= $2 OR EXTRACT(hour FROM c.event_time) < $3) \
             ON CONFLICT (fingerprint) DO UPDATE SET \
               last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen), description = EXCLUDED.description, \
               evidence = EXCLUDED.evidence, status = CASE WHEN alerts.status = 'resolved' AND EXCLUDED.last_seen > COALESCE(alerts.resolved_at, alerts.last_seen) THEN 'open' ELSE alerts.status END, updated_at = now()",
        )
        .bind::<Timestamptz, _>(window_floor)
        .bind::<Double, _>(ohs)
        .bind::<Double, _>(ohe)
        .execute(conn)
        .context("rule off_hours_key_creation")?;

        // Rule: priv_role_self_assign
        touched += diesel::sql_query(
            "INSERT INTO alerts (fingerprint, rule_id, severity, title, description, actor_id, source, first_seen, last_seen, event_count, status, evidence, updated_at) \
             SELECT \
               'priv_role_self_assign:' || c.event_id, 'priv_role_self_assign', 'critical', 'Privileged self-assignment', \
               COALESCE(c.principal_name, '?') || ' attached a privileged policy to themselves', \
               aa.actor_id, 'cloudtrail', c.event_time, c.event_time, 1, 'open', \
               jsonb_build_object('event_id', c.event_id, 'policy', COALESCE(c.raw->'requestParameters'->>'policyArn', c.raw->'requestParameters'->>'policyName')), now() \
             FROM cloudtrail_events c \
             LEFT JOIN actor_aliases aa ON aa.alias = COALESCE(c.principal_name, c.principal_arn) \
             WHERE c.event_name IN ('AttachUserPolicy','PutUserPolicy','AttachRolePolicy','PutRolePolicy') \
               AND c.error_code IS NULL AND c.event_time >= $1 \
               AND (c.raw->'requestParameters'->>'userName' = c.principal_name OR c.raw->'requestParameters'->>'roleName' = c.principal_name) \
               AND (COALESCE(c.raw->'requestParameters'->>'policyArn', '') ~* 'Admin|PowerUser|FullAccess' \
                 OR COALESCE(c.raw->'requestParameters'->>'policyName', '') ~* 'Admin|PowerUser|FullAccess') \
             ON CONFLICT (fingerprint) DO UPDATE SET \
               last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen), description = EXCLUDED.description, \
               evidence = EXCLUDED.evidence, status = CASE WHEN alerts.status = 'resolved' AND EXCLUDED.last_seen > COALESCE(alerts.resolved_at, alerts.last_seen) THEN 'open' ELSE alerts.status END, updated_at = now()",
        )
        .bind::<Timestamptz, _>(window_floor)
        .execute(conn)
        .context("rule priv_role_self_assign")?;

        // Rule: dormant_principal_active
        touched += diesel::sql_query(
            "INSERT INTO alerts (fingerprint, rule_id, severity, title, description, actor_id, source, first_seen, last_seen, event_count, status, evidence, updated_at) \
             WITH agg AS ( \
               SELECT aa.actor_id AS actor_id, \
                 max(c.event_time) AS last_ts, \
                 max(c.event_time) FILTER (WHERE c.event_time < $1) AS prev_ts \
               FROM cloudtrail_events c \
               JOIN actor_aliases aa ON aa.alias = COALESCE(c.principal_name, c.principal_arn) \
               GROUP BY aa.actor_id \
             ) \
             SELECT \
               'dormant_principal_active:' || agg.actor_id || ':' || to_char($1, 'YYYY-MM-DD'), \
               'dormant_principal_active', 'medium', 'Dormant principal reactivated', \
               agg.actor_id || ' became active after a dormant period', \
               agg.actor_id, 'cloudtrail', agg.prev_ts, agg.last_ts, 1, 'open', \
               jsonb_build_object('last_active', agg.last_ts, 'previously_active', agg.prev_ts), now() \
             FROM agg \
             WHERE agg.last_ts >= $1 AND agg.prev_ts IS NOT NULL AND agg.prev_ts < $2 \
             ON CONFLICT (fingerprint) DO UPDATE SET \
               last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen), description = EXCLUDED.description, \
               evidence = EXCLUDED.evidence, status = CASE WHEN alerts.status = 'resolved' AND EXCLUDED.last_seen > COALESCE(alerts.resolved_at, alerts.last_seen) THEN 'open' ELSE alerts.status END, updated_at = now()",
        )
        .bind::<Timestamptz, _>(h24)
        .bind::<Timestamptz, _>(dormant_floor)
        .execute(conn)
        .context("rule dormant_principal_active")?;

        // Rule: github_secret_scanning
        touched += diesel::sql_query(
            "INSERT INTO alerts (fingerprint, rule_id, severity, title, description, actor_id, source, first_seen, last_seen, event_count, status, evidence, updated_at) \
             SELECT \
               'github_secret_scanning:' || g.document_id, 'github_secret_scanning', 'high', 'GitHub secret scanning', \
               COALESCE(g.actor, '?') || ' — ' || g.action, aa.actor_id, 'github', g.event_time, g.event_time, 1, 'open', \
               jsonb_build_object('action', g.action, 'repo', g.repo), now() \
             FROM github_audit_events g \
             LEFT JOIN actor_aliases aa ON aa.alias = g.actor \
             WHERE g.action ILIKE 'secret_scanning%' AND g.event_time >= $1 \
             ON CONFLICT (fingerprint) DO UPDATE SET \
               last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen), description = EXCLUDED.description, \
               evidence = EXCLUDED.evidence, status = CASE WHEN alerts.status = 'resolved' AND EXCLUDED.last_seen > COALESCE(alerts.resolved_at, alerts.last_seen) THEN 'open' ELSE alerts.status END, updated_at = now()",
        )
        .bind::<Timestamptz, _>(window_floor)
        .execute(conn)
        .context("rule github_secret_scanning")?;

        // Flag sessions tied to an open/acked high+ alert for the same actor.
        diesel::sql_query(
            "UPDATE sessions s SET status = 'flagged', flag_reason = 'linked to ' || a.rule_id \
             FROM alerts a \
             WHERE a.actor_id = s.actor_id AND a.status IN ('open','acked') AND a.severity IN ('high','critical') \
               AND s.status <> 'flagged' AND s.last_seen_at >= a.first_seen - interval '1 day'",
        )
        .execute(conn)
        .context("flag sessions")?;

        diesel::sql_query(
            "UPDATE alerts SET status = 'resolved', resolved_by = 'auto', resolved_at = now(), updated_at = now() \
             WHERE status = 'open' AND source <> 'guardduty' AND last_seen < now() - interval '24 hours'",
        )
        .execute(conn)
        .context("auto-resolve alerts")?;

        Ok(())
    })?;

    Ok(touched)
}

/// Acknowledge an alert (triage). Returns the number of rows updated (0 if the
/// alert is missing or already resolved). Writes a self-service audit event.
pub fn ack(conn: &mut PgConnection, id: i64, who: &str) -> anyhow::Result<usize> {
    let n = diesel::sql_query(
        "UPDATE alerts SET status = 'acked', acked_by = $2, acked_at = now(), updated_at = now() \
         WHERE id = $1 AND status <> 'resolved'",
    )
    .bind::<BigInt, _>(id)
    .bind::<Text, _>(who)
    .execute(conn)
    .context("ack alert")?;
    if n > 0 {
        write_triage_audit(conn, "alert.ack", who, id)?;
    }
    Ok(n)
}

/// Resolve an alert (triage). Returns the number of rows updated. Writes an audit event.
pub fn resolve(conn: &mut PgConnection, id: i64, who: &str) -> anyhow::Result<usize> {
    let n = diesel::sql_query(
        "UPDATE alerts SET status = 'resolved', resolved_by = $2, resolved_at = now(), updated_at = now() \
         WHERE id = $1",
    )
    .bind::<BigInt, _>(id)
    .bind::<Text, _>(who)
    .execute(conn)
    .context("resolve alert")?;
    if n > 0 {
        write_triage_audit(conn, "alert.resolve", who, id)?;
    }
    Ok(n)
}

/// Un-acknowledge an alert: revert `acked → open`, clearing the ack trail.
/// No-op (0 rows) unless the alert is currently acked. Writes an audit event.
pub fn unack(conn: &mut PgConnection, id: i64, who: &str) -> anyhow::Result<usize> {
    let n = diesel::sql_query(
        "UPDATE alerts SET status = 'open', acked_by = NULL, acked_at = NULL, updated_at = now() \
         WHERE id = $1 AND status = 'acked'",
    )
    .bind::<BigInt, _>(id)
    .execute(conn)
    .context("unack alert")?;
    if n > 0 {
        write_triage_audit(conn, "alert.unack", who, id)?;
    }
    Ok(n)
}

/// Un-resolve an alert: revert `resolved` to its prior active state (`acked` when
/// an ack trail survives, else `open`), clearing the resolve trail.
/// No-op (0 rows) unless the alert is currently resolved. Writes an audit event.
pub fn unresolve(conn: &mut PgConnection, id: i64, who: &str) -> anyhow::Result<usize> {
    let n = diesel::sql_query(
        "UPDATE alerts SET status = CASE WHEN acked_at IS NOT NULL THEN 'acked' ELSE 'open' END, \
           resolved_by = NULL, resolved_at = NULL, updated_at = now() \
         WHERE id = $1 AND status = 'resolved'",
    )
    .bind::<BigInt, _>(id)
    .execute(conn)
    .context("unresolve alert")?;
    if n > 0 {
        write_triage_audit(conn, "alert.unresolve", who, id)?;
    }
    Ok(n)
}

/// Record a triage action as a self-service audit event (the tool audits itself).
fn write_triage_audit(conn: &mut PgConnection, action: &str, who: &str, alert_id: i64) -> anyhow::Result<()> {
    diesel::sql_query(
        "INSERT INTO audit_records_selfservice \
           (message_id, type, principal, action, method, path, service, timestamp, created_at, request_data) \
         VALUES ('triage-' || $3 || '-' || $1 || '-' || extract(epoch FROM now())::bigint, \
                 'triage', $2, $1, 'POST', '/api/alerts/' || $3 || '/' || split_part($1, '.', 2), 'ssu-mgmt', \
                 now(), now(), jsonb_build_object('alert_id', $3, 'by', $2))",
    )
    .bind::<Text, _>(action)
    .bind::<Text, _>(who)
    .bind::<BigInt, _>(alert_id)
    .execute(conn)
    .context("write triage audit")?;
    Ok(())
}
