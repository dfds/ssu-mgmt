use std::collections::HashMap;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, Nullable, Text, Timestamptz};
use diesel::PgConnection;
use log::{info, warn};
use serde_json::Value;

use crate::misc::config::SelfserviceConfig;

/// A roster member as resolved from selfservice-api. Tolerant of field naming
/// across the API surface.
#[derive(Clone, Debug)]
pub struct RosterMember {
    pub email: String,
    pub upn: Option<String>,
    pub display_name: Option<String>,
    pub team: Option<String>,
    /// Azure AD object id — present only for service principals (the roster's
    /// `UserId` when it isn't an email-like UPN). Lets a federated/web-identity
    /// GUID actor stitch to the named SP.
    pub object_id: Option<String>,
}

/// Best-effort fetch of the authoritative roster from selfservice-api's REST API.
/// Returns an empty vec (graceful degradation) on any error or when unconfigured.
#[tracing::instrument(name = "siem.roster_fetch", skip_all, fields(otel.kind = "client", peer.service = "selfservice-api"))]
pub async fn fetch_roster(conf: &SelfserviceConfig) -> Vec<RosterMember> {
    if conf.base_url.is_empty() {
        info!("siem/actors: selfservice base_url unset — roster enrichment skipped");
        return Vec::new();
    }
    match fetch_roster_inner(conf).await {
        Ok(members) => {
            info!("siem/actors: fetched {} roster members from selfservice-api", members.len());
            members
        }
        Err(e) => {
            warn!("siem/actors: roster fetch failed ({:#}) — falling back to unresolved", e);
            Vec::new()
        }
    }
}

async fn fetch_roster_inner(conf: &SelfserviceConfig) -> anyhow::Result<Vec<RosterMember>> {
    let url = format!("{}/system/legacy/aad-aws-sync", conf.base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let bearer: Option<String> = if !conf.token.is_empty() {
        Some(conf.token.clone())
    } else if !conf.client_id.is_empty()
        && !conf.client_secret.is_empty()
        && !conf.tenant_id.is_empty()
    {
        Some(fetch_access_token(conf, &client).await.context("mint selfservice token")?)
    } else {
        warn!("siem/actors: no selfservice token or client credentials configured — roster request unauthenticated");
        None
    };

    let mut req = client.get(&url).header("Accept", "application/json");
    if let Some(b) = &bearer {
        req = req.bearer_auth(b);
    }
    let resp = req.send().await.context("send roster request")?;
    if !resp.status().is_success() {
        anyhow::bail!("roster endpoint {} returned {}", url, resp.status());
    }
    let body: Value = resp.json().await.context("parse roster json")?;
    Ok(parse_capability_roster(&body))
}

fn parse_capability_roster(body: &Value) -> Vec<RosterMember> {
    let caps = body
        .as_array()
        .cloned()
        .or_else(|| body.get("items").and_then(|v| v.as_array()).cloned())
        .or_else(|| body.get("capabilities").and_then(|v| v.as_array()).cloned())
        .unwrap_or_default();

    // Keyed by canonical id: lowercased email for people, lowercased object id for
    // service principals.
    let mut by_key: HashMap<String, RosterMember> = HashMap::new();
    for cap in &caps {
        let team = first_str(cap, &["name", "Name"]);
        let members = match cap.get("members").or_else(|| cap.get("Members")).and_then(Value::as_array) {
            Some(m) => m,
            None => continue,
        };
        for m in members {
            let email = first_str(m, &["email", "Email"]).filter(|e| e.contains('@'));
            let user_id = first_str(m, &["userId", "UserId"]);
            match email {
                // Person: email-keyed; UserId becomes the UPN alias only when it
                // looks like one, so GUIDs never become bogus UPN aliases.
                Some(email) => {
                    let upn = user_id.filter(|s| s.contains('@'));
                    by_key
                        .entry(email.to_lowercase())
                        .and_modify(|existing| {
                            if existing.team.is_none() {
                                existing.team = team.clone();
                            }
                            if existing.upn.is_none() {
                                existing.upn = upn.clone();
                            }
                        })
                        .or_insert_with(|| RosterMember {
                            email,
                            upn,
                            display_name: None,
                            team: team.clone(),
                            object_id: None,
                        });
                }
                // Service principal: anchor on the Azure object id (the non-email
                // UserId). No object id → no usable key, skip.
                None => {
                    let object_id = match user_id.filter(|s| !s.is_empty() && !s.contains('@')) {
                        Some(oid) => oid,
                        None => continue,
                    };
                    let name = first_str(m, &["name", "Name", "displayName", "DisplayName"]);
                    by_key
                        .entry(object_id.to_lowercase())
                        .and_modify(|existing| {
                            if existing.team.is_none() {
                                existing.team = team.clone();
                            }
                            if existing.display_name.is_none() {
                                existing.display_name = name.clone();
                            }
                        })
                        .or_insert_with(|| RosterMember {
                            email: String::new(),
                            upn: None,
                            display_name: name,
                            team: team.clone(),
                            object_id: Some(object_id),
                        });
                }
            }
        }
    }
    by_key.into_values().collect()
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
}

async fn fetch_access_token(
    conf: &SelfserviceConfig,
    client: &reqwest::Client,
) -> anyhow::Result<String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        conf.tenant_id
    );
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", conf.client_id.as_str()),
        ("client_secret", conf.client_secret.as_str()),
        ("scope", conf.token_scope.as_str()),
    ];
    let resp = client
        .post(&url)
        .form(&params)
        .send()
        .await
        .context("send token request")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("AAD token endpoint returned {} :: {}", status, body);
    }
    let tok: TokenResponse = resp.json().await.context("parse token json")?;
    Ok(tok.access_token)
}

fn first_str(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(Value::as_str) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Person,
    Service,
    Unresolved,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Person => "person",
            Kind::Service => "service",
            Kind::Unresolved => "unresolved",
        }
    }
    /// Strength ordering for merging: person > service > unresolved.
    fn rank(self) -> u8 {
        match self {
            Kind::Person => 2,
            Kind::Service => 1,
            Kind::Unresolved => 0,
        }
    }
}

/// Conservative service-principal heuristic — only clear automation markers.
fn is_serviceish(name: &str) -> bool {
    let n = name.to_lowercase();
    n.starts_with("svc-")
        || n.ends_with("-bot")
        || n.contains("github-actions")
        || n.contains("automation")
        || n.contains("terraform")
}

/// A reconciled identity, aggregated across all of an actor's raw appearances.
struct Resolved {
    id: String,
    kind: Kind,
    email: Option<String>,
    display_name: Option<String>,
    team: Option<String>,
    first_seen: DateTime<Utc>,
    last_active: DateTime<Utc>,
    sources: Vec<String>,
    /// Distinct identity-origin badges (kubernetes/azure-ad/aws/github/…) unioned
    /// across this actor's raw appearances.
    origins: Vec<String>,
    /// Raw `actor` strings (per source) that resolve to this id.
    aliases: Vec<(String, String)>, // (alias, alias_kind)
}

#[derive(QueryableByName)]
struct ActorActivity {
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Timestamptz)]
    first_seen: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    last_active: DateTime<Utc>,
}

/// Classify one raw `(source, actor)` into a canonical id + kind + alias kind.
/// `by_object_id` maps Azure AD object ids → roster service principals, so a
/// federated/web-identity GUID actor can stitch to the named SP.
fn classify(
    source: &str,
    actor: &str,
    roster: &HashMap<String, RosterMember>,
    by_object_id: &HashMap<String, RosterMember>,
) -> (String, Kind, Option<RosterMember>, String) {
    let lower = actor.to_lowercase();

    if actor.contains('@') {
        if let Some(m) = roster.get(&lower) {
            return (m.email.to_lowercase(), Kind::Person, Some(m.clone()), "email".to_string());
        }
        if is_serviceish(&lower) {
            return (lower, Kind::Service, None, "email".to_string());
        }
        // Email-like but not in roster → stands alone as its own person actor.
        return (lower.clone(), Kind::Person, None, "email".to_string());
    }

    if actor.starts_with("arn:") {
        return (actor.to_string(), Kind::Unresolved, None, "arn".to_string());
    }

    // Kubernetes service account (EKS IRSA / pod-identity via OIDC). The
    // `system:serviceaccount:<ns>:<name>` prefix is an unambiguous signal it's a
    // k8s SA, so resolve it as a non-human `service` with a dedicated `k8s` alias
    // kind instead of letting it fall through to `unresolved`.
    if lower.starts_with("system:serviceaccount:") {
        return (actor.to_string(), Kind::Service, None, "k8s".to_string());
    }

    // Azure-AD-federated web-identity subject (an object id) → the named service
    // principal when it's in the roster. The canonical id is the object id, so the
    // GUID actor maps to itself but gains kind=service + the SP's team/name.
    if let Some(m) = by_object_id.get(&lower) {
        let id = m.object_id.clone().unwrap_or_else(|| lower.clone());
        return (id.to_lowercase(), Kind::Service, Some(m.clone()), "oidc".to_string());
    }

    let alias_kind = match source {
        "github" => "github",
        "selfservice" => "principal",
        _ => "principal",
    };

    if is_serviceish(&lower) {
        return (actor.to_string(), Kind::Service, None, alias_kind.to_string());
    }

    (actor.to_string(), Kind::Unresolved, None, alias_kind.to_string())
}

/// Derive the identity-origin badges for one raw `(source, actor)` appearance.
/// An actor accumulates the distinct *set* of origins it was seen through, so the
/// list/inspect surfaces can show where each identity came from. Coarse on the
/// AWS side (`aws`, not split SSO/IAM — per-event provenance lives in the
/// `identity_source`). Taxonomy: `kubernetes`, `azure-ad`, `aws`, `github`,
/// `selfservice`, `unknown`.
///
/// - `system:serviceaccount:` prefix → `["kubernetes"]` (k8s supersedes the feed
///   badge — the OIDC feed it rode in on is incidental to it being a k8s SA).
/// - otherwise: `azure-ad` when roster-matched (a roster person, or an
///   object-id-matched service principal), then the **feed** origin from `source`
///   (`cloudtrail → aws`, `github → github`, `selfservice → selfservice`); if
///   nothing applied → `["unknown"]`.
fn origins_for(source: &str, actor: &str, resolved_via_roster: bool) -> Vec<&'static str> {
    if actor.to_lowercase().starts_with("system:serviceaccount:") {
        return vec!["kubernetes"];
    }
    let mut out = Vec::new();
    if resolved_via_roster {
        out.push("azure-ad");
    }
    match source {
        "cloudtrail" => out.push("aws"),
        "github" => out.push("github"),
        "selfservice" => out.push("selfservice"),
        _ => {}
    }
    if out.is_empty() {
        out.push("unknown");
    }
    out
}

/// Reconcile actors + aliases from the roster and the windowed union view.
/// Runs inside `spawn_blocking`. Returns the number of canonical actors upserted.
pub fn reconcile(conn: &mut PgConnection, roster: &[RosterMember], window_days: i64) -> anyhow::Result<usize> {
    let floor = Utc::now() - Duration::days(window_days.max(1));

    let roster_map: HashMap<String, RosterMember> = roster
        .iter()
        .flat_map(|m| {
            // Only real `@`-emails / UPNs anchor the person spine; SP entries have
            // an empty email and are matched via `by_object_id` instead.
            let mut keys = Vec::new();
            if m.email.contains('@') {
                keys.push((m.email.to_lowercase(), m.clone()));
            }
            if let Some(upn) = &m.upn {
                keys.push((upn.to_lowercase(), m.clone()));
            }
            keys
        })
        .collect();

    // Azure object id → service principal, for federated/web-identity GUID actors.
    let by_object_id: HashMap<String, RosterMember> = roster
        .iter()
        .filter_map(|m| m.object_id.as_ref().map(|o| (o.to_lowercase(), m.clone())))
        .collect();

    // Distinct actor activity across all sources in the window.
    let activity: Vec<ActorActivity> = diesel::sql_query(
        "SELECT source, actor, min(ts) AS first_seen, max(ts) AS last_active \
         FROM ssumgmt_events \
         WHERE actor IS NOT NULL AND actor <> '' AND ts >= $1 \
         GROUP BY source, actor",
    )
    .bind::<Timestamptz, _>(floor)
    .load(conn)
    .context("load actor activity")?;

    // Aggregate per canonical id.
    let mut by_id: HashMap<String, Resolved> = HashMap::new();
    for a in &activity {
        let (id, kind, member, alias_kind) = classify(&a.source, &a.actor, &roster_map, &by_object_id);
        let member_email = member.as_ref().map(|m| m.email.clone()).filter(|e| e.contains('@'));
        let entry = by_id.entry(id.clone()).or_insert_with(|| Resolved {
            id: id.clone(),
            kind,
            email: member_email.clone(),
            display_name: member.as_ref().and_then(|m| m.display_name.clone()),
            team: member.as_ref().and_then(|m| m.team.clone()),
            first_seen: a.first_seen,
            last_active: a.last_active,
            sources: Vec::new(),
            origins: Vec::new(),
            aliases: Vec::new(),
        });
        if kind.rank() > entry.kind.rank() {
            entry.kind = kind;
        }
        if let Some(m) = &member {
            if entry.email.is_none() {
                entry.email = member_email.clone();
            }
            if entry.display_name.is_none() {
                entry.display_name = m.display_name.clone();
            }
            if entry.team.is_none() {
                entry.team = m.team.clone();
            }
        }
        entry.first_seen = entry.first_seen.min(a.first_seen);
        entry.last_active = entry.last_active.max(a.last_active);
        if !entry.sources.contains(&a.source) {
            entry.sources.push(a.source.clone());
        }
        for o in origins_for(&a.source, &a.actor, member.is_some()) {
            if !entry.origins.iter().any(|x| x == o) {
                entry.origins.push(o.to_string());
            }
        }
        entry.aliases.push((a.actor.clone(), alias_kind));
        // Unresolved/service ids equal their raw value, so a self-alias keeps the
        // resolution table total (every raw value resolves to a canonical id).
    }

    // Seed roster people who may have no events yet, so the roster is browsable.
    // SP entries (empty email) aren't seeded — they only matter when they actually
    // appear as a GUID actor, at which point `classify` resolves them.
    for m in roster {
        if !m.email.contains('@') {
            continue;
        }
        let id = m.email.to_lowercase();
        by_id.entry(id.clone()).or_insert_with(|| Resolved {
            id,
            kind: Kind::Person,
            email: Some(m.email.clone()),
            display_name: m.display_name.clone(),
            team: m.team.clone(),
            first_seen: Utc::now(),
            last_active: Utc::now(),
            sources: vec!["selfservice".to_string()],
            // The AAD roster *is* Azure AD — a seeded-but-unseen person originates there.
            origins: vec!["azure-ad".to_string()],
            aliases: Vec::new(),
        });
    }

    let count = by_id.len();
    conn.transaction::<_, anyhow::Error, _>(|conn| {
        for r in by_id.values() {
            diesel::sql_query(
                "INSERT INTO actors (id, email, display_name, team, kind, first_seen, last_active, sources, origins, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now()) \
                 ON CONFLICT (id) DO UPDATE SET \
                   email        = COALESCE(EXCLUDED.email, actors.email), \
                   display_name = COALESCE(EXCLUDED.display_name, actors.display_name), \
                   team         = COALESCE(EXCLUDED.team, actors.team), \
                   kind         = CASE WHEN EXCLUDED.kind <> 'unresolved' THEN EXCLUDED.kind ELSE actors.kind END, \
                   first_seen   = LEAST(EXCLUDED.first_seen, actors.first_seen), \
                   last_active  = GREATEST(EXCLUDED.last_active, actors.last_active), \
                   sources      = (SELECT array_agg(DISTINCT x) FROM unnest(actors.sources || EXCLUDED.sources) x), \
                   origins      = (SELECT array_agg(DISTINCT x) FROM unnest(actors.origins || EXCLUDED.origins) x), \
                   updated_at   = now()",
            )
            .bind::<Text, _>(&r.id)
            .bind::<Nullable<Text>, _>(r.email.as_ref())
            .bind::<Nullable<Text>, _>(r.display_name.as_ref())
            .bind::<Nullable<Text>, _>(r.team.as_ref())
            .bind::<Text, _>(r.kind.as_str())
            .bind::<Timestamptz, _>(r.first_seen)
            .bind::<Timestamptz, _>(r.last_active)
            .bind::<Array<Text>, _>(&r.sources)
            .bind::<Array<Text>, _>(&r.origins)
            .execute(conn)
            .context("upsert actor")?;

            for (alias, alias_kind) in &r.aliases {
                diesel::sql_query(
                    "INSERT INTO actor_aliases (alias, actor_id, kind) VALUES ($1, $2, $3) \
                     ON CONFLICT (alias) DO UPDATE SET actor_id = EXCLUDED.actor_id, kind = EXCLUDED.kind",
                )
                .bind::<Text, _>(alias)
                .bind::<Text, _>(&r.id)
                .bind::<Text, _>(alias_kind)
                .execute(conn)
                .context("upsert alias")?;
            }
            // Roster aliases (email + upn) for people seeded without events.
            if r.kind == Kind::Person {
                if let Some(email) = &r.email {
                    diesel::sql_query(
                        "INSERT INTO actor_aliases (alias, actor_id, kind) VALUES ($1, $2, 'email') \
                         ON CONFLICT (alias) DO UPDATE SET actor_id = EXCLUDED.actor_id, kind = EXCLUDED.kind",
                    )
                    .bind::<Text, _>(email.to_lowercase())
                    .bind::<Text, _>(&r.id)
                    .execute(conn)
                    .context("upsert email alias")?;
                }
            }
        }
        Ok(())
    })?;

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> HashMap<String, RosterMember> {
        HashMap::new()
    }

    #[test]
    fn classify_k8s_service_account() {
        let (id, kind, member, alias) = classify(
            "cloudtrail",
            "system:serviceaccount:kube-system:aws-node",
            &empty(),
            &empty(),
        );
        assert_eq!(id, "system:serviceaccount:kube-system:aws-node");
        assert!(kind == Kind::Service);
        assert!(member.is_none());
        assert_eq!(alias, "k8s");
    }

    #[test]
    fn origins_kubernetes_supersedes_feed() {
        // k8s SA seen via CloudTrail → kubernetes only, not aws.
        assert_eq!(
            origins_for("cloudtrail", "system:serviceaccount:kube-system:aws-node", false),
            vec!["kubernetes"],
        );
    }

    #[test]
    fn origins_roster_person_via_cloudtrail() {
        assert_eq!(
            origins_for("cloudtrail", "alice@dfds.com", true),
            vec!["azure-ad", "aws"],
        );
    }

    #[test]
    fn origins_unresolved_cloudtrail_role_arn() {
        assert_eq!(
            origins_for("cloudtrail", "arn:aws:iam::123:role/Foo", false),
            vec!["aws"],
        );
    }

    #[test]
    fn origins_bare_selfservice_actor() {
        assert_eq!(origins_for("selfservice", "bob", false), vec!["selfservice"]);
    }

    #[test]
    fn origins_unknown_when_nothing_applies() {
        assert_eq!(origins_for("mystery", "x", false), vec!["unknown"]);
    }
}
