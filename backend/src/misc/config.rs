use crate::messaging::config::MessagingConfig;
use crate::misc::error::SsuResult;
use config::builder::DefaultState;
use config::ConfigBuilder;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Config {
    pub log_level: String,
    pub api_port: u16,
    pub api_listen_address: String,
    pub metrics_port: u16,
    pub metrics_listen_address: String,
    pub health_port: u16,
    pub health_listen_address: String,
    pub api_enable_auth: bool,
    pub enable_api: bool,
    pub enable_messaging_ingest: bool,
    pub enable_cloudtrail_ingest: bool,
    pub enable_github_ingest: bool,
    pub enable_github_s3_ingest: bool,
    pub enable_siem_derivation: bool,
    pub enable_guardduty: bool,
    pub enable_retention: bool,
    pub auth: Auth,
    pub auth_jwks_url: Option<String>,
    pub cache_implementation: String,
    pub messaging: MessagingConfig,
    pub cloudtrail: CloudtrailConfig,
    pub github: GithubConfig,
    pub github_s3: GithubS3Config,
    pub siem: SiemConfig,
    pub selfservice: SelfserviceConfig,
    pub risk: RiskConfig,
    pub geoip: GeoipConfig,
    pub guardduty: GuarddutyConfig,
    pub worker: WorkerConfig,
    pub runtime: RuntimeConfig,
    pub timeline: TimelineConfig,
    pub retention: RetentionConfig,
    pub audit: AuditConfig,
    pub tracing: TracingConfig,
    pub profiling: ProfilingConfig,
    pub db: crate::db::Config,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TimelineConfig {
    pub rollup_interval_secs: u64,
}

impl Default for TimelineConfig {
    fn default() -> Self {
        Self {
            rollup_interval_secs: 300,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TracingConfig {
    pub enable: bool,
    pub otlp_endpoint: String,
    pub protocol: String,
    pub sample_ratio: f64,
    pub service_name: String,
    /// Optional auth headers for the OTLP exporter, as a comma-separated
    /// `key=value` list (OTel-spec convention), e.g.
    /// `authorization=Bearer abc,x-scope-orgid=tenant1`. Empty = none. Parsed in
    /// `main` and passed through to `OtlpOptions.headers`; values may be secrets,
    /// so only header **names** are ever logged.
    pub otlp_headers: String,
    /// Optional OTel **resource** namespace, mapped to the `service.namespace`
    /// resource attribute (namespaced tracing). Empty = unset.
    pub namespace: String,
    /// Optional deployment environment, mapped to the `deployment.environment`
    /// resource attribute (e.g. `prod`, `staging`, `dev`). Empty = unset.
    pub environment: String,
    /// Arbitrary extra resource attributes as a comma-separated `key=value` list
    /// (e.g. `team=cloud-engineering,region=eu-west-1`), parsed like `otlp_headers`
    /// and stamped on every exported span. Not secrets — logged in full. The
    /// standard `OTEL_RESOURCE_ATTRIBUTES` env var is also honoured (these win on a
    /// key collision). Empty = none.
    pub resource_attributes: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enable: false,
            otlp_endpoint: "http://localhost:4317".to_owned(),
            protocol: "grpc".to_owned(),
            sample_ratio: 1.0,
            service_name: "ssu-mgmt".to_owned(),
            otlp_headers: "".to_owned(),
            namespace: "".to_owned(),
            environment: "".to_owned(),
            resource_attributes: "".to_owned(),
        }
    }
}

/// On-demand pprof profiler knobs (`SSU__PROFILING__*`). The endpoint lives on the
/// **internal** health server (`health_port`, default 9001) — not the public API —
/// and is enabled by default since it costs nothing until hit. A request samples
/// the whole process for `seconds` (clamped to `max_seconds`) at `default_hz`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfilingConfig {
    pub enable: bool,
    pub default_seconds: u64,
    pub default_hz: i32,
    pub max_seconds: u64,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            enable: true,
            default_seconds: 30,
            default_hz: 100,
            max_seconds: 120,
        }
    }
}

/// Leader-election knobs (`SSU__WORKER__*`) for the singleton background workers
/// (CloudTrail/GitHub/GitHub-S3 ingest, SIEM derivation, GuardDuty). With 3 HA
/// replicas these must run on exactly one at a time; a `leader_leases` row is the
/// election primitive (see `service::leader`). `leader_election=false` bypasses
/// the lease and spawns the workers directly — single-instance / local-dev mode.
///
/// `lease_ttl_secs` should be ~3× `lease_renew_secs` so a missed heartbeat or two
/// doesn't trigger a spurious takeover; it also bounds the hard-crash failover
/// window (a standby steals the lease once `expires_at < now()`).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WorkerConfig {
    pub leader_election: bool,
    pub lease_ttl_secs: u64,
    pub lease_renew_secs: u64,
    pub lease_retry_secs: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            leader_election: true,
            lease_ttl_secs: 30,
            lease_renew_secs: 10,
            lease_retry_secs: 10,
        }
    }
}

/// Tokio runtime sizing knobs (`SSU__RUNTIME__*`). Each of the three runtimes (API
/// server, health server, background worker) caps its `worker_threads` and bounds its
/// `spawn_blocking` pool. The `*_worker_threads` value is a **cap** — the actual count is
/// `min(cap, host parallelism)` (see `misc::runtime::worker_threads`), so a small node
/// still uses fewer. The defaults are sized for a ~3-core CPU limit; raise them if the
/// pod's `limits.cpu` is increased.
///
/// Why this exists: `new_multi_thread()` otherwise defaults `worker_threads` to the
/// *host* core count (CPU affinity, not the cgroup CPU limit) and the blocking pool to
/// 512, so on a large node the runtimes over-subscribe threads — CFS throttling plus a
/// pile of 2 MB stacks and per-thread allocator arenas (a contributor to the prod OOM).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuntimeConfig {
    pub api_worker_threads: usize,
    pub api_max_blocking_threads: usize,
    pub worker_worker_threads: usize,
    pub worker_max_blocking_threads: usize,
    pub health_worker_threads: usize,
    pub health_max_blocking_threads: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            api_worker_threads: 4,
            api_max_blocking_threads: 16,
            worker_worker_threads: 4,
            worker_max_blocking_threads: 32,
            health_worker_threads: 2,
            health_max_blocking_threads: 4,
        }
    }
}

/// Retention prune knobs (`SSU__RETENTION__*`). The worker (a leader singleton)
/// runs every `interval_secs` and deletes rows older than a per-source window from
/// the source tables (`cloudtrail_events`/`github_audit_events`/
/// `audit_records_selfservice`) and the derived tables (`sessions`/`anomalies` and
/// resolved `alerts`). Each table is pruned in `batch_size` chunks ordered by its
/// time index. A `*_days <= 0` keeps that table forever (retention disabled for it).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RetentionConfig {
    /// Sweep cadence (default daily). Clamped to ≥60s.
    pub interval_secs: u64,
    /// Keep CloudTrail events for this many days. `<= 0` → keep forever.
    pub cloudtrail_days: i64,
    /// Keep GitHub audit events for this many days. `<= 0` → keep forever.
    pub github_days: i64,
    /// Keep self-service audit records for this many days. `<= 0` → keep forever.
    pub selfservice_days: i64,
    /// Keep derived `sessions`/`anomalies` + **resolved** `alerts` for this many
    /// days (open/acked alerts are never pruned). `<= 0` → keep forever.
    pub derived_days: i64,
    /// Keep the service's own self-audit rows (`ssumgmt_audit`) for this many days.
    /// `<= 0` → keep forever.
    pub ssumgmt_days: i64,
    /// Rows deleted per chunk. Small + index-driven so each chunk is quick and
    /// cancellation is observed promptly between chunks (shutdown-wedge guard).
    pub batch_size: i64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            interval_secs: 86_400,
            cloudtrail_days: 90,
            github_days: 365,
            selfservice_days: 365,
            derived_days: 90,
            ssumgmt_days: 365,
            batch_size: 5_000,
        }
    }
}

/// Self-audit knobs (`SSU__AUDIT__*`). The `audit_usage` middleware records every
/// intentful authenticated API call as a `ssu-mgmt`-source audit event. High-volume
/// polling endpoints are excluded by matched-path prefix so the audit table (and the
/// SIEM actor model) aren't flooded with low-intent rows.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditConfig {
    /// Master switch for self-audit. When false, no API-usage rows are written.
    pub enabled: bool,
    /// Comma-separated matched-path template **prefixes** to exclude from self-audit
    /// (matched against the full `/api/...` template). Defaults exclude the dashboard
    /// polling endpoints plus the auth-config and progress-WS bypasses.
    pub exclude_prefixes: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            exclude_prefixes: "/api/overview/,/api/auth/config,/api/progress/".to_owned(),
        }
    }
}

/// SIEM derivation batch loop knobs (`SSU__SIEM__*`). The loop runs every
/// `interval_secs` and recomputes actors → grants → sessions → risk → alerts.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SiemConfig {
    /// Batch cadence (target ~5–15 min freshness).
    pub interval_secs: u64,
    /// Trailing window (days) the derivation passes consider.
    pub window_days: i64,
    /// Idle gap (minutes) that closes a derived session.
    pub session_gap_mins: i64,
    /// A principal silent for at least this many days is "dormant"; activity
    /// after that trips `dormant_principal_active`.
    pub dormant_days: i64,
    /// Off-hours window (UTC hours, `[start, end)`), used for off-hours scoring
    /// and the `off_hours_key_creation` rule. Default 20:00–06:00 UTC.
    pub off_hours_start: u32,
    pub off_hours_end: u32,
    /// Failed-ConsoleLogin count within `bruteforce_window_mins` that trips
    /// `console_login_bruteforce`.
    pub bruteforce_threshold: i64,
    pub bruteforce_window_mins: i64,
    /// Anomaly detection (statistical, threshold-only — no ML).
    /// Z-score above which today's per-actor volume is a `volume_spike`.
    pub anomaly_z_threshold: f64,
    /// Minimum prior-day samples before a volume z-score is trusted.
    pub anomaly_min_history_days: i64,
    /// Minimum off-hours event count in 24h before `off_hours_spike` can fire.
    pub off_hours_spike_min: i64,
    /// Speed (km/h) between two consecutive logins above which travel is deemed
    /// physically impossible (faster than a commercial flight + airport overhead).
    pub impossible_travel_kmh: f64,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            interval_secs: 300,
            window_days: 7,
            session_gap_mins: 60,
            dormant_days: 30,
            off_hours_start: 20,
            off_hours_end: 6,
            bruteforce_threshold: 5,
            bruteforce_window_mins: 15,
            anomaly_z_threshold: 3.0,
            anomaly_min_history_days: 3,
            off_hours_spike_min: 5,
            impossible_travel_kmh: 900.0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SelfserviceConfig {
    pub base_url: String,
    /// Optional static bearer override (local/testing). Empty → use client creds.
    pub token: String,
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_scope: String,
}

/// Risk-model weights (`SSU__RISK__W_*`). Each factor is
/// saturating so no single signal dominates; `score = clamp(0..100, Σ w·f(x))`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RiskConfig {
    pub w_failed_auth: f64,
    pub w_priv_grants: f64,
    pub w_off_hours: f64,
    pub w_dormant: f64,
    pub w_flagged_sessions: f64,
    pub w_source_diversity: f64,
    pub w_anomalies: f64,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            w_failed_auth: 25.0,
            w_priv_grants: 20.0,
            w_off_hours: 15.0,
            w_dormant: 20.0,
            w_flagged_sessions: 25.0,
            w_source_diversity: 10.0,
            w_anomalies: 20.0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct GeoipConfig {
    pub license_key: String,
    pub db_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GuarddutyConfig {
    pub regions: String,
    pub interval_secs: u64,
    /// Role ARN in the findings account to assume before listing detectors/
    /// findings. Empty → default credential chain (no cross-account hop).
    pub assume_role_arn: String,
    /// STS session name used when `assume_role_arn` is set.
    pub assume_role_session_name: String,
    /// First-run lookback bound, in days. When no watermark exists yet (fresh DB),
    /// the sweep would otherwise fetch *every* finding the detector has ever held —
    /// on an org delegated-admin/aggregator detector that is the whole org's history
    /// (hundreds of thousands of findings), which OOMs the pod. This caps the cold
    /// start to `updatedAt >= now() - backfill_window_days`. Once a watermark is set,
    /// subsequent sweeps use it instead. `<= 0` → unbounded (the old behaviour).
    pub backfill_window_days: i64,
}

impl Default for GuarddutyConfig {
    fn default() -> Self {
        Self {
            regions: "eu-west-1".to_owned(),
            interval_secs: 900,
            assume_role_arn: String::new(),
            assume_role_session_name: "ssu-mgmt-guardduty".to_owned(),
            backfill_window_days: 30,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct CloudtrailConfig {
    /// S3 bucket holding the org trail, e.g. `dfds-audit`.
    pub bucket: String,
    /// Base key prefix above the `<account>/CloudTrail/<region>/...` layout,
    /// e.g. `AWSLogs/o-csdabyhi6f`.
    pub prefix: String,
    /// Region for the S3 client (the bucket's region).
    pub region: String,
    /// Trailing look-back window in days. Older data stays in Athena.
    pub window_days: i64,
    /// Comma-separated `eventName` allowlist. Empty → the built-in SIEM set
    /// (see `cloudtrail::default_allowlist`).
    pub event_allowlist: String,
    /// Drop non-management events (`eventCategory != "Management"`) before insert.
    pub management_events_only: bool,
    /// Poll cadence; CloudTrail's S3 delivery floor is ~5–15 min.
    pub poll_interval_secs: u64,
    /// Concurrent object download+decode workers per sweep.
    pub workers: usize,
    /// Peak decode working-set budget in MB, across all concurrent decodes
    pub max_decode_mb: usize,
    /// Objects folded into one commit transaction.
    pub batch_size: usize,
    /// Records buffered in memory before flushing a sub-batch to Postgres
    /// **within a single object's decode**. This — not `batch_size` (objects) — is
    /// what bounds decode memory: a single CloudTrail object can hold ~1M records,
    /// and accumulating all of their `serde_json::Value` `raw` trees before
    /// committing was a heap-dump-confirmed multi-GB OOM. `decode_and_map` now
    /// streams the `Records` array and flushes every `flush_records` kept rows
    /// (idempotent `on_conflict_do_nothing`), so peak ≈ `flush_records` rows ×
    /// concurrent decodes. Larger → fewer commits/WAL fsyncs but more memory;
    /// smaller → the opposite. Tune against `/debug/mem`. `0` → fall back to a safe
    /// internal default.
    pub flush_records: usize,
    /// Backfill throttle: max objects downloaded per sweep (0 → unbounded).
    pub max_objects_per_run: i64,
    /// Per-account fairness cap: max objects a single account may consume in one
    /// sweep, so one high-volume account can't monopolise the global
    /// `max_objects_per_run` budget and starve the other accounts. `0` → derive
    /// from the global budget (`max_objects_per_run / 8`) when that is set, else
    /// unbounded. Paired with a persisted rotating account cursor so the budget
    /// walks across all accounts instead of always restarting at the first one.
    pub max_objects_per_account: i64,
    /// Role ARN to assume if the trail bucket lives in another account. Empty →
    /// default credential chain (same-account). Used for the cross-account hop:
    /// the pod's role assumes this role in the bucket's account before reading.
    pub assume_role_arn: String,
    /// STS session name when assuming `assume_role_arn`.
    pub assume_role_session_name: String,
    /// Minimum seconds between web-identity role-chain resolution passes. The pass
    /// scans the whole window twice over unindexable `raw #>>` extractions, so
    /// running it after every sweep nearly doubles cycle time during a continuous
    /// backfill. Throttled on elapsed wall-clock instead — independent of sweep
    /// cadence/backlog. `0` → run after every sweep (legacy behaviour).
    pub webidentity_resolve_interval_secs: u64,
}

/// GitHub Enterprise audit-log ingester config (`SSU__GITHUB__*`). The audit-log
/// REST endpoint needs a classic PAT with `read:audit_log`; the App fields are
/// declared for a later member-enumeration / actor reconciliation pass and
/// are unused today.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct GithubConfig {
    pub enterprise: String,
    pub audit_pat: String,
    /// API base, default `https://api.github.com`.
    pub api_base_url: String,
    pub poll_interval_secs: u64,
    pub backfill_window_days: i64,
    // App auth (member enumeration → actors). Declared, unused here.
    pub app_id: String,
    pub private_key_pem: String,
    pub private_key_path: String,
}

/// GitHub audit-log **S3 export** backfill config (`SSU__GITHUB_S3__*`). GitHub's
/// audit-log streaming writes gzipped NDJSON objects under a globally date-sortable
/// key layout (`<prefix>/YYYY/MM/DD/<file>.json.gz`), so a single lexical cursor
/// resumes correctly. Unbounded retention — complements the bounded REST ingester;
/// both write `github_audit_events`, deduped on `document_id`.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct GithubS3Config {
    /// S3 bucket holding the audit-log export.
    pub bucket: String,
    /// Base key prefix above the `YYYY/MM/DD/...` layout (may be empty).
    pub prefix: String,
    /// Region of the S3 client (the bucket's region).
    pub region: String,
    /// Poll cadence.
    pub poll_interval_secs: u64,
    /// Concurrent object download+decode workers per sweep.
    pub workers: usize,
    /// Backfill throttle: max objects downloaded per sweep (0 → unbounded).
    pub max_objects_per_run: i64,
    /// Role ARN to assume if the export bucket lives in another account. Empty →
    /// default credential chain.
    pub assume_role_arn: String,
    /// STS session name used when `assume_role_arn` is set.
    pub assume_role_session_name: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Auth {
    pub issuer: String,
    pub aud: String,
    pub oidc_url: String,
    pub tenant_id: String,
    pub client_id: String,
    pub api_scope: String,
}

pub fn get_conf_path() -> String {
    std::env::var("SSU__DATA_DIR").unwrap_or_else(|_| "./".to_owned())
}

pub fn load_conf() -> SsuResult<Config> {
    let mut settings = config::Config::builder()
        .add_source(config::Environment::with_prefix("SSU").separator("__"))
        .add_source(
            config::File::with_name(format!("{}/{}", get_conf_path(), "config.yaml").as_str())
                .required(false),
        );
    settings = set_defaults(settings);
    let settings_built = settings.build().unwrap();

    let config: Config = settings_built.try_deserialize()?;

    Ok(config)
}

fn set_defaults(builder: ConfigBuilder<DefaultState>) -> ConfigBuilder<DefaultState> {
    let builder = builder
        .set_default("auth.issuer", "")
        .unwrap()
        .set_default("auth.aud", "")
        .unwrap()
        .set_default("auth.oidc_url", "")
        .unwrap()
        .set_default("auth.tenant_id", "")
        .unwrap()
        .set_default("auth.client_id", "")
        .unwrap()
        .set_default("auth.api_scope", "")
        .unwrap()
        .set_default("api_port", 8080)
        .unwrap()
        .set_default("api_listen_address", "0.0.0.0")
        .unwrap()
        .set_default("metrics_port", 9000)
        .unwrap()
        .set_default("metrics_listen_address", "0.0.0.0")
        .unwrap()
        .set_default("health_port", 9001)
        .unwrap()
        .set_default("health_listen_address", "0.0.0.0")
        .unwrap()
        .set_default("log_level", "info")
        .unwrap()
        .set_default("api_enable_auth", "true")
        .unwrap()
        .set_default("enable_api", "true")
        .unwrap()
        .set_default("enable_messaging_ingest", "true")
        .unwrap()
        .set_default("enable_cloudtrail_ingest", "false")
        .unwrap()
        .set_default("enable_github_ingest", "false")
        .unwrap()
        .set_default("cache_implementation", "inmemory")
        .unwrap()
        .set_default("messaging.group_id", "ssu-mgmt")
        .unwrap()
        .set_default("messaging.bootstrap_servers", "")
        .unwrap()
        .set_default("messaging.sasl_mechanism", "GSSAPI")
        .unwrap()
        .set_default("messaging.security_protocol", "PLAINTEXT")
        .unwrap()
        .set_default("messaging.credentials.username", "")
        .unwrap()
        .set_default("messaging.credentials.password", "")
        .unwrap()
        // CloudTrail ingester defaults (bounded + allowlisted).
        .set_default("cloudtrail.bucket", "")
        .unwrap()
        .set_default("cloudtrail.prefix", "")
        .unwrap()
        .set_default("cloudtrail.region", "eu-west-1")
        .unwrap()
        .set_default("cloudtrail.window_days", 30)
        .unwrap()
        .set_default("cloudtrail.event_allowlist", "")
        .unwrap()
        .set_default("cloudtrail.management_events_only", "true")
        .unwrap()
        .set_default("cloudtrail.poll_interval_secs", 300)
        .unwrap()
        .set_default("cloudtrail.workers", 12)
        .unwrap()
        .set_default("cloudtrail.max_decode_mb", 1500)
        .unwrap()
        .set_default("cloudtrail.batch_size", 100)
        .unwrap()
        .set_default("cloudtrail.flush_records", 10_000)
        .unwrap()
        .set_default("cloudtrail.max_objects_per_run", 0)
        .unwrap()
        .set_default("cloudtrail.max_objects_per_account", 0)
        .unwrap()
        .set_default("cloudtrail.assume_role_arn", "")
        .unwrap()
        .set_default("cloudtrail.assume_role_session_name", "ssu-mgmt-cloudtrail")
        .unwrap()
        .set_default("cloudtrail.webidentity_resolve_interval_secs", 300)
        .unwrap()
        // GitHub audit-log ingester defaults.
        .set_default("github.enterprise", "")
        .unwrap()
        .set_default("github.audit_pat", "")
        .unwrap()
        .set_default("github.api_base_url", "https://api.github.com")
        .unwrap()
        .set_default("github.poll_interval_secs", 300)
        .unwrap()
        .set_default("github.backfill_window_days", 7)
        .unwrap()
        .set_default("github.app_id", "")
        .unwrap()
        .set_default("github.private_key_pem", "")
        .unwrap()
        .set_default("github.private_key_path", "")
        .unwrap()
        // GitHub audit-log S3 export backfill defaults.
        .set_default("enable_github_s3_ingest", "false")
        .unwrap()
        .set_default("github_s3.bucket", "")
        .unwrap()
        .set_default("github_s3.prefix", "")
        .unwrap()
        .set_default("github_s3.region", "eu-west-1")
        .unwrap()
        .set_default("github_s3.poll_interval_secs", 300)
        .unwrap()
        .set_default("github_s3.workers", 12)
        .unwrap()
        .set_default("github_s3.max_objects_per_run", 0)
        .unwrap()
        .set_default("github_s3.assume_role_arn", "")
        .unwrap()
        .set_default("github_s3.assume_role_session_name", "ssu-mgmt-github-s3")
        .unwrap()
        .set_default("enable_siem_derivation", "false")
        .unwrap()
        .set_default("enable_guardduty", "false")
        .unwrap()
        .set_default("siem.interval_secs", 300)
        .unwrap()
        .set_default("siem.window_days", 7)
        .unwrap()
        .set_default("siem.session_gap_mins", 60)
        .unwrap()
        .set_default("siem.dormant_days", 30)
        .unwrap()
        .set_default("siem.off_hours_start", 20)
        .unwrap()
        .set_default("siem.off_hours_end", 6)
        .unwrap()
        .set_default("siem.bruteforce_threshold", 5)
        .unwrap()
        .set_default("siem.bruteforce_window_mins", 15)
        .unwrap()
        .set_default("siem.anomaly_z_threshold", 3.0)
        .unwrap()
        .set_default("siem.anomaly_min_history_days", 3)
        .unwrap()
        .set_default("siem.off_hours_spike_min", 5)
        .unwrap()
        .set_default("siem.impossible_travel_kmh", 900.0)
        .unwrap()
        .set_default("selfservice.base_url", "")
        .unwrap()
        .set_default("selfservice.token", "")
        .unwrap()
        .set_default("risk.w_failed_auth", 25.0)
        .unwrap()
        .set_default("risk.w_priv_grants", 20.0)
        .unwrap()
        .set_default("risk.w_off_hours", 15.0)
        .unwrap()
        .set_default("risk.w_dormant", 20.0)
        .unwrap()
        .set_default("risk.w_flagged_sessions", 25.0)
        .unwrap()
        .set_default("risk.w_source_diversity", 10.0)
        .unwrap()
        .set_default("risk.w_anomalies", 20.0)
        .unwrap()
        .set_default("geoip.license_key", "")
        .unwrap()
        .set_default("geoip.db_path", "")
        .unwrap()
        .set_default("guardduty.regions", "eu-west-1")
        .unwrap()
        .set_default("guardduty.interval_secs", 900)
        .unwrap()
        .set_default("guardduty.assume_role_arn", "")
        .unwrap()
        .set_default("guardduty.assume_role_session_name", "ssu-mgmt-guardduty")
        .unwrap()
        .set_default("guardduty.backfill_window_days", 30)
        .unwrap()
        // Leader election for the singleton background workers.
        .set_default("worker.leader_election", "true")
        .unwrap()
        .set_default("worker.lease_ttl_secs", 30)
        .unwrap()
        .set_default("worker.lease_renew_secs", 10)
        .unwrap()
        .set_default("worker.lease_retry_secs", 10)
        .unwrap()
        // Tokio runtime sizing (caps; clamped to host parallelism at build time).
        .set_default("runtime.api_worker_threads", 4)
        .unwrap()
        .set_default("runtime.api_max_blocking_threads", 16)
        .unwrap()
        .set_default("runtime.worker_worker_threads", 4)
        .unwrap()
        .set_default("runtime.worker_max_blocking_threads", 32)
        .unwrap()
        .set_default("runtime.health_worker_threads", 2)
        .unwrap()
        .set_default("runtime.health_max_blocking_threads", 4)
        .unwrap()
        .set_default("timeline.rollup_interval_secs", 300)
        .unwrap()
        // Retention prune worker — off by default (destructive deletes).
        .set_default("enable_retention", "false")
        .unwrap()
        .set_default("retention.interval_secs", 86_400)
        .unwrap()
        .set_default("retention.cloudtrail_days", 90)
        .unwrap()
        .set_default("retention.github_days", 365)
        .unwrap()
        .set_default("retention.selfservice_days", 365)
        .unwrap()
        .set_default("retention.derived_days", 90)
        .unwrap()
        .set_default("retention.ssumgmt_days", 365)
        .unwrap()
        .set_default("retention.batch_size", 5_000)
        .unwrap()
        // Self-audit: record the service's own API usage as source `ssu-mgmt`.
        .set_default("audit.enabled", "true")
        .unwrap()
        .set_default(
            "audit.exclude_prefixes",
            "/api/overview/,/api/auth/config,/api/progress/",
        )
        .unwrap()
        .set_default("tracing.enable", "false")
        .unwrap()
        .set_default("tracing.otlp_endpoint", "http://localhost:4317")
        .unwrap()
        .set_default("tracing.protocol", "grpc")
        .unwrap()
        .set_default("tracing.sample_ratio", 1.0)
        .unwrap()
        .set_default("tracing.service_name", "ssu-mgmt")
        .unwrap()
        .set_default("tracing.otlp_headers", "")
        .unwrap()
        .set_default("tracing.namespace", "ssu")
        .unwrap()
        .set_default("tracing.environment", "")
        .unwrap()
        .set_default("tracing.resource_attributes", "")
        .unwrap()
        .set_default("profiling.enable", "false")
        .unwrap()
        .set_default("profiling.default_seconds", 30)
        .unwrap()
        .set_default("profiling.default_hz", 100)
        .unwrap()
        .set_default("profiling.max_seconds", 120)
        .unwrap();
    builder
}
