use diesel::{Queryable, Insertable};
use diesel::prelude::*;
use serde::Serialize;
use crate::schema::*;

#[derive(Queryable, Selectable, Identifiable, AsChangeset, Insertable, QueryableByName, Clone)]
#[diesel(table_name = audit_records_selfservice)]
pub struct AuditRecordsSelfservice {
    pub id : i64,
    pub message_id : String,
    #[diesel(column_name = "type_")]
    pub record_type : String,
    pub principal : String,
    pub action : String,
    pub method : String,
    pub path : String,
    pub service : String,
    pub timestamp : chrono::naive::NaiveDateTime,
    pub created_at : chrono::naive::NaiveDateTime,
    pub request_data : Option<serde_json::Value>,
}

#[derive(Insertable, Clone)]
#[diesel(table_name = audit_records_selfservice)]
pub struct AuditRecordsSelfserviceInsert {
    pub message_id : String,
    pub created_at : chrono::naive::NaiveDateTime,
    pub timestamp : chrono::naive::NaiveDateTime,
    #[diesel(column_name = "type_")]
    pub record_type : String,
    pub principal : String,
    pub action : String,
    pub method : String,
    pub path : String,
    pub service : String,
    pub request_data : Option<serde_json::Value>,
}

/// Self-audit row for the service's own API usage (source `ssu-mgmt`). Written by
/// the `audit_usage` middleware via the bg batch writer; read back through the
/// 4th branch of the `ssumgmt_events` view. `message_id` is a per-request UUID
/// (UNIQUE), so `on_conflict_do_nothing` makes batched inserts idempotent.
#[derive(Insertable, Clone, Debug)]
#[diesel(table_name = ssumgmt_audit)]
pub struct SsuMgmtAuditInsert {
    pub message_id : String,
    pub ts : chrono::DateTime<chrono::Utc>,
    pub actor : Option<String>,
    pub action : String,
    pub method : Option<String>,
    pub path : Option<String>,
    pub status_code : Option<i32>,
    pub status : String,
    pub level : String,
    pub source_ip : Option<String>,
    pub role : Option<String>,
    pub request_data : Option<serde_json::Value>,
    pub created_at : chrono::DateTime<chrono::Utc>,
}

#[derive(Insertable, Clone)]
#[diesel(table_name = cloudtrail_events)]
pub struct CloudtrailEventInsert {
    pub event_id : String,
    pub event_time : chrono::DateTime<chrono::Utc>,
    pub event_name : String,
    pub event_source : String,
    pub aws_region : Option<String>,
    pub recipient_account_id : Option<String>,
    pub user_identity_account_id : Option<String>,
    pub principal_arn : Option<String>,
    pub principal_type : Option<String>,
    pub principal_name : Option<String>,
    pub assumed_role_arn : Option<String>,
    pub identity_source : Option<String>,
    pub source_ip : Option<String>,
    pub user_agent : Option<String>,
    pub error_code : Option<String>,
    pub read_only : Option<bool>,
    pub management_event : Option<bool>,
    pub s3_object_key : Option<String>,
    pub raw : serde_json::Value,
    pub created_at : chrono::DateTime<chrono::Utc>,
}

#[derive(Insertable, Clone)]
#[diesel(table_name = github_audit_events)]
pub struct GithubAuditEventInsert {
    pub document_id : String,
    pub event_time : chrono::DateTime<chrono::Utc>,
    pub action : String,
    pub actor : Option<String>,
    pub actor_id : Option<String>,
    pub org : Option<String>,
    pub repo : Option<String>,
    pub source_ip : Option<String>,
    pub user_agent : Option<String>,
    pub raw : serde_json::Value,
    pub created_at : chrono::DateTime<chrono::Utc>,
}

#[derive(Queryable, Selectable, QueryableByName, Serialize, Clone)]
#[diesel(table_name = ingest_watermarks)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct IngestWatermark {
    pub source : String,
    pub last_object_key : Option<String>,
    pub last_event_at : Option<chrono::DateTime<chrono::Utc>>,
    pub last_cursor : Option<String>,
    pub objects_scanned : i64,
    pub events_applied : i64,
    pub last_run_at : Option<chrono::DateTime<chrono::Utc>>,
    pub last_run_error : Option<String>,
}

#[derive(Queryable, Selectable, Serialize, Clone)]
#[diesel(table_name = ingest_watermarks)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct IngestHealth {
    pub source : String,
    pub last_object_key : Option<String>,
    pub last_event_at : Option<chrono::DateTime<chrono::Utc>>,
    pub objects_scanned : i64,
    pub events_applied : i64,
    pub last_run_at : Option<chrono::DateTime<chrono::Utc>>,
    pub last_run_error : Option<String>,
}

#[derive(Queryable, Selectable, QueryableByName, Serialize, Clone)]
#[diesel(table_name = crate::db::views::ssumgmt_events)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct SsuMgmtEvent {
    pub source : String,
    pub uid : String,
    pub ts : chrono::DateTime<chrono::Utc>,
    pub actor : Option<String>,
    pub action : String,
    pub resource : Option<String>,
    pub source_ip : Option<String>,
    pub level : String,
    pub status : String,
    pub raw : Option<serde_json::Value>,
    pub role : Option<String>,
    pub identity_source : Option<String>,
    pub account_id : Option<String>,
    pub caller_account_id : Option<String>,
}

#[derive(Queryable, Selectable, QueryableByName, Serialize, Clone)]
#[diesel(table_name = actors)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Actor {
    pub id : String,
    pub email : Option<String>,
    pub display_name : Option<String>,
    pub team : Option<String>,
    pub kind : String,
    pub first_seen : Option<chrono::DateTime<chrono::Utc>>,
    pub last_active : Option<chrono::DateTime<chrono::Utc>>,
    pub sources : Vec<Option<String>>,
    pub origins : Vec<Option<String>>,
    pub created_at : chrono::DateTime<chrono::Utc>,
    pub updated_at : chrono::DateTime<chrono::Utc>,
}

/// Stored risk score + per-factor breakdown (`components`).
#[derive(Queryable, Selectable, QueryableByName, Serialize, Clone)]
#[diesel(table_name = risk_scores)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct RiskScore {
    pub actor_id : String,
    pub score : i32,
    pub label : String,
    pub components : serde_json::Value,
    pub computed_at : chrono::DateTime<chrono::Utc>,
}

/// Alert / GuardDuty finding row (triage-lite lifecycle).
#[derive(Queryable, Selectable, QueryableByName, Serialize, Clone)]
#[diesel(table_name = alerts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Alert {
    pub id : i64,
    pub fingerprint : String,
    pub rule_id : String,
    pub severity : String,
    pub title : String,
    pub description : Option<String>,
    pub actor_id : Option<String>,
    pub source : String,
    pub first_seen : chrono::DateTime<chrono::Utc>,
    pub last_seen : chrono::DateTime<chrono::Utc>,
    pub event_count : i64,
    pub status : String,
    pub evidence : serde_json::Value,
    pub acked_by : Option<String>,
    pub acked_at : Option<chrono::DateTime<chrono::Utc>>,
    pub resolved_by : Option<String>,
    pub resolved_at : Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at : chrono::DateTime<chrono::Utc>,
}

/// Derived session row (AWS-only in v1; `location` via GeoLite2 when available).
#[derive(Queryable, Selectable, QueryableByName, Serialize, Clone)]
#[diesel(table_name = sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Session {
    pub id : i64,
    pub session_key : String,
    pub actor_id : Option<String>,
    pub source : String,
    pub device : Option<String>,
    pub source_ip : Option<String>,
    pub location : Option<String>,
    pub started_at : chrono::DateTime<chrono::Utc>,
    pub last_seen_at : chrono::DateTime<chrono::Utc>,
    pub event_count : i64,
    pub status : String,
    pub flag_reason : Option<String>,
}

#[derive(Queryable, Selectable, QueryableByName, Serialize, Clone)]
#[diesel(table_name = anomalies)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Anomaly {
    pub id : i64,
    pub fingerprint : String,
    pub kind : String,
    pub actor_id : Option<String>,
    pub severity : String,
    pub score : f64,
    pub baseline : Option<f64>,
    pub observed : Option<f64>,
    pub title : String,
    pub detail : Option<String>,
    pub evidence : serde_json::Value,
    pub event_time : chrono::DateTime<chrono::Utc>,
    pub detected_at : chrono::DateTime<chrono::Utc>,
    pub updated_at : chrono::DateTime<chrono::Utc>,
}

/// Derived privileged-access grant row.
#[derive(Queryable, Selectable, QueryableByName, Serialize, Clone)]
#[diesel(table_name = grants)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Grant {
    pub id : i64,
    pub grant_key : String,
    pub actor_id : Option<String>,
    pub system : String,
    pub role : String,
    pub scope : Option<String>,
    pub severity : String,
    pub privileged : bool,
    pub granted_at : Option<chrono::DateTime<chrono::Utc>>,
    pub granted_by : Option<String>,
    pub source_event : Option<String>,
    pub revoked_at : Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at : chrono::DateTime<chrono::Utc>,
}
