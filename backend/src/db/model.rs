use diesel::{Queryable, Insertable};
use diesel::prelude::*;
use serde::{Deserialize, Serialize, Serializer};
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
