// @generated automatically by Diesel CLI.

diesel::table! {
    audit_records_selfservice (id) {
        id -> Int8,
        message_id -> Text,
        #[sql_name = "type"]
        type_ -> Text,
        principal -> Text,
        action -> Text,
        method -> Text,
        path -> Text,
        service -> Text,
        timestamp -> Timestamp,
        created_at -> Timestamp,
        request_data -> Nullable<Jsonb>,
    }
}
