// @generated automatically by Diesel CLI.

diesel::table! {
    actor_aliases (alias) {
        alias -> Text,
        actor_id -> Text,
        kind -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    actors (id) {
        id -> Text,
        email -> Nullable<Text>,
        display_name -> Nullable<Text>,
        team -> Nullable<Text>,
        kind -> Text,
        first_seen -> Nullable<Timestamptz>,
        last_active -> Nullable<Timestamptz>,
        sources -> Array<Nullable<Text>>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        origins -> Array<Nullable<Text>>,
    }
}

diesel::table! {
    alerts (id) {
        id -> Int8,
        fingerprint -> Text,
        rule_id -> Text,
        severity -> Text,
        title -> Text,
        description -> Nullable<Text>,
        actor_id -> Nullable<Text>,
        source -> Text,
        first_seen -> Timestamptz,
        last_seen -> Timestamptz,
        event_count -> Int8,
        status -> Text,
        evidence -> Jsonb,
        acked_by -> Nullable<Text>,
        acked_at -> Nullable<Timestamptz>,
        resolved_by -> Nullable<Text>,
        resolved_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    anomalies (id) {
        id -> Int8,
        fingerprint -> Text,
        kind -> Text,
        actor_id -> Nullable<Text>,
        severity -> Text,
        score -> Float8,
        baseline -> Nullable<Float8>,
        observed -> Nullable<Float8>,
        title -> Text,
        detail -> Nullable<Text>,
        evidence -> Jsonb,
        event_time -> Timestamptz,
        detected_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

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

diesel::table! {
    cloudtrail_events (event_id, event_time) {
        event_id -> Text,
        event_time -> Timestamptz,
        event_name -> Text,
        event_source -> Text,
        aws_region -> Nullable<Text>,
        recipient_account_id -> Nullable<Text>,
        principal_arn -> Nullable<Text>,
        principal_type -> Nullable<Text>,
        principal_name -> Nullable<Text>,
        source_ip -> Nullable<Text>,
        user_agent -> Nullable<Text>,
        error_code -> Nullable<Text>,
        read_only -> Nullable<Bool>,
        management_event -> Nullable<Bool>,
        s3_object_key -> Nullable<Text>,
        raw -> Jsonb,
        created_at -> Timestamptz,
        assumed_role_arn -> Nullable<Text>,
        identity_source -> Nullable<Text>,
        user_identity_account_id -> Nullable<Text>,
    }
}

diesel::table! {
    github_audit_events (id) {
        id -> Int8,
        document_id -> Text,
        event_time -> Timestamptz,
        action -> Text,
        actor -> Nullable<Text>,
        actor_id -> Nullable<Text>,
        org -> Nullable<Text>,
        repo -> Nullable<Text>,
        source_ip -> Nullable<Text>,
        user_agent -> Nullable<Text>,
        raw -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    grants (id) {
        id -> Int8,
        grant_key -> Text,
        actor_id -> Nullable<Text>,
        system -> Text,
        role -> Text,
        scope -> Nullable<Text>,
        severity -> Text,
        privileged -> Bool,
        granted_at -> Nullable<Timestamptz>,
        granted_by -> Nullable<Text>,
        source_event -> Nullable<Text>,
        revoked_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    ingest_watermarks (source) {
        source -> Text,
        last_object_key -> Nullable<Text>,
        last_event_at -> Nullable<Timestamptz>,
        last_cursor -> Nullable<Text>,
        objects_scanned -> Int8,
        events_applied -> Int8,
        last_run_at -> Nullable<Timestamptz>,
        last_run_error -> Nullable<Text>,
    }
}

diesel::table! {
    risk_scores (actor_id) {
        actor_id -> Text,
        score -> Int4,
        label -> Text,
        components -> Jsonb,
        computed_at -> Timestamptz,
    }
}

diesel::table! {
    sessions (id) {
        id -> Int8,
        session_key -> Text,
        actor_id -> Nullable<Text>,
        source -> Text,
        device -> Nullable<Text>,
        source_ip -> Nullable<Text>,
        location -> Nullable<Text>,
        started_at -> Timestamptz,
        last_seen_at -> Timestamptz,
        event_count -> Int8,
        status -> Text,
        flag_reason -> Nullable<Text>,
    }
}

diesel::joinable!(actor_aliases -> actors (actor_id));
diesel::joinable!(alerts -> actors (actor_id));
diesel::joinable!(anomalies -> actors (actor_id));
diesel::joinable!(grants -> actors (actor_id));
diesel::joinable!(risk_scores -> actors (actor_id));
diesel::joinable!(sessions -> actors (actor_id));

diesel::allow_tables_to_appear_in_same_query!(
    actor_aliases,
    actors,
    alerts,
    anomalies,
    audit_records_selfservice,
    cloudtrail_events,
    github_audit_events,
    grants,
    ingest_watermarks,
    risk_scores,
    sessions,
);
