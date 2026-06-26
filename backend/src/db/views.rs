//! Hand-maintained Diesel `table!` definitions for DB **views** that
//! `diesel print-schema` cannot emit.
//!
//! `src/schema.rs` is auto-generated and, crucially, is **rewritten on every
//! `diesel migration run`/`redo`** by the `diesel.toml` `[print_schema]` hook.
//! `print-schema` omits views, so anything view-related appended to `schema.rs`
//! was silently dropped on the next migration run — a recurring footgun.
//!
//! Keeping view definitions HERE (a normal source file diesel never regenerates)
//! permanently decouples them from that regen cycle: `schema.rs` can be
//! regenerated freely and these blocks are never touched. When you add or change
//! a view, edit the `table!` here and the matching `CREATE ... VIEW` in the
//! migration — `schema.rs` is not involved.

diesel::table! {
    /// Source-agnostic union view over `audit_records_selfservice` /
    /// `cloudtrail_events` / `github_audit_events`. Backs Query / Timeline /
    /// Graph. `uid` is the per-source unique key. Read-only.
    ///
    /// Mirrors the `ssumgmt_events` view defined in the migration; keep the two
    /// in sync (column set + types).
    ssumgmt_events (uid) {
        source -> Text,
        uid -> Text,
        ts -> Timestamptz,
        actor -> Nullable<Text>,
        action -> Text,
        resource -> Nullable<Text>,
        source_ip -> Nullable<Text>,
        level -> Text,
        status -> Text,
        raw -> Nullable<Jsonb>,
        role -> Nullable<Text>,
        identity_source -> Nullable<Text>,
        account_id -> Nullable<Text>,
        caller_account_id -> Nullable<Text>,
    }
}
