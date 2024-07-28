use axum::http::StatusCode;

pub async fn get_stats() -> (StatusCode) {
    (StatusCode::OK)
}