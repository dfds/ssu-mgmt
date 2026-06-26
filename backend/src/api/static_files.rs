use axum::body::Body;
use axum::http::{header, HeaderValue, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "dist/"]
struct Asset;

pub fn router() -> axum::Router {
    axum::Router::new().fallback(serve)
}

async fn serve(req: Request<Body>) -> Response {
    let uri: &Uri = req.uri();
    let raw = uri.path().trim_start_matches('/');
    let path = if raw.is_empty() { "index.html" } else { raw };

    if let Some(asset) = Asset::get(path) {
        return build_response(path, asset.data.into_owned(), cache_for(path));
    }

    if !path.starts_with("assets/") {
        if let Some(asset) = Asset::get("index.html") {
            return build_response("index.html", asset.data.into_owned(), CacheKind::NoCache);
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

enum CacheKind {
    NoCache,
    Immutable,
}

fn cache_for(path: &str) -> CacheKind {
    if path.starts_with("assets/") {
        CacheKind::Immutable
    } else {
        CacheKind::NoCache
    }
}

fn build_response(path: &str, body: Vec<u8>, cache: CacheKind) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let cache_control = match cache {
        CacheKind::Immutable => "public, max-age=31536000, immutable",
        CacheKind::NoCache => "no-cache",
    };

    let mut resp = (StatusCode::OK, body).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref()).unwrap_or_else(|_| {
            HeaderValue::from_static("application/octet-stream")
        }),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache_control));
    resp
}
