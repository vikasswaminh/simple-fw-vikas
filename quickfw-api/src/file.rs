use axum::{extract::Path, routing::get, Router};
use lazy_static::lazy_static;
use std::env;
use tokio::fs;

lazy_static! {
    static ref STATIC_FILES_PATH: String =
        env::var("STATIC_FILES_PATH").unwrap_or_else(|_| "./front".to_string());
}

pub async fn create_router() -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/login.html", get(serve_login))
        .route("/favicon.ico", get(serve_favicon))
        .route("/fonts/:filename", get(serve_font))
        .route("/assets/:filename", get(serve_asset))
        // NB: no catch-all /:filename route — we previously had one that
        // returned 404 for any path without a known extension, which broke
        // SPA deep links like /firewall or /network. The fallback below
        // serves index.html so the client-side router can take over.
        .fallback(serve_index)
}

async fn serve_favicon() -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    let path = format!("{}/favicon.ico", *STATIC_FILES_PATH);
    match fs::read(&path).await {
        Ok(bytes) => axum::response::Response::builder()
            .header("Content-Type", "image/x-icon")
            .header("Cache-Control", "public, max-age=86400")
            .body(axum::body::Body::from(bytes))
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        // No favicon shipped? Return 204 so the browser stops asking.
        Err(_) => Ok(axum::response::Response::builder()
            .status(axum::http::StatusCode::NO_CONTENT)
            .body(axum::body::Body::empty())
            .unwrap_or_default()),
    }
}

async fn serve_asset(
    Path(filename): Path<String>,
) -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    // Reuse the single-segment static handler for /assets/<filename> — the
    // allow-list, extension guard, and path-traversal checks are identical.
    // Vite emits hashed bundles under /assets/ so this route has to exist
    // separately from the top-level one (axum won't match nested paths to
    // a single-segment route).
    serve_asset_file(&filename).await
}

async fn serve_asset_file(
    filename: &str,
) -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    if filename.contains("..") || filename.starts_with('.') {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    if !filename
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    let content_type = if filename.ends_with(".css") {
        "text/css"
    } else if filename.ends_with(".js") {
        "application/javascript"
    } else if filename.ends_with(".html") {
        "text/html"
    } else if filename.ends_with(".svg") {
        "image/svg+xml"
    } else if filename.ends_with(".ico") {
        "image/x-icon"
    } else if filename.ends_with(".woff2") {
        "font/woff2"
    } else if filename.ends_with(".woff") {
        "font/woff"
    } else if filename.ends_with(".ttf") {
        "font/ttf"
    } else if filename.ends_with(".json") {
        "application/json"
    } else if filename.ends_with(".map") {
        "application/json"
    } else {
        return Err(axum::http::StatusCode::NOT_FOUND);
    };
    let path = format!("{}/assets/{}", *STATIC_FILES_PATH, filename);
    match fs::read(&path).await {
        Ok(bytes) => axum::response::Response::builder()
            .header("Content-Type", content_type)
            // Vite emits content-hashed filenames, so we can cache forever.
            .header("Cache-Control", "public, max-age=31536000, immutable")
            .body(axum::body::Body::from(bytes))
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        Err(_) => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn serve_index() -> axum::response::Html<String> {
    let index_path = format!("{}/index.html", *STATIC_FILES_PATH);
    let index_content = fs::read_to_string(index_path)
        .await
        .unwrap_or_else(|_| "Error loading index.html".to_string());
    axum::response::Html(index_content)
}

async fn serve_login() -> axum::response::Html<String> {
    let path = format!("{}/login.html", *STATIC_FILES_PATH);
    let content = fs::read_to_string(path)
        .await
        .unwrap_or_else(|_| "Error loading login.html".to_string());
    axum::response::Html(content)
}

async fn serve_font(
    Path(filename): Path<String>,
) -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    // Only allow known font filenames — no path traversal
    if filename.contains("..") || filename.starts_with('.') {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    if !filename
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    let path = format!("{}/fonts/{}", *STATIC_FILES_PATH, filename);
    match fs::read(&path).await {
        Ok(bytes) => {
            let content_type = if filename.ends_with(".woff2") {
                "font/woff2"
            } else if filename.ends_with(".woff") {
                "font/woff"
            } else if filename.ends_with(".ttf") {
                "font/ttf"
            } else {
                "application/octet-stream"
            };
            axum::response::Response::builder()
                .header("Content-Type", content_type)
                .header("Cache-Control", "public, max-age=31536000, immutable")
                .body(axum::body::Body::from(bytes))
                .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(_) => Err(axum::http::StatusCode::NOT_FOUND),
    }
}
