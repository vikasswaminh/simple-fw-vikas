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
        .route("/fonts/:filename", get(serve_font))
        .route("/:filename", get(serve_static_file))
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

async fn serve_static_file(
    Path(filename): Path<String>,
) -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    // Only allow safe filenames — no path traversal
    if !filename
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    // Extension allowlist
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
    } else if filename.ends_with(".json") {
        "application/json"
    } else {
        return Err(axum::http::StatusCode::NOT_FOUND);
    };
    let path = format!("{}/{}", *STATIC_FILES_PATH, filename);
    match fs::read(&path).await {
        Ok(bytes) => Ok(axum::response::Response::builder()
            .header("Content-Type", content_type)
            .header("Cache-Control", "no-cache, must-revalidate")
            .body(axum::body::Body::from(bytes))
            .unwrap()),
        Err(_) => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn serve_font(
    Path(filename): Path<String>,
) -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    // Only allow known font filenames — no path traversal
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
            Ok(axum::response::Response::builder()
                .header("Content-Type", content_type)
                .header("Cache-Control", "public, max-age=31536000, immutable")
                .body(axum::body::Body::from(bytes))
                .unwrap())
        }
        Err(_) => Err(axum::http::StatusCode::NOT_FOUND),
    }
}
