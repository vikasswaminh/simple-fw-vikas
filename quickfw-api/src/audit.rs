//! Audit logging for API write operations.
//!
//! Records POST/PUT/DELETE requests with user identity, source IP, and response status.
//! Stores last 200 entries in memory and appends to /var/log/quickfw/audit.log.

use axum::{
    extract::Request,
    http::Method,
    middleware::Next,
    response::Response,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Mutex;

use crate::auth::AuthUser;

const MAX_AUDIT_ENTRIES: usize = 200;
const AUDIT_LOG_PATH: &str = "/var/log/quickfw/audit.log";

#[derive(Serialize, Clone)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub method: String,
    pub endpoint: String,
    pub user: String,
    pub source_ip: String,
    pub status: u16,
}

lazy_static::lazy_static! {
    static ref AUDIT_LOG: Mutex<VecDeque<AuditEntry>> = Mutex::new(VecDeque::new());
}

pub fn create_router() -> Router {
    Router::new().route("/api/audit", get(get_audit_log))
}

async fn get_audit_log() -> Json<Vec<AuditEntry>> {
    let log = AUDIT_LOG.lock().unwrap();
    Json(log.iter().rev().cloned().collect())
}

/// Middleware that records mutating API operations to the audit log.
pub async fn audit_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let user = request
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.0.clone())
        .unwrap_or_default();
    let source_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let response = next.run(request).await;

    if method != Method::GET && method != Method::OPTIONS && method != Method::HEAD {
        let entry = AuditEntry {
            timestamp: unix_now(),
            method: method.to_string(),
            endpoint: path,
            user,
            source_ip,
            status: response.status().as_u16(),
        };

        // Append to log file
        if let Ok(line) = serde_json::to_string(&entry) {
            let _ = append_audit_line(&format!("{}\n", line));
        }

        // Store in memory ring buffer
        let mut log = AUDIT_LOG.lock().unwrap();
        if log.len() >= MAX_AUDIT_ENTRIES {
            log.pop_front();
        }
        log.push_back(entry);
    }

    response
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

const AUDIT_MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const AUDIT_KEEP_BYTES: usize = 5 * 1024 * 1024; // 5 MB

fn append_audit_line(content: &str) -> std::io::Result<()> {
    use std::io::{Read, Write};
    let _ = std::fs::create_dir_all("/var/log/quickfw");

    // Rotate if file exceeds 10 MB: keep the last 5 MB
    if let Ok(meta) = std::fs::metadata(AUDIT_LOG_PATH) {
        if meta.len() > AUDIT_MAX_BYTES {
            if let Ok(mut f) = std::fs::File::open(AUDIT_LOG_PATH) {
                let skip = meta.len() as usize - AUDIT_KEEP_BYTES;
                let mut buf = Vec::with_capacity(AUDIT_KEEP_BYTES);
                let _ = std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(skip as u64));
                let _ = f.read_to_end(&mut buf);
                drop(f);
                // Trim to the next newline boundary so we don't leave a partial line
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    buf = buf[pos + 1..].to_vec();
                }
                let _ = std::fs::write(AUDIT_LOG_PATH, &buf);
            }
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG_PATH)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}
