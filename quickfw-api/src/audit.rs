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
use tokio::sync::Mutex as TokioMutex;

use crate::auth::AuthUser;

static AUDIT_FILE_LOCK: std::sync::OnceLock<TokioMutex<()>> = std::sync::OnceLock::new();

fn audit_file_lock() -> &'static TokioMutex<()> {
    AUDIT_FILE_LOCK.get_or_init(|| TokioMutex::new(()))
}

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
    let log = AUDIT_LOG.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
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
            let _ = append_audit_line(&format!("{}\n", line)).await;
        }

        // Store in memory ring buffer
        let mut log = AUDIT_LOG.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
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
        .unwrap_or_else(|e| {
            tracing::warn!("System clock is before Unix epoch: {}. Treating as epoch.", e);
            std::time::Duration::from_secs(0)
        })
        .as_secs()
}

const AUDIT_MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const AUDIT_KEEP_BYTES: usize = 5 * 1024 * 1024; // 5 MB

async fn append_audit_line(content: &str) -> std::io::Result<()> {
    use std::io::{Read, Seek, Write};
    let _guard = audit_file_lock().lock().await;
    let _ = tokio::fs::create_dir_all("/var/log/quickfw").await;

    // Rotate if file exceeds 10 MB: keep the last 5 MB
    if let Ok(meta) = tokio::fs::metadata(AUDIT_LOG_PATH).await {
        if meta.len() > AUDIT_MAX_BYTES {
            if let Ok(mut f) = std::fs::File::open(AUDIT_LOG_PATH) {
                let skip = meta.len() as usize - AUDIT_KEEP_BYTES;
                let mut buf = Vec::with_capacity(AUDIT_KEEP_BYTES);
                let _ = f.seek(std::io::SeekFrom::Start(skip as u64));
                let _ = f.read_to_end(&mut buf);
                drop(f);
                // Trim to the next newline boundary so we don't leave a partial line
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    buf = buf[pos + 1..].to_vec();
                }
                // Atomic rotation: write to temp, fsync, rename
                let tmp = format!("{}.tmp", AUDIT_LOG_PATH);
                let mut tmp_file = std::fs::File::create(&tmp)?;
                tmp_file.write_all(&buf)?;
                tmp_file.sync_all()?;
                drop(tmp_file);
                std::fs::rename(&tmp, AUDIT_LOG_PATH)?;
                if let Some(parent) = std::path::Path::new(AUDIT_LOG_PATH).parent() {
                    if let Ok(dir) = std::fs::File::open(parent) {
                        let _ = dir.sync_all();
                    }
                }
            }
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG_PATH)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
