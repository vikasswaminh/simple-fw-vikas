//! Local log viewer API (Phase J).
//!
//! GET /api/logs?source={audit|system|firewall}&tail=N
//!
//! - `audit`    → tail of /var/log/quickfw/audit.log (written by audit
//!                middleware)
//! - `system`   → `journalctl -u quickfw-api --no-pager -n N`
//! - `firewall` → `journalctl -k --grep=QUICKFW --no-pager -n N` (nftables
//!                LOG rules are prefixed "QUICKFW " in the ruleset)
//!
//! Admin-only. Bounded tail length to keep response size predictable.

use axum::{
    extract::Query,
    http::StatusCode,
    middleware,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::process::Command;

pub fn create_router() -> Router {
    Router::new()
        .route("/api/logs", get(get_logs))
        .layer(middleware::from_fn(crate::auth::require_role(
            crate::users::Role::Admin,
        )))
}

#[derive(Deserialize)]
struct LogQuery {
    source: String,
    #[serde(default)]
    tail: Option<usize>,
}

#[derive(Serialize)]
struct LogResponse {
    source: String,
    lines: Vec<String>,
    truncated: bool,
}

const DEFAULT_TAIL: usize = 200;
const MAX_TAIL: usize = 2000;

async fn get_logs(
    Query(q): Query<LogQuery>,
) -> Result<Json<LogResponse>, (StatusCode, Json<serde_json::Value>)> {
    let tail = clamp_tail(q.tail.unwrap_or(DEFAULT_TAIL));

    let (lines, truncated) = match q.source.as_str() {
        "audit" => read_tail_file("/var/log/quickfw/audit.log", tail),
        "system" => read_journalctl(&["-u", "quickfw-api", "--no-pager", "-n"], tail),
        "firewall" => read_journalctl(
            &["-k", "--grep=QUICKFW", "--no-pager", "-n"],
            tail,
        ),
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("unknown source {:?} — expected audit|system|firewall", other)
                })),
            ));
        }
    };

    Ok(Json(LogResponse {
        source: q.source,
        lines,
        truncated,
    }))
}

/// Clamp tail to the [1, MAX_TAIL] range. Unbounded tail would make the
/// response size user-controlled; easier to defend if it's always bounded.
fn clamp_tail(n: usize) -> usize {
    n.clamp(1, MAX_TAIL)
}

/// Read the last N lines of a file. Returns (lines, truncated) where
/// truncated=true means we had more than N lines and dropped the oldest.
fn read_tail_file(path: &str, tail: usize) -> (Vec<String>, bool) {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return (Vec::new(), false),
    };
    let all: Vec<&str> = content.lines().collect();
    let total = all.len();
    let start = total.saturating_sub(tail);
    let lines = all[start..].iter().map(|s| s.to_string()).collect();
    (lines, total > tail)
}

/// Run journalctl with the given argv prefix + "N <tail>" and return its
/// stdout split into lines. If journalctl isn't present (e.g., test host),
/// returns empty.
fn read_journalctl(prefix_args: &[&str], tail: usize) -> (Vec<String>, bool) {
    let tail_s = tail.to_string();
    let mut args: Vec<&str> = prefix_args.to_vec();
    args.push(&tail_s);
    let output = match Command::new("journalctl").args(&args).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return (Vec::new(), false),
    };
    let text = String::from_utf8_lossy(&output);
    let lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    // journalctl already applied the tail bound; we can't tell if more
    // existed without a second call, so truncated=false here.
    (lines, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_tail_bounds() {
        assert_eq!(clamp_tail(0), 1);
        assert_eq!(clamp_tail(100), 100);
        assert_eq!(clamp_tail(MAX_TAIL + 1), MAX_TAIL);
        assert_eq!(clamp_tail(usize::MAX), MAX_TAIL);
    }

    #[test]
    fn read_tail_file_missing_returns_empty() {
        let (lines, truncated) = read_tail_file("/tmp/this-path-does-not-exist-ever", 10);
        assert!(lines.is_empty());
        assert!(!truncated);
    }

    #[test]
    fn read_tail_file_returns_last_n_lines() {
        let path = format!("/tmp/quickfw-logtest-{}", std::process::id());
        let content = (0..50).map(|i| format!("line {}\n", i)).collect::<String>();
        std::fs::write(&path, &content).unwrap();
        let (lines, truncated) = read_tail_file(&path, 5);
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "line 45");
        assert_eq!(lines[4], "line 49");
        assert!(truncated);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_tail_file_no_truncation_when_under_limit() {
        let path = format!("/tmp/quickfw-logtest2-{}", std::process::id());
        std::fs::write(&path, "only\ntwo\nlines\n").unwrap();
        let (lines, truncated) = read_tail_file(&path, 100);
        assert_eq!(lines.len(), 3);
        assert!(!truncated);
        let _ = std::fs::remove_file(&path);
    }
}
