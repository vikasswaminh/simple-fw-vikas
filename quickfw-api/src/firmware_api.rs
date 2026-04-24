//! Firmware upgrade upload / status endpoints (Phase I).
//!
//! POST /api/system/firmware-upload — admin-only, raw ISO body, up to 1 GiB.
//!   Saves body to /tmp/quickfw-upgrade.iso, then invokes
//!   `quickfw-upgrade apply --no-reboot <iso>`. Returns the upgrade CLI's
//!   stdout/stderr/exit so the UI can show the result. The user has to
//!   reboot separately via /api/system/reboot (or quickfw-upgrade's own
//!   reboot, which we suppress with --no-reboot so the HTTP response has
//!   a chance to be sent first).
//!
//! GET /api/system/upgrade-status — admin-only. Runs `quickfw-upgrade
//!   status` and returns the parsed result (active slot, standby slot,
//!   pending marker).

use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::process::Command;

const FIRMWARE_UPLOAD_PATH: &str = "/tmp/quickfw-upgrade.iso";
const MAX_FIRMWARE_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB

pub fn create_router() -> Router {
    Router::new()
        .route("/api/system/firmware-upload", post(upload_firmware)
            .layer(DefaultBodyLimit::max(MAX_FIRMWARE_SIZE)))
        .route("/api/system/upgrade-status", get(upgrade_status))
        .layer(middleware::from_fn(crate::auth::require_role(
            crate::users::Role::Admin,
        )))
}

#[derive(Serialize)]
struct UploadResult {
    accepted_bytes: usize,
    iso_path: String,
    apply_exit: i32,
    apply_stdout: String,
    apply_stderr: String,
}

async fn upload_firmware(
    body: Bytes,
) -> Result<Json<UploadResult>, (StatusCode, Json<serde_json::Value>)> {
    // Minimal sanity check — a real ISO9660 image starts with a volume
    // descriptor at offset 32768, but it's not worth reading that far just
    // to reject a misaddressed POST. We require at least 1 MiB so we're
    // not storing a stray browser form submit.
    if body.len() < 1024 * 1024 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("body too small ({} bytes) — expected an ISO", body.len())
            })),
        ));
    }

    // Write body to /tmp/quickfw-upgrade.iso atomically.
    let tmp = format!("{}.part", FIRMWARE_UPLOAD_PATH);
    std::fs::write(&tmp, &body).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("write tmp iso: {}", e)})),
        )
    })?;
    std::fs::rename(&tmp, FIRMWARE_UPLOAD_PATH).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("rename tmp iso: {}", e)})),
        )
    })?;

    // Run quickfw-upgrade apply --no-reboot. --no-reboot lets us return the
    // HTTP response cleanly; the caller invokes /api/system/reboot when
    // ready.
    let out = Command::new("quickfw-upgrade")
        .args(["apply", FIRMWARE_UPLOAD_PATH, "--no-reboot"])
        .output()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("spawn quickfw-upgrade: {}", e)})),
            )
        })?;

    let result = UploadResult {
        accepted_bytes: body.len(),
        iso_path: FIRMWARE_UPLOAD_PATH.to_string(),
        apply_exit: out.status.code().unwrap_or(-1),
        apply_stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        apply_stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    };

    if !out.status.success() {
        // Non-zero exit (bad signature, no A/B layout, dd failed, etc.).
        // Return the stderr so the UI can show a useful error.
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "upgrade apply failed",
                "exit": result.apply_exit,
                "stdout": result.apply_stdout,
                "stderr": result.apply_stderr,
            })),
        ));
    }

    Ok(Json(result))
}

async fn upgrade_status() -> Json<serde_json::Value> {
    let out = Command::new("quickfw-upgrade")
        .arg("status")
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            Json(serde_json::json!({
                "available": true,
                "exit": o.status.code().unwrap_or(-1),
                "stdout": stdout,
                "stderr": stderr,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "available": false,
            "error": format!("quickfw-upgrade not installed or not executable: {}", e),
        })),
    }
}
