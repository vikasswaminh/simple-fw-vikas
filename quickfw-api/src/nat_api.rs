//! NAT rule management API endpoints.

use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use gfw_io::nat::NatConfig;
use tracing::{error, info, warn};

use crate::{state, validation};

const NAT_CONFIG_PATH: &str = "/etc/quickfw/nat.yaml";

pub async fn create_router() -> Router {
    Router::new()
        .route("/api/nat", get(get_nat_config))
        .route("/api/nat", post(save_nat_config))
        .route("/api/nat/masquerade/:idx", delete(delete_masquerade))
        .route("/api/nat/port_forward/:idx", delete(delete_port_forward))
        .route("/api/nat/snat/:idx", delete(delete_snat))
}

async fn get_nat_config() -> Json<NatConfig> {
    let _guard = state::config_lock().lock().await;
    let config = load_nat_config().unwrap_or_default();
    Json(config)
}

async fn save_nat_config(
    Json(config): Json<NatConfig>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    // Validate all user-supplied fields before touching nftables
    if let Err(e) = validation::validate_nat_config(&config) {
        warn!("NAT config validation failed: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "validation_failed", "detail": e})),
        ));
    }

    // Apply rules first; only save config if apply succeeds
    gfw_io::nat::apply_nat(&config).map_err(|e| {
        error!("Failed to apply NAT rules: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Apply failed: {}", e)})),
        )
    })?;

    // Backup before save
    let _ = crate::config_utils::backup_config(NAT_CONFIG_PATH);

    // Atomic save
    let yaml = serde_yaml::to_string(&config).map_err(|e| {
        error!("Failed to serialize NAT config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Serialize failed: {}", e)})),
        )
    })?;

    crate::config_utils::atomic_write(NAT_CONFIG_PATH, &yaml).map_err(|e| {
        error!("Failed to write NAT config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Write failed: {}", e)})),
        )
    })?;

    info!("NAT configuration saved and applied");
    Ok(Json(serde_json::json!({"message": "NAT rules applied"})))
}

fn load_nat_config() -> Result<NatConfig, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(NAT_CONFIG_PATH)?;
    let config: NatConfig = serde_yaml::from_str(&contents)?;
    Ok(config)
}

async fn delete_masquerade(
    Path(idx): Path<usize>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    let mut config = load_nat_config().unwrap_or_default();

    if idx == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid index (must be >= 1)"})),
        ));
    }
    if idx > config.masquerade.len() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("masquerade index {} out of range (have {} rules)", idx, config.masquerade.len())})),
        ));
    }

    config.masquerade.remove(idx - 1);

    // Save and apply
    let yaml = serde_yaml::to_string(&config).map_err(|e| {
        error!("Failed to serialize NAT config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Serialize failed: {}", e)})),
        )
    })?;

    std::fs::write(NAT_CONFIG_PATH, &yaml).map_err(|e| {
        error!("Failed to write NAT config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Write failed: {}", e)})),
        )
    })?;

    gfw_io::nat::apply_nat(&config).map_err(|e| {
        error!("Failed to apply NAT rules: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Apply failed: {}", e)})),
        )
    })?;

    info!("Masquerade rule {} deleted", idx);
    Ok(Json(serde_json::json!({"message": "Masquerade rule deleted"})))
}

async fn delete_port_forward(
    Path(idx): Path<usize>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    let mut config = load_nat_config().unwrap_or_default();

    if idx == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid index (must be >= 1)"})),
        ));
    }
    if idx > config.port_forward.len() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("port_forward index {} out of range (have {} rules)", idx, config.port_forward.len())})),
        ));
    }

    config.port_forward.remove(idx - 1);

    // Save and apply
    let yaml = serde_yaml::to_string(&config).map_err(|e| {
        error!("Failed to serialize NAT config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Serialize failed: {}", e)})),
        )
    })?;

    std::fs::write(NAT_CONFIG_PATH, &yaml).map_err(|e| {
        error!("Failed to write NAT config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Write failed: {}", e)})),
        )
    })?;

    gfw_io::nat::apply_nat(&config).map_err(|e| {
        error!("Failed to apply NAT rules: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Apply failed: {}", e)})),
        )
    })?;

    info!("Port forward rule {} deleted", idx);
    Ok(Json(serde_json::json!({"message": "Port forward rule deleted"})))
}

async fn delete_snat(
    Path(idx): Path<usize>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    let mut config = load_nat_config().unwrap_or_default();

    if idx == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid index (must be >= 1)"})),
        ));
    }
    if idx > config.snat.len() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("snat index {} out of range (have {} rules)", idx, config.snat.len())})),
        ));
    }

    config.snat.remove(idx - 1);

    let yaml = serde_yaml::to_string(&config).map_err(|e| {
        error!("Failed to serialize NAT config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Serialize failed: {}", e)})),
        )
    })?;

    std::fs::write(NAT_CONFIG_PATH, &yaml).map_err(|e| {
        error!("Failed to write NAT config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Write failed: {}", e)})),
        )
    })?;

    gfw_io::nat::apply_nat(&config).map_err(|e| {
        error!("Failed to apply NAT rules: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Apply failed: {}", e)})),
        )
    })?;

    info!("Static SNAT rule {} deleted", idx);
    Ok(Json(serde_json::json!({"message": "Static SNAT rule deleted"})))
}
