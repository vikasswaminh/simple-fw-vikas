//! NAT rule management API endpoints.

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use gfw_io::nat::NatConfig;
use tracing::{error, info, warn};

use crate::validation;

const NAT_CONFIG_PATH: &str = "/etc/quickfw/nat.yaml";

pub async fn create_router() -> Router {
    Router::new()
        .route("/api/nat", get(get_nat_config))
        .route("/api/nat", post(save_nat_config))
}

async fn get_nat_config() -> Json<NatConfig> {
    let config = load_nat_config().unwrap_or_default();
    Json(config)
}

async fn save_nat_config(
    Json(config): Json<NatConfig>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Validate all user-supplied fields before touching nftables
    if let Err(e) = validation::validate_nat_config(&config) {
        warn!("NAT config validation failed: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "validation_failed", "detail": e})),
        ));
    }

    // Backup before save
    let _ = crate::config_utils::backup_config(NAT_CONFIG_PATH);

    // Save to file
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

    // Apply rules
    gfw_io::nat::apply_nat(&config).map_err(|e| {
        error!("Failed to apply NAT rules: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Apply failed: {}", e)})),
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
