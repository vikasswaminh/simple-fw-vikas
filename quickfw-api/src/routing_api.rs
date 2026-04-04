//! Routing protocol management API endpoints.

use axum::{
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::collections::HashMap;
use tracing::{error, info, warn};

use routing::{bgp, ospf, StaticRoutesConfig};

use crate::validation;

pub async fn create_router() -> Router {
    Router::new()
        .route("/api/routing/ospf", get(get_ospf_config))
        .route("/api/routing/ospf", post(save_ospf_config))
        .route("/api/routing/bgp", get(get_bgp_config))
        .route("/api/routing/bgp", post(save_bgp_config))
        .route("/api/routing/table", get(get_routing_table))
        .route("/api/routing/ospf/neighbors", get(get_ospf_neighbors))
        .route("/api/routing/bgp/summary", get(get_bgp_summary))
        .route("/api/routing/protocols", get(get_active_protocols))
}

async fn get_ospf_config() -> Json<ospf::OspfConfig> {
    Json(ospf::load_ospf_config())
}

async fn save_ospf_config(
    Json(config): Json<ospf::OspfConfig>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Validate
    if let Err(e) = ospf::validate_ospf_config(&config) {
        warn!("OSPF config validation failed: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "validation_failed", "detail": e})),
        ));
    }

    // Backup
    let _ = crate::config_utils::backup_config("/etc/quickfw/ospf.yaml");

    // Save OSPF config
    ospf::save_ospf_config(&config).map_err(|e| {
        error!("Failed to save OSPF config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Save failed: {}", e)})),
        )
    })?;

    // Regenerate and apply FRR config
    apply_routing_config().map_err(|e| {
        error!("Failed to apply routing config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Apply failed: {}", e)})),
        )
    })?;

    info!("OSPF config saved and applied");
    Ok(Json(serde_json::json!({"message": "OSPF configuration applied"})))
}

async fn get_bgp_config() -> Json<bgp::BgpConfig> {
    Json(bgp::load_bgp_config())
}

async fn save_bgp_config(
    Json(config): Json<bgp::BgpConfig>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Validate
    if let Err(e) = bgp::validate_bgp_config(&config) {
        warn!("BGP config validation failed: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "validation_failed", "detail": e})),
        ));
    }

    // Backup
    let _ = crate::config_utils::backup_config("/etc/quickfw/bgp.yaml");

    // Save BGP config
    bgp::save_bgp_config(&config).map_err(|e| {
        error!("Failed to save BGP config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Save failed: {}", e)})),
        )
    })?;

    // Regenerate and apply FRR config
    apply_routing_config().map_err(|e| {
        error!("Failed to apply routing config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Apply failed: {}", e)})),
        )
    })?;

    info!("BGP config saved and applied");
    Ok(Json(serde_json::json!({"message": "BGP configuration applied"})))
}

async fn get_routing_table(
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let protocol = params.get("protocol").map(|s| s.as_str());
    match routing::get_routing_table(protocol) {
        Ok(table) => Ok(Json(serde_json::json!({"table": table}))),
        Err(e) => {
            error!("Failed to get routing table: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to get routing table: {}", e)})),
            ))
        }
    }
}

async fn get_ospf_neighbors() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    match routing::get_ospf_neighbors() {
        Ok(output) => Ok(Json(serde_json::json!({"neighbors": output}))),
        Err(e) => {
            error!("Failed to get OSPF neighbors: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to get OSPF neighbors: {}", e)})),
            ))
        }
    }
}

async fn get_bgp_summary() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    match routing::get_bgp_summary() {
        Ok(output) => Ok(Json(serde_json::json!({"summary": output}))),
        Err(e) => {
            error!("Failed to get BGP summary: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to get BGP summary: {}", e)})),
            ))
        }
    }
}

async fn get_active_protocols() -> Json<serde_json::Value> {
    let ospf_config = ospf::load_ospf_config();
    let bgp_config = bgp::load_bgp_config();

    Json(serde_json::json!({
        "ospf": {
            "enabled": ospf_config.enabled,
            "router_id": ospf_config.router_id,
            "networks": ospf_config.networks.len(),
        },
        "bgp": {
            "enabled": bgp_config.enabled,
            "local_as": bgp_config.local_as,
            "router_id": bgp_config.router_id,
            "neighbors": bgp_config.neighbors.len(),
        }
    }))
}

/// Regenerate and apply complete FRR configuration.
fn apply_routing_config() -> Result<(), Box<dyn std::error::Error>> {
    let ospf_config = ospf::load_ospf_config();
    let bgp_config = bgp::load_bgp_config();
    let static_routes = routing::load_static_routes();

    let frr_conf = routing::generate_frr_config(&ospf_config, &bgp_config, &static_routes);
    routing::apply_frr_config(&frr_conf)?;

    Ok(())
}
