//! L3/L4 firewall rule management and address/port groups API endpoints.

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use gfw_io::firewall::{self, FirewallConfig};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::validation;

const GROUPS_PATH: &str = "/etc/quickfw/firewall-groups.yaml";

#[derive(Serialize, Deserialize, Clone)]
pub struct AddressGroup {
    pub name: String,
    #[serde(default)]
    pub addresses: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PortGroup {
    pub name: String,
    #[serde(default)]
    pub ports: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FirewallGroups {
    #[serde(default)]
    pub address_groups: Vec<AddressGroup>,
    #[serde(default)]
    pub port_groups: Vec<PortGroup>,
}

pub async fn create_router() -> Router {
    Router::new()
        .route("/api/firewall", get(get_firewall_config))
        .route("/api/firewall", post(save_firewall_config))
        .route("/api/firewall/groups", get(get_groups))
        .route("/api/firewall/groups", post(save_groups))
        .route("/api/firewall/counters", get(get_firewall_counters))
}

async fn get_firewall_config() -> Json<FirewallConfig> {
    Json(firewall::load_firewall_config())
}

async fn save_firewall_config(
    query: axum::extract::Query<std::collections::HashMap<String, String>>,
    Json(config): Json<FirewallConfig>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Validate all user-supplied fields before touching nftables
    if let Err(e) = validation::validate_firewall_config(&config) {
        warn!("Firewall config validation failed: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "validation_failed", "detail": e})),
        ));
    }

    // Dry-run mode: generate nft script but don't apply
    if query.get("dry_run").map(|v| v == "true").unwrap_or(false) {
        let script = firewall::generate_firewall_nft_script(&config);
        return Ok(Json(serde_json::json!({
            "dry_run": true,
            "nft_script": script,
            "rule_count": config.rules.len(),
        })));
    }

    // Backup before save
    let _ = crate::config_utils::backup_config("/etc/quickfw/firewall.yaml");

    // Apply firewall first; only save config if apply succeeds (rollback on failure)
    firewall::apply_firewall(&config).map_err(|e| {
        error!("Failed to apply firewall rules: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to apply: {}", e)})),
        )
    })?;

    firewall::save_firewall_config(&config).map_err(|e| {
        error!("Failed to save firewall config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save: {}", e)})),
        )
    })?;

    info!(
        "Firewall config saved and applied ({} rules)",
        config.rules.len()
    );
    Ok(Json(serde_json::json!({"message": "Firewall rules applied"})))
}

async fn get_groups() -> Json<FirewallGroups> {
    let groups: FirewallGroups = match std::fs::read_to_string(GROUPS_PATH) {
        Ok(c) => serde_yaml::from_str(&c).unwrap_or_default(),
        Err(_) => FirewallGroups::default(),
    };
    Json(groups)
}

async fn save_groups(
    Json(groups): Json<FirewallGroups>,
) -> Result<Json<&'static str>, StatusCode> {
    // Validate group addresses and ports
    for group in &groups.address_groups {
        if let Err(e) = validation::validate_rule_name(&group.name) {
            warn!("Address group name validation failed: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
        for addr in &group.addresses {
            if let Err(e) = validation::validate_cidr(addr) {
                warn!("Address group address validation failed: {}", e);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }
    for group in &groups.port_groups {
        if let Err(e) = validation::validate_rule_name(&group.name) {
            warn!("Port group name validation failed: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
        for port in &group.ports {
            if let Err(e) = validation::validate_port(port) {
                warn!("Port group port validation failed: {}", e);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    let yaml = serde_yaml::to_string(&groups).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    std::fs::write(GROUPS_PATH, &yaml).map_err(|e| {
        error!("Failed to write firewall groups: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    info!(
        "Firewall groups saved ({} addr, {} port)",
        groups.address_groups.len(),
        groups.port_groups.len()
    );
    Ok(Json("Groups saved"))
}

/// Parse `nft list chain` output for rule hit counters.
async fn get_firewall_counters() -> Json<serde_json::Value> {
    let mut counters = Vec::new();

    for chain in ["gfw_fw_input", "gfw_fw_forward", "gfw_fw_output"] {
        let output = std::process::Command::new("nft")
            .args(["list", "chain", "inet", "gfw_rs", chain])
            .output();

        if let Ok(o) = output {
            if o.status.success() {
                let text = String::from_utf8_lossy(&o.stdout);
                for line in text.lines() {
                    let line = line.trim();
                    if !line.contains("counter") {
                        continue;
                    }
                    // Extract counter values: "counter packets X bytes Y"
                    let mut packets: u64 = 0;
                    let mut bytes: u64 = 0;
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, part) in parts.iter().enumerate() {
                        if *part == "packets" {
                            packets = parts.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(0);
                        }
                        if *part == "bytes" {
                            bytes = parts.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(0);
                        }
                    }
                    // Extract comment if present
                    let comment = if let Some(pos) = line.find("comment \"") {
                        let rest = &line[pos + 9..];
                        rest.split('"').next().unwrap_or("").to_string()
                    } else {
                        String::new()
                    };

                    counters.push(serde_json::json!({
                        "chain": chain,
                        "comment": comment,
                        "packets": packets,
                        "bytes": bytes,
                    }));
                }
            }
        }
    }

    Json(serde_json::json!({"counters": counters}))
}
