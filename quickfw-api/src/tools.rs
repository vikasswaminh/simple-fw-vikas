//! Tools API — diagnostic endpoints
//!
//! GET  /api/tools/arp          — ARP table (ip neigh show)
//! GET  /api/tools/dhcp-leases  — DHCP leases from dnsmasq
//! GET  /api/tools/dns-local    — local DNS overrides
//! POST /api/tools/dns-local    — save local DNS overrides
//! POST /api/tools/ping         — ping a host
//! POST /api/tools/traceroute   — traceroute a host
//! POST /api/tools/wol          — Wake-on-LAN magic packet
//! GET  /api/tools/ntp-status   — NTP/time sync status

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::process::Command;
use crate::state;
use tracing::{error, info};

const DNS_LOCAL_PATH: &str = "/etc/dnsmasq.d/quickfw-local.conf";

pub fn create_router() -> Router {
    Router::new()
        .route("/api/tools/arp", get(get_arp_table))
        .route("/api/tools/arp/flush", post(flush_arp_table))
        .route("/api/tools/dhcp-leases", get(get_dhcp_leases))
        .route("/api/tools/dns-local", get(get_dns_local))
        .route("/api/tools/dns-local", post(save_dns_local))
        .route("/api/tools/ping", post(ping_host))
        .route("/api/tools/traceroute", post(traceroute_host))
        .route("/api/tools/wol", post(wake_on_lan))
        .route("/api/tools/ntp-status", get(get_ntp_status))
}

// ===================================================================
// ARP table
// ===================================================================

#[derive(Serialize)]
struct ArpEntry {
    ip: String,
    mac: String,
    interface: String,
    state: String,
}

async fn get_arp_table() -> Json<Vec<ArpEntry>> {
    let output = Command::new("ip")
        .args(["neigh", "show"])
        .output();

    let entries = match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines()
                .filter_map(parse_arp_line)
                .collect()
        }
        _ => vec![],
    };
    Json(entries)
}

fn parse_arp_line(line: &str) -> Option<ArpEntry> {
    // Format: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let ip = parts[0].to_string();
    let mut mac = String::new();
    let mut interface = String::new();
    let mut state = String::new();

    let mut i = 1;
    while i < parts.len() {
        match parts[i] {
            "dev" => {
                if i + 1 < parts.len() {
                    interface = parts[i + 1].to_string();
                    i += 1;
                }
            }
            "lladdr" => {
                if i + 1 < parts.len() {
                    mac = parts[i + 1].to_string();
                    i += 1;
                }
            }
            s if s == "REACHABLE" || s == "STALE" || s == "DELAY" || s == "PROBE"
                || s == "FAILED" || s == "NOARP" || s == "INCOMPLETE" || s == "PERMANENT" =>
            {
                state = s.to_string();
            }
            _ => {}
        }
        i += 1;
    }

    Some(ArpEntry {
        ip,
        mac,
        interface,
        state,
    })
}

async fn flush_arp_table() -> Result<Json<&'static str>, StatusCode> {
    let output = Command::new("ip")
        .args(["neigh", "flush", "all"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            info!("ARP table flushed");
            Ok(Json("ARP table flushed"))
        }
        Ok(o) => {
            error!("arp flush failed: {}", String::from_utf8_lossy(&o.stderr));
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(e) => {
            error!("arp flush error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ===================================================================
// DHCP Leases
// ===================================================================

#[derive(Serialize)]
struct DhcpLease {
    expires: String,
    mac: String,
    ip: String,
    hostname: String,
    client_id: String,
}

async fn get_dhcp_leases() -> Json<Vec<DhcpLease>> {
    let content = std::fs::read_to_string("/var/lib/misc/dnsmasq.leases")
        .unwrap_or_default();

    let leases: Vec<DhcpLease> = content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                return None;
            }
            Some(DhcpLease {
                expires: parts[0].to_string(),
                mac: parts[1].to_string(),
                ip: parts[2].to_string(),
                hostname: parts.get(3).unwrap_or(&"*").to_string(),
                client_id: parts.get(4).unwrap_or(&"*").to_string(),
            })
        })
        .collect();

    Json(leases)
}

// ===================================================================
// Local DNS overrides
// ===================================================================

#[derive(Serialize, Deserialize, Clone)]
struct DnsLocalEntry {
    hostname: String,
    ip: String,
}

async fn get_dns_local() -> Json<Vec<DnsLocalEntry>> {
    let _guard = state::config_lock().lock().await;
    let content = std::fs::read_to_string(DNS_LOCAL_PATH).unwrap_or_default();

    let entries: Vec<DnsLocalEntry> = content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // Format: address=/hostname/ip
            let stripped = line.strip_prefix("address=/")?;
            let (hostname, ip) = stripped.rsplit_once('/')?;
            if hostname.is_empty() || ip.is_empty() {
                return None;
            }
            Some(DnsLocalEntry {
                hostname: hostname.to_string(),
                ip: ip.to_string(),
            })
        })
        .collect();

    Json(entries)
}

async fn save_dns_local(
    Json(entries): Json<Vec<DnsLocalEntry>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    // Validate entries
    for entry in &entries {
        if entry.hostname.is_empty() || entry.hostname.len() > 253 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid hostname: '{}'", entry.hostname)})),
            ));
        }
        // Basic hostname validation
        if !entry.hostname.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_') {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid hostname characters: '{}'", entry.hostname)})),
            ));
        }
        // Validate IP
        if entry.ip.parse::<std::net::IpAddr>().is_err() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid IP address: '{}'", entry.ip)})),
            ));
        }
    }

    // Build config content
    let content: String = entries
        .iter()
        .map(|e| format!("address=/{}/{}\n", e.hostname, e.ip))
        .collect();

    // Ensure directory exists
    let _ = std::fs::create_dir_all("/etc/dnsmasq.d");

    std::fs::write(DNS_LOCAL_PATH, &content).map_err(|e| {
        error!("Failed to write DNS local config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Write failed: {}", e)})),
        )
    })?;

    // Reload dnsmasq if running
    let _ = Command::new("systemctl")
        .args(["reload", "dnsmasq"])
        .output();

    info!("Local DNS overrides saved ({} entries)", entries.len());
    Ok(Json(serde_json::json!({"message": "DNS local overrides saved", "count": entries.len()})))
}

// ===================================================================
// Ping
// ===================================================================

#[derive(Deserialize)]
struct PingRequest {
    host: String,
    #[serde(default = "default_ping_count")]
    count: u32,
}

fn default_ping_count() -> u32 {
    4
}

async fn ping_host(
    Json(req): Json<PingRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate host — prevent command injection
    if req.host.is_empty() || req.host.len() > 253 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid host"})),
        ));
    }
    if !req.host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid host characters"})),
        ));
    }
    // Cap count
    let count = req.count.min(20).max(1);

    let output = Command::new("ping")
        .args(["-c", &count.to_string(), "-W", "3", &req.host])
        .output()
        .map_err(|e| {
            error!("Ping failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Ping failed: {}", e)})),
            )
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(Json(serde_json::json!({
        "success": output.status.success(),
        "stdout": stdout,
        "stderr": stderr,
    })))
}

// ===================================================================
// Traceroute
// ===================================================================

#[derive(Deserialize)]
struct TracerouteRequest {
    host: String,
}

async fn traceroute_host(
    Json(req): Json<TracerouteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate host — prevent command injection
    if req.host.is_empty() || req.host.len() > 253 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid host"})),
        ));
    }
    if !req.host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid host characters"})),
        ));
    }

    let output = Command::new("traceroute")
        .args(["-n", "-w", "2", "-m", "20", &req.host])
        .output()
        .map_err(|e| {
            error!("Traceroute failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Traceroute failed: {}", e)})),
            )
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(Json(serde_json::json!({
        "success": output.status.success(),
        "stdout": stdout,
        "stderr": stderr,
    })))
}

// ===================================================================
// Wake-on-LAN
// ===================================================================

#[derive(Deserialize)]
struct WolRequest {
    mac: String,
    #[serde(default = "default_wol_interface")]
    interface: String,
}

fn default_wol_interface() -> String {
    "eth0".to_string()
}

async fn wake_on_lan(
    Json(req): Json<WolRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate MAC address format
    let mac_bytes = parse_mac(&req.mac).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
    })?;

    // Validate interface name
    if !req.interface.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid interface name"})),
        ));
    }

    // Build magic packet: 6x 0xFF + 16x MAC address
    let mut magic_packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        magic_packet.extend_from_slice(&mac_bytes);
    }

    // Send via UDP broadcast on port 9
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| {
        error!("WoL socket bind failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Socket error: {}", e)})),
        )
    })?;
    socket.set_broadcast(true).map_err(|e| {
        error!("WoL set_broadcast failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Broadcast error: {}", e)})),
        )
    })?;
    socket
        .send_to(&magic_packet, "255.255.255.255:9")
        .map_err(|e| {
            error!("WoL send failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Send error: {}", e)})),
            )
        })?;

    info!("Wake-on-LAN magic packet sent to {} via {}", req.mac, req.interface);
    Ok(Json(serde_json::json!({
        "message": "Magic packet sent",
        "mac": req.mac,
        "interface": req.interface,
    })))
}

fn parse_mac(mac: &str) -> Result<[u8; 6], String> {
    let mac = mac.trim();
    let parts: Vec<&str> = if mac.contains(':') {
        mac.split(':').collect()
    } else if mac.contains('-') {
        mac.split('-').collect()
    } else {
        return Err(format!("Invalid MAC format: '{}'", mac));
    };

    if parts.len() != 6 {
        return Err(format!("MAC must have 6 octets, got {}", parts.len()));
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("Invalid hex octet '{}' in MAC", part))?;
    }
    Ok(bytes)
}

// ===================================================================
// NTP Status
// ===================================================================

async fn get_ntp_status() -> Json<serde_json::Value> {
    let output = Command::new("timedatectl")
        .args(["show"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let mut info = serde_json::Map::new();
            for line in text.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    info.insert(
                        key.trim().to_string(),
                        serde_json::Value::String(value.trim().to_string()),
                    );
                }
            }
            Json(serde_json::Value::Object(info))
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            Json(serde_json::json!({"error": stderr}))
        }
        Err(e) => {
            Json(serde_json::json!({"error": format!("Failed to run timedatectl: {}", e)}))
        }
    }
}
