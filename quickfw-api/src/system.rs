//! System information, interface management, traffic stats, routing,
//! appliance settings, and configuration management API endpoints.

use axum::{
    extract::Path,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use tracing::{error, info};

// ===================================================================
// Data types
// ===================================================================

#[derive(Serialize)]
struct SystemInfo {
    hostname: String,
    version: String,
    uptime_seconds: f64,
    boot_time: String,
    cpu_usage_percent: f64,
    load_avg_1: f64,
    load_avg_5: f64,
    load_avg_15: f64,
    memory_total_mb: u64,
    memory_used_mb: u64,
    memory_free_mb: u64,
    memory_percent: f64,
}

#[derive(Serialize)]
struct TrafficSnapshot {
    active_connections: u64,
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    total_rx_packets: u64,
    total_tx_packets: u64,
}

#[derive(Serialize)]
struct InterfaceResponse {
    interfaces: Vec<InterfaceItem>,
}

#[derive(Serialize, Clone)]
struct InterfaceItem {
    name: String,
    mac: String,
    link_up: bool,
    ipv4_addrs: Vec<String>,
    mtu: u32,
    speed: String,
    description: String,
    role: String,
    zone: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
}

#[derive(Deserialize)]
struct InterfaceConfigRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    gateway: String,
    #[serde(default)]
    dns: Vec<String>,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct InterfaceRole {
    interface: String,
    role: String,
    zone: String,
}

#[derive(Serialize, Deserialize, Default)]
struct InterfaceRolesConfig {
    #[serde(default)]
    roles: Vec<InterfaceRole>,
}

#[derive(Serialize, Deserialize, Default)]
struct InterfaceDescriptions {
    #[serde(default)]
    descriptions: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StaticRoute {
    destination: String,
    gateway: String,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    metric: u32,
}

#[derive(Serialize, Deserialize, Default)]
struct RoutesConfig {
    #[serde(default)]
    routes: Vec<StaticRoute>,
}

#[derive(Serialize, Deserialize)]
struct ApplianceSettings {
    hostname: String,
    timezone: String,
    #[serde(default)]
    ntp_servers: Vec<String>,
    #[serde(default)]
    dns_servers: Vec<String>,
}

#[derive(Serialize)]
struct ConfigExport {
    exported_at: String,
    settings: serde_json::Value,
    firewall: serde_json::Value,
    nat: serde_json::Value,
    roles: serde_json::Value,
    routes: serde_json::Value,
}

// ===================================================================
// Constants
// ===================================================================

const ROLES_PATH: &str = "/etc/quickfw/interfaces.yaml";
const DESCRIPTIONS_PATH: &str = "/etc/quickfw/iface-descriptions.yaml";
const SETTINGS_PATH: &str = "/etc/quickfw/settings.yaml";
const ROUTES_PATH: &str = "/etc/quickfw/routes.yaml";
const FIREWALL_PATH: &str = "/etc/quickfw/firewall.yaml";
const NAT_PATH: &str = "/etc/quickfw/nat.yaml";

// ===================================================================
// Router
// ===================================================================

const SYSLOG_CONFIG_PATH: &str = "/etc/quickfw/syslog.yaml";

pub async fn create_router() -> Router {
    Router::new()
        .route("/api/system/info", get(get_system_info))
        .route("/api/system/traffic", get(get_traffic_snapshot))
        .route("/api/system/reboot", post(reboot_system))
        .route("/api/interfaces", get(get_interfaces))
        .route("/api/interfaces/config", post(set_interface_config))
        .route("/api/interfaces/:name/config", post(set_interface_config_by_path))
        .route("/api/interfaces/roles", get(get_interface_roles))
        .route("/api/interfaces/roles", post(save_interface_roles))
        .route("/api/routes", get(get_routes))
        .route("/api/routes", post(save_routes))
        .route("/api/settings", get(get_settings))
        .route("/api/settings", post(save_settings))
        .route("/api/config/export", get(export_config))
        .route("/api/config/backups", get(get_config_backups))
        .route("/api/config/restore", post(restore_config_backup))
        .route("/api/config/import", post(import_config))
        .route("/api/conntrack", get(get_conntrack))
        .route("/api/syslog", get(get_syslog_config))
        .route("/api/syslog", post(save_syslog_config))
}

// ===================================================================
// Handlers — System
// ===================================================================

async fn get_system_info() -> Json<SystemInfo> {
    let hostname = fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "quickfw".to_string())
        .trim()
        .to_string();

    let (memory_total_mb, memory_used_mb, memory_free_mb, memory_percent) = parse_memory();
    let (load1, load5, load15) = parse_loadavg();

    Json(SystemInfo {
        hostname,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: parse_uptime(),
        boot_time: get_boot_time(),
        cpu_usage_percent: parse_cpu_usage(),
        load_avg_1: load1,
        load_avg_5: load5,
        load_avg_15: load15,
        memory_total_mb,
        memory_used_mb,
        memory_free_mb,
        memory_percent,
    })
}

async fn get_traffic_snapshot() -> Json<TrafficSnapshot> {
    let active_connections = fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_count")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let (mut rx_b, mut tx_b, mut rx_p, mut tx_p) = (0u64, 0u64, 0u64, 0u64);
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            rx_b += read_sys_stat(&name, "rx_bytes");
            tx_b += read_sys_stat(&name, "tx_bytes");
            rx_p += read_sys_stat(&name, "rx_packets");
            tx_p += read_sys_stat(&name, "tx_packets");
        }
    }

    Json(TrafficSnapshot {
        active_connections,
        total_rx_bytes: rx_b,
        total_tx_bytes: tx_b,
        total_rx_packets: rx_p,
        total_tx_packets: tx_p,
    })
}

#[derive(Deserialize)]
struct RebootRequest {
    #[serde(default)]
    confirm_password: String,
}

async fn reboot_system(
    Json(payload): Json<RebootRequest>,
) -> Result<Json<&'static str>, (StatusCode, Json<serde_json::Value>)> {
    // Re-authentication required for destructive operations
    if payload.confirm_password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "confirm_password required for reboot"})),
        ));
    }
    if !crate::auth::verify_password(&payload.confirm_password) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid confirmation password"})),
        ));
    }

    info!("Reboot requested via API (re-authenticated)");
    Command::new("systemctl")
        .args(["reboot"])
        .spawn()
        .map_err(|e| {
            error!("Failed to reboot: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Reboot failed: {}", e)})),
            )
        })?;
    Ok(Json("Rebooting"))
}

// ===================================================================
// Handlers — Interfaces
// ===================================================================

async fn get_interfaces() -> Json<InterfaceResponse> {
    let roles_config = load_roles();
    let descriptions = load_descriptions();
    let mut interfaces = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }

            let mac = fs::read_to_string(format!("/sys/class/net/{}/address", name))
                .unwrap_or_default()
                .trim()
                .to_string();
            let operstate =
                fs::read_to_string(format!("/sys/class/net/{}/operstate", name)).unwrap_or_default();
            let link_up = operstate.trim() == "up";
            let mtu = fs::read_to_string(format!("/sys/class/net/{}/mtu", name))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1500);
            let speed = fs::read_to_string(format!("/sys/class/net/{}/speed", name))
                .ok()
                .map(|s| {
                    let mbps: i64 = s.trim().parse().unwrap_or(-1);
                    if mbps > 0 {
                        format!("{} Mbps", mbps)
                    } else {
                        "\u{2014}".to_string()
                    }
                })
                .unwrap_or_else(|| "\u{2014}".to_string());

            let role_info = roles_config.roles.iter().find(|r| r.interface == name);
            let desc = descriptions
                .descriptions
                .get(&name)
                .cloned()
                .unwrap_or_default();

            interfaces.push(InterfaceItem {
                name: name.clone(),
                mac,
                link_up,
                ipv4_addrs: get_ipv4_addrs(&name),
                mtu,
                speed,
                description: desc,
                role: role_info.map(|r| r.role.clone()).unwrap_or_default(),
                zone: role_info.map(|r| r.zone.clone()).unwrap_or_default(),
                rx_bytes: read_sys_stat(&name, "rx_bytes"),
                tx_bytes: read_sys_stat(&name, "tx_bytes"),
                rx_packets: read_sys_stat(&name, "rx_packets"),
                tx_packets: read_sys_stat(&name, "tx_packets"),
                rx_errors: read_sys_stat(&name, "rx_errors"),
                tx_errors: read_sys_stat(&name, "tx_errors"),
                rx_dropped: read_sys_stat(&name, "rx_dropped"),
                tx_dropped: read_sys_stat(&name, "tx_dropped"),
            });
        }
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Json(InterfaceResponse { interfaces })
}

fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn is_valid_cidr(s: &str) -> bool {
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        if let (Ok(_ip), Ok(prefix)) = (ip_str.parse::<std::net::IpAddr>(), prefix_str.parse::<u8>()) {
            return if ip_str.contains(':') { prefix <= 128 } else { prefix <= 32 };
        }
    }
    false
}

fn is_valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !s.starts_with('-')
        && !s.starts_with('.')
}

fn is_valid_timezone(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '_' || c == '-' || c == '+')
}

async fn set_interface_config(
    Json(req): Json<InterfaceConfigRequest>,
) -> Result<Json<&'static str>, StatusCode> {
    let iface = &req.name;

    // Validate interface name (alphanumeric, dot, dash, underscore only)
    if iface.is_empty() || iface.len() > 15
        || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !std::path::Path::new(&format!("/sys/class/net/{}", iface)).exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Enable/disable
    if let Some(enabled) = req.enabled {
        let state = if enabled { "up" } else { "down" };
        let _ = Command::new("ip")
            .args(["link", "set", iface, state])
            .output();
        info!("Interface {} set {}", iface, state);
    }

    // MTU
    if let Some(mtu) = req.mtu {
        let mtu_s = mtu.to_string();
        let output = Command::new("ip")
            .args(["link", "set", iface, "mtu", &mtu_s])
            .output()
            .map_err(|e| {
                error!("Failed to set MTU: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        if !output.status.success() {
            error!("MTU set failed: {}", String::from_utf8_lossy(&output.stderr));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // Description (stored in config file)
    if let Some(ref desc) = req.description {
        let mut descriptions = load_descriptions();
        if desc.is_empty() {
            descriptions.descriptions.remove(iface);
        } else {
            descriptions
                .descriptions
                .insert(iface.to_string(), desc.clone());
        }
        save_descriptions(&descriptions);
    }

    // IP configuration
    if req.mode == "dhcp" {
        let _ = Command::new("ip")
            .args(["addr", "flush", "dev", iface])
            .output();
        let output = Command::new("dhclient")
            .args(["-v", iface])
            .output()
            .map_err(|e| {
                error!("dhclient failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        if !output.status.success() {
            error!("dhclient failed: {}", String::from_utf8_lossy(&output.stderr));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    } else if req.mode == "static" {
        let _ = Command::new("ip")
            .args(["addr", "flush", "dev", iface])
            .output();
        if !req.address.is_empty() {
            // Validate CIDR format before passing to ip command
            if !is_valid_cidr(&req.address) {
                error!("Invalid CIDR address: {}", req.address);
                return Err(StatusCode::BAD_REQUEST);
            }
            let output = Command::new("ip")
                .args(["addr", "add", &req.address, "dev", iface])
                .output()
                .map_err(|e| {
                    error!("ip addr add failed: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            if !output.status.success() {
                error!("ip addr add: {}", String::from_utf8_lossy(&output.stderr));
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
        if !req.gateway.is_empty() {
            // Validate gateway IP
            if !is_valid_ip(&req.gateway) {
                error!("Invalid gateway IP: {}", req.gateway);
                return Err(StatusCode::BAD_REQUEST);
            }
            let _ = Command::new("ip")
                .args(["route", "del", "default"])
                .output();
            let output = Command::new("ip")
                .args(["route", "add", "default", "via", &req.gateway, "dev", iface])
                .output()
                .map_err(|e| {
                    error!("ip route add failed: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            if !output.status.success() {
                error!("ip route add: {}", String::from_utf8_lossy(&output.stderr));
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
        if !req.dns.is_empty() {
            // Validate each DNS server is a valid IP
            for d in &req.dns {
                if !is_valid_ip(d) {
                    error!("Invalid DNS server IP: {}", d);
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
            let dns_content: String =
                req.dns.iter().map(|d| format!("nameserver {}\n", d)).collect();
            let _ = fs::write("/etc/resolv.conf", dns_content);
        }
    }

    // Ensure link is up unless explicitly disabled
    if req.enabled != Some(false) && !req.mode.is_empty() {
        let _ = Command::new("ip")
            .args(["link", "set", iface, "up"])
            .output();
    }

    info!(
        "Interface {} configured: mode={} addr={} mtu={:?}",
        iface, req.mode, req.address, req.mtu
    );
    Ok(Json("Interface configured"))
}

async fn set_interface_config_by_path(
    Path(name): Path<String>,
    Json(mut req): Json<InterfaceConfigRequest>,
) -> Result<Json<&'static str>, StatusCode> {
    req.name = name;
    set_interface_config(Json(req)).await
}

async fn get_interface_roles() -> Json<InterfaceRolesConfig> {
    Json(load_roles())
}

async fn save_interface_roles(
    Json(config): Json<InterfaceRolesConfig>,
) -> Result<Json<&'static str>, StatusCode> {
    let yaml = serde_yaml::to_string(&config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    fs::write(ROLES_PATH, &yaml).map_err(|e| {
        error!("Failed to write interface roles: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json("Interface roles saved"))
}

// ===================================================================
// Handlers — Routing
// ===================================================================

async fn get_routes() -> Json<RoutesConfig> {
    let config: RoutesConfig = match fs::read_to_string(ROUTES_PATH) {
        Ok(contents) => serde_yaml::from_str(&contents).unwrap_or_default(),
        Err(_) => RoutesConfig::default(),
    };
    Json(config)
}

async fn save_routes(
    Json(config): Json<RoutesConfig>,
) -> Result<Json<&'static str>, StatusCode> {
    // Validate all routes before saving
    for route in &config.routes {
        if !route.destination.is_empty() && !is_valid_cidr(&route.destination) && !is_valid_ip(&route.destination) {
            error!("Invalid route destination: {}", route.destination);
            return Err(StatusCode::BAD_REQUEST);
        }
        if !route.gateway.is_empty() && !is_valid_ip(&route.gateway) {
            error!("Invalid route gateway: {}", route.gateway);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let yaml = serde_yaml::to_string(&config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    fs::write(ROUTES_PATH, &yaml).map_err(|e| {
        error!("Failed to write routes: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    for route in &config.routes {
        let metric_s = route.metric.to_string();
        let mut args = vec!["route", "replace", route.destination.as_str(), "via", route.gateway.as_str()];
        if !route.interface.is_empty() {
            args.push("dev");
            args.push(&route.interface);
        }
        if route.metric > 0 {
            args.push("metric");
            args.push(&metric_s);
        }
        let output = Command::new("ip").args(&args).output();
        if let Ok(out) = output {
            if !out.status.success() {
                error!("Route apply failed: {}", String::from_utf8_lossy(&out.stderr));
            }
        }
    }

    info!("Static routes saved ({} routes)", config.routes.len());
    Ok(Json("Routes applied"))
}

// ===================================================================
// Handlers — Settings
// ===================================================================

async fn get_settings() -> Json<ApplianceSettings> {
    let config: ApplianceSettings = match fs::read_to_string(SETTINGS_PATH) {
        Ok(contents) => serde_yaml::from_str(&contents).unwrap_or_else(|_| default_settings()),
        Err(_) => default_settings(),
    };
    Json(config)
}

async fn save_settings(
    Json(config): Json<ApplianceSettings>,
) -> Result<Json<&'static str>, StatusCode> {
    // Validate hostname
    if !config.hostname.is_empty() {
        if !is_valid_hostname(&config.hostname) {
            error!("Invalid hostname: {}", config.hostname);
            return Err(StatusCode::BAD_REQUEST);
        }
        let _ = fs::write("/etc/hostname", format!("{}\n", config.hostname));
        let _ = Command::new("hostname").arg(&config.hostname).output();
    }
    // Validate timezone
    if !config.timezone.is_empty() {
        if !is_valid_timezone(&config.timezone) {
            error!("Invalid timezone: {}", config.timezone);
            return Err(StatusCode::BAD_REQUEST);
        }
        let _ = Command::new("timedatectl")
            .args(["set-timezone", &config.timezone])
            .output();
    }
    // Validate DNS servers
    if !config.dns_servers.is_empty() {
        for d in &config.dns_servers {
            if !is_valid_ip(d) {
                error!("Invalid DNS server IP in settings: {}", d);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        let dns: String = config.dns_servers.iter().map(|d| format!("nameserver {}\n", d)).collect();
        let _ = fs::write("/etc/resolv.conf", dns);
    }

    let yaml = serde_yaml::to_string(&config).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    fs::write(SETTINGS_PATH, &yaml).map_err(|e| {
        error!("Failed to write settings: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Settings saved");
    Ok(Json("Settings applied"))
}

// ===================================================================
// Handlers — Config Management
// ===================================================================

async fn export_config() -> Json<ConfigExport> {
    let read_yaml_json = |path: &str| -> serde_json::Value {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_yaml::from_str::<serde_json::Value>(&s).ok())
            .unwrap_or(serde_json::Value::Null)
    };

    let now = Command::new("date")
        .args(["+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    Json(ConfigExport {
        exported_at: now,
        settings: read_yaml_json(SETTINGS_PATH),
        firewall: read_yaml_json(FIREWALL_PATH),
        nat: read_yaml_json(NAT_PATH),
        roles: read_yaml_json(ROLES_PATH),
        routes: read_yaml_json(ROUTES_PATH),
    })
}

// ===================================================================
// Handlers — Connection Tracking
// ===================================================================

#[derive(Serialize)]
struct ConntrackEntry {
    protocol: String,
    src: String,
    dst: String,
    sport: String,
    dport: String,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
}

async fn get_conntrack() -> Json<Vec<ConntrackEntry>> {
    let output = Command::new("conntrack")
        .args(["-L", "-o", "extended"])
        .output();

    let entries = match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines()
                .take(1000) // limit output
                .filter_map(parse_conntrack_line)
                .collect()
        }
        _ => vec![],
    };
    Json(entries)
}

fn parse_conntrack_line(line: &str) -> Option<ConntrackEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let protocol = parts.first()?.to_string();
    let mut src = String::new();
    let mut dst = String::new();
    let mut sport = String::new();
    let mut dport = String::new();
    let mut state = String::new();
    let mut bytes = None;

    for part in &parts {
        if let Some(v) = part.strip_prefix("src=") {
            if src.is_empty() {
                src = v.to_string();
            }
        } else if let Some(v) = part.strip_prefix("dst=") {
            if dst.is_empty() {
                dst = v.to_string();
            }
        } else if let Some(v) = part.strip_prefix("sport=") {
            if sport.is_empty() {
                sport = v.to_string();
            }
        } else if let Some(v) = part.strip_prefix("dport=") {
            if dport.is_empty() {
                dport = v.to_string();
            }
        } else if let Some(v) = part.strip_prefix("bytes=") {
            bytes = v.parse().ok();
        } else if *part == "ESTABLISHED" || *part == "TIME_WAIT" || *part == "SYN_SENT"
            || *part == "SYN_RECV" || *part == "FIN_WAIT" || *part == "CLOSE_WAIT"
            || *part == "LAST_ACK" || *part == "CLOSE" || *part == "LISTEN"
        {
            state = part.to_string();
        }
    }

    Some(ConntrackEntry {
        protocol,
        src,
        dst,
        sport,
        dport,
        state,
        bytes,
    })
}

// ===================================================================
// Handlers — Config Backup & Restore
// ===================================================================

async fn get_config_backups() -> Json<Vec<crate::config_utils::BackupInfo>> {
    Json(crate::config_utils::list_backups())
}

#[derive(Deserialize)]
struct RestoreRequest {
    name: String,
    confirm_password: String,
}

async fn restore_config_backup(
    Json(req): Json<RestoreRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Re-auth required
    if !crate::auth::verify_password(&req.confirm_password) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid confirmation password"})),
        ));
    }

    // Validate backup name (prevent path traversal)
    if req.name.contains("..") || req.name.contains('/') || req.name.contains('\\') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid backup name"})),
        ));
    }

    let backup_path = format!("/etc/quickfw/backups/{}", req.name);
    if !std::path::Path::new(&backup_path).exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Backup not found"})),
        ));
    }

    // Determine target config file from backup name (e.g., "firewall.yaml.1709836800.bak")
    let target = if req.name.starts_with("firewall.yaml") {
        FIREWALL_PATH
    } else if req.name.starts_with("nat.yaml") {
        NAT_PATH
    } else if req.name.starts_with("settings.yaml") {
        SETTINGS_PATH
    } else if req.name.starts_with("routes.yaml") {
        ROUTES_PATH
    } else if req.name.starts_with("interfaces.yaml") {
        ROLES_PATH
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Unknown config type in backup name"})),
        ));
    };

    // Backup current before restoring
    let _ = crate::config_utils::backup_config(target);

    // Copy backup to target
    fs::copy(&backup_path, target).map_err(|e| {
        error!("Failed to restore backup: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Restore failed: {}", e)})),
        )
    })?;

    info!("Config restored from backup: {} -> {}", backup_path, target);
    Ok(Json(serde_json::json!({"message": format!("Restored {} from {}", target, req.name)})))
}

// ===================================================================
// Handlers — Config Import
// ===================================================================

#[derive(Deserialize)]
struct ConfigImport {
    #[serde(default)]
    settings: Option<serde_json::Value>,
    #[serde(default)]
    firewall: Option<serde_json::Value>,
    #[serde(default)]
    nat: Option<serde_json::Value>,
    #[serde(default)]
    roles: Option<serde_json::Value>,
    #[serde(default)]
    routes: Option<serde_json::Value>,
}

async fn import_config(
    Json(config): Json<ConfigImport>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut imported = Vec::new();

    // Validate and import each section
    if let Some(ref fw) = config.firewall {
        let fw_config: gfw_io::firewall::FirewallConfig =
            serde_json::from_value(fw.clone()).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Invalid firewall config: {}", e)})),
                )
            })?;
        if let Err(e) = crate::validation::validate_firewall_config(&fw_config) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Firewall validation: {}", e)})),
            ));
        }
        let _ = crate::config_utils::backup_config(FIREWALL_PATH);
        let yaml = serde_yaml::to_string(&fw_config).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialize: {}", e)})),
            )
        })?;
        crate::config_utils::atomic_write(FIREWALL_PATH, &yaml).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Write: {}", e)})),
            )
        })?;
        imported.push("firewall");
    }

    if let Some(ref nat) = config.nat {
        let nat_config: gfw_io::nat::NatConfig =
            serde_json::from_value(nat.clone()).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Invalid NAT config: {}", e)})),
                )
            })?;
        if let Err(e) = crate::validation::validate_nat_config(&nat_config) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("NAT validation: {}", e)})),
            ));
        }
        let _ = crate::config_utils::backup_config(NAT_PATH);
        let yaml = serde_yaml::to_string(&nat_config).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialize: {}", e)})),
            )
        })?;
        crate::config_utils::atomic_write(NAT_PATH, &yaml).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Write: {}", e)})),
            )
        })?;
        imported.push("nat");
    }

    if let Some(ref settings) = config.settings {
        let _ = crate::config_utils::backup_config(SETTINGS_PATH);
        let yaml = serde_yaml::to_string(settings).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialize: {}", e)})),
            )
        })?;
        crate::config_utils::atomic_write(SETTINGS_PATH, &yaml).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Write: {}", e)})),
            )
        })?;
        imported.push("settings");
    }

    if let Some(ref roles) = config.roles {
        let _ = crate::config_utils::backup_config(ROLES_PATH);
        let yaml = serde_yaml::to_string(roles).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialize: {}", e)})),
            )
        })?;
        crate::config_utils::atomic_write(ROLES_PATH, &yaml).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Write: {}", e)})),
            )
        })?;
        imported.push("roles");
    }

    if let Some(ref routes) = config.routes {
        let _ = crate::config_utils::backup_config(ROUTES_PATH);
        let yaml = serde_yaml::to_string(routes).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialize: {}", e)})),
            )
        })?;
        crate::config_utils::atomic_write(ROUTES_PATH, &yaml).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Write: {}", e)})),
            )
        })?;
        imported.push("routes");
    }

    info!("Config imported: {:?}", imported);
    Ok(Json(serde_json::json!({
        "message": "Config imported",
        "imported": imported,
    })))
}

// ===================================================================
// Helpers
// ===================================================================

fn load_roles() -> InterfaceRolesConfig {
    match fs::read_to_string(ROLES_PATH) {
        Ok(c) => serde_yaml::from_str(&c).unwrap_or_default(),
        Err(_) => InterfaceRolesConfig::default(),
    }
}

fn load_descriptions() -> InterfaceDescriptions {
    match fs::read_to_string(DESCRIPTIONS_PATH) {
        Ok(c) => serde_yaml::from_str(&c).unwrap_or_default(),
        Err(_) => InterfaceDescriptions::default(),
    }
}

fn save_descriptions(d: &InterfaceDescriptions) {
    if let Ok(yaml) = serde_yaml::to_string(d) {
        let _ = fs::write(DESCRIPTIONS_PATH, &yaml);
    }
}

fn default_settings() -> ApplianceSettings {
    let hostname = fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "quickfw".to_string())
        .trim()
        .to_string();
    let timezone = Command::new("timedatectl")
        .args(["show", "--property=Timezone", "--value"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "UTC".to_string());
    let dns_servers = fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver ").map(|s| s.trim().to_string()))
        .collect();
    ApplianceSettings {
        hostname,
        timezone,
        ntp_servers: vec!["0.pool.ntp.org".to_string(), "1.pool.ntp.org".to_string()],
        dns_servers,
    }
}

fn read_sys_stat(iface: &str, stat: &str) -> u64 {
    fs::read_to_string(format!("/sys/class/net/{}/statistics/{}", iface, stat))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn get_ipv4_addrs(iface: &str) -> Vec<String> {
    Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.split_whitespace().nth(3).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_uptime() -> f64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(0.0)
}

fn parse_memory() -> (u64, u64, u64, f64) {
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total_kb: u64 = 0;
    let mut available_kb: u64 = 0;
    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = parse_meminfo_value(line);
        } else if line.starts_with("MemAvailable:") {
            available_kb = parse_meminfo_value(line);
        }
    }
    let total_mb = total_kb / 1024;
    let used_mb = total_kb.saturating_sub(available_kb) / 1024;
    let free_mb = available_kb / 1024;
    let pct = if total_kb > 0 {
        ((total_kb - available_kb) as f64 / total_kb as f64) * 100.0
    } else {
        0.0
    };
    (total_mb, used_mb, free_mb, pct)
}

fn parse_meminfo_value(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn parse_loadavg() -> (f64, f64, f64) {
    let s = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let p: Vec<&str> = s.split_whitespace().collect();
    (
        p.first().and_then(|v| v.parse().ok()).unwrap_or(0.0),
        p.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0),
        p.get(2).and_then(|v| v.parse().ok()).unwrap_or(0.0),
    )
}

fn parse_cpu_usage() -> f64 {
    let stat = fs::read_to_string("/proc/stat").unwrap_or_default();
    if let Some(cpu_line) = stat.lines().next() {
        let parts: Vec<u64> = cpu_line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse().ok())
            .collect();
        if parts.len() >= 4 {
            let total: u64 = parts.iter().sum();
            let idle = parts.get(3).copied().unwrap_or(0);
            if total > 0 {
                return ((total - idle) as f64 / total as f64) * 100.0;
            }
        }
    }
    0.0
}

fn get_boot_time() -> String {
    let uptime = parse_uptime();
    if uptime <= 0.0 {
        return "\u{2014}".to_string();
    }
    Command::new("date")
        .args([
            "-d",
            &format!("-{} seconds", uptime as u64),
            "+%Y-%m-%dT%H:%M:%SZ",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "\u{2014}".to_string())
}

// ===================================================================
// Handlers — Syslog Forwarding
// ===================================================================

#[derive(Serialize, Deserialize, Default)]
struct SyslogConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    server: String,
    #[serde(default = "default_syslog_port")]
    port: u16,
    #[serde(default = "default_syslog_protocol")]
    protocol: String,
    #[serde(default = "default_syslog_facility")]
    facility: String,
}

fn default_syslog_port() -> u16 {
    514
}
fn default_syslog_protocol() -> String {
    "udp".to_string()
}
fn default_syslog_facility() -> String {
    "local0".to_string()
}

async fn get_syslog_config() -> Json<SyslogConfig> {
    let config: SyslogConfig = fs::read_to_string(SYSLOG_CONFIG_PATH)
        .ok()
        .and_then(|s| serde_yaml::from_str(&s).ok())
        .unwrap_or_default();
    Json(config)
}

async fn save_syslog_config(
    Json(config): Json<SyslogConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate server address
    if config.enabled && config.server.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Syslog server address required when enabled"})),
        ));
    }
    if !config.server.is_empty() {
        // Validate as IP or hostname (simple check)
        if !config
            .server
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid syslog server address"})),
            ));
        }
    }
    if config.port == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Syslog port must be > 0"})),
        ));
    }
    match config.protocol.as_str() {
        "udp" | "tcp" => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Syslog protocol must be udp or tcp"})),
            ));
        }
    }

    let yaml = serde_yaml::to_string(&config).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Serialize: {}", e)})),
        )
    })?;
    fs::write(SYSLOG_CONFIG_PATH, &yaml).map_err(|e| {
        error!("Failed to write syslog config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Write: {}", e)})),
        )
    })?;

    info!(
        "Syslog config saved: server={}:{}, protocol={}, enabled={}",
        config.server, config.port, config.protocol, config.enabled
    );
    Ok(Json(serde_json::json!({"message": "Syslog config saved"})))
}
