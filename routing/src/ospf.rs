//! OSPF configuration and FRR config generation.

use serde::{Deserialize, Serialize};

const OSPF_CONFIG_PATH: &str = "/etc/quickfw/ospf.yaml";

/// Complete OSPF configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfConfig {
    /// Config schema version — see io::firewall for migration notes.
    #[serde(default = "default_ospf_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub router_id: String,
    #[serde(default)]
    pub networks: Vec<OspfNetwork>,
    #[serde(default)]
    pub areas: Vec<OspfArea>,
    #[serde(default)]
    pub passive_interfaces: Vec<String>,
    #[serde(default)]
    pub redistribute: Vec<String>,
    #[serde(default)]
    pub default_information_originate: bool,
    #[serde(default)]
    pub log_adjacency_changes: bool,
}

impl Default for OspfConfig {
    fn default() -> Self {
        Self {
            schema_version: default_ospf_schema_version(),
            enabled: false,
            router_id: String::new(),
            networks: Vec::new(),
            areas: Vec::new(),
            passive_interfaces: Vec::new(),
            redistribute: Vec::new(),
            default_information_originate: false,
            log_adjacency_changes: false,
        }
    }
}

fn default_ospf_schema_version() -> String {
    "1.0".to_string()
}

/// OSPF network statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfNetwork {
    pub prefix: String,
    pub area: u32,
}

/// OSPF area configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfArea {
    pub area_id: u32,
    #[serde(default)]
    pub area_type: String, // normal, stub, nssa
    #[serde(default)]
    pub authentication: Option<String>,
}

/// Load OSPF config from disk.
pub fn load_ospf_config() -> OspfConfig {
    match std::fs::read_to_string(OSPF_CONFIG_PATH) {
        Ok(contents) => match serde_yaml::from_str(&contents) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("Failed to parse OSPF config: {}", e);
                OspfConfig::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("No OSPF config found, using defaults");
            OspfConfig::default()
        }
        Err(e) => {
            tracing::error!("Failed to read OSPF config: {}", e);
            OspfConfig::default()
        }
    }
}

/// Save OSPF config to disk.
pub fn save_ospf_config(config: &OspfConfig) -> Result<(), Box<dyn std::error::Error>> {
    let yaml = serde_yaml::to_string(config)?;
    std::fs::write(OSPF_CONFIG_PATH, &yaml)?;
    Ok(())
}

/// Generate FRR OSPF section.
pub fn generate_ospf_frr(config: &OspfConfig) -> String {
    if !config.enabled {
        return String::new();
    }

    let mut frr = String::new();
    frr.push_str("router ospf\n");

    if !config.router_id.is_empty() {
        frr.push_str(&format!(" ospf router-id {}\n", config.router_id));
    }

    for net in &config.networks {
        frr.push_str(&format!(" network {} area {}\n", net.prefix, net.area));
    }

    for iface in &config.passive_interfaces {
        frr.push_str(&format!(" passive-interface {}\n", iface));
    }

    for area in &config.areas {
        match area.area_type.as_str() {
            "stub" => {
                frr.push_str(&format!(" area {} stub\n", area.area_id));
            }
            "nssa" => {
                frr.push_str(&format!(" area {} nssa\n", area.area_id));
            }
            _ => {}
        }
        if let Some(ref auth) = area.authentication {
            frr.push_str(&format!(" area {} authentication {}\n", area.area_id, auth));
        }
    }

    for r in &config.redistribute {
        frr.push_str(&format!(" redistribute {}\n", r));
    }

    if config.default_information_originate {
        frr.push_str(" default-information originate\n");
    }

    if config.log_adjacency_changes {
        frr.push_str(" log-adjacency-changes\n");
    }

    frr.push_str("!\n");
    frr
}

/// Validate OSPF configuration.
pub fn validate_ospf_config(config: &OspfConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }

    // Validate router-id format (must be IPv4 address)
    if !config.router_id.is_empty() {
        config.router_id.parse::<std::net::IpAddr>()
            .map_err(|_| format!("Invalid router-id: {}", config.router_id))?;
    }

    // Validate network prefixes
    for net in &config.networks {
        validate_cidr(&net.prefix)?;
    }

    // Validate area types
    for area in &config.areas {
        match area.area_type.as_str() {
            "" | "normal" | "stub" | "nssa" => {}
            _ => return Err(format!("Invalid area type: {}", area.area_type)),
        }
    }

    // Validate redistribute values
    for r in &config.redistribute {
        match r.as_str() {
            "connected" | "static" | "kernel" | "bgp" => {}
            _ => return Err(format!("Invalid redistribute: {}", r)),
        }
    }

    Ok(())
}

fn validate_cidr(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() || s == "any" {
        return Ok(());
    }
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        ip_str.parse::<std::net::IpAddr>()
            .map_err(|_| format!("Invalid IP in CIDR: {}", s))?;
        let prefix: u8 = prefix_str.parse()
            .map_err(|_| format!("Invalid prefix in CIDR: {}", s))?;
        if prefix > 32 {
            return Err(format!("Invalid prefix length: {}", prefix));
        }
    } else {
        s.parse::<std::net::IpAddr>()
            .map_err(|_| format!("Invalid IP address: {}", s))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ospf_disabled() {
        let config = OspfConfig::default();
        assert!(validate_ospf_config(&config).is_ok());
    }

    #[test]
    fn test_validate_ospf_valid() {
        let config = OspfConfig {
            enabled: true,
            router_id: "1.1.1.1".to_string(),
            networks: vec![
                OspfNetwork { prefix: "192.168.1.0/24".to_string(), area: 0 },
            ],
            ..Default::default()
        };
        assert!(validate_ospf_config(&config).is_ok());
    }

    #[test]
    fn test_validate_ospf_invalid_router_id() {
        let config = OspfConfig {
            enabled: true,
            router_id: "not-an-ip".to_string(),
            ..Default::default()
        };
        assert!(validate_ospf_config(&config).is_err());
    }

    #[test]
    fn test_generate_ospf_frr() {
        let config = OspfConfig {
            enabled: true,
            router_id: "1.1.1.1".to_string(),
            networks: vec![
                OspfNetwork { prefix: "192.168.1.0/24".to_string(), area: 0 },
                OspfNetwork { prefix: "10.0.0.0/8".to_string(), area: 1 },
            ],
            passive_interfaces: vec!["eth0".to_string()],
            default_information_originate: true,
            ..Default::default()
        };
        let frr = generate_ospf_frr(&config);
        assert!(frr.contains("router ospf"));
        assert!(frr.contains("ospf router-id 1.1.1.1"));
        assert!(frr.contains("network 192.168.1.0/24 area 0"));
        assert!(frr.contains("passive-interface eth0"));
        assert!(frr.contains("default-information originate"));
    }
}
