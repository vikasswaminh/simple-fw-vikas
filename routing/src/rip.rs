//! RIP (Routing Information Protocol) implementation.
//!
//! RIP is a distance-vector routing protocol used for intra-domain routing.

use serde::{Deserialize, Serialize};

/// RIP configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RipConfig {
    /// Enable RIP on this router.
    #[serde(default)]
    pub enabled: bool,
    /// Router ID (IP address).
    #[serde(default)]
    pub router_id: Option<String>,
    /// Networks to advertise via RIP.
    #[serde(default)]
    pub networks: Vec<String>,
    /// Interfaces where RIP is enabled.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Passive interfaces (listen only, don't advertise).
    #[serde(default)]
    pub passive_interfaces: Vec<String>,
    /// Redistribute connected routes.
    #[serde(default)]
    pub redistribute_connected: bool,
    /// Redistribute static routes.
    #[serde(default)]
    pub redistribute_static: bool,
    /// Redistribute OSPF routes.
    #[serde(default)]
    pub redistribute_ospf: bool,
    /// Redistribute BGP routes.
    #[serde(default)]
    pub redistribute_bgp: bool,
    /// RIP version (1 or 2).
    #[serde(default = "default_version")]
    pub version: u8,
    /// poison reverse (enabled by default).
    #[serde(default = "default_true")]
    pub poison_reverse: bool,
    /// triggered updates (enabled by default).
    #[serde(default = "default_true")]
    pub triggered_updates: bool,
}

fn default_version() -> u8 {
    2
}

fn default_true() -> bool {
    true
}

/// Validate RIP configuration.
pub fn validate_rip_config(config: &RipConfig) -> Result<(), String> {
    if config.enabled {
        if config.router_id.is_none() {
            return Err("RIP router ID is required when enabled".to_string());
        }
        // Validate router_id is a valid IP
        if let Some(rid) = &config.router_id {
            if !rid.contains('.') {
                return Err("RIP router ID must be a valid IP address".to_string());
            }
        }
    }
    Ok(())
}

/// Generate FRR configuration for RIP.
pub fn generate_rip_frr(config: &RipConfig) -> String {
    if !config.enabled {
        return String::new();
    }

    let mut frr = String::new();
    frr.push_str("router rip\n");
    frr.push_str("  version 2\n");

    if let Some(rid) = &config.router_id {
        frr.push_str(&format!("  router-id {}\n", rid));
    }

    // Networks to advertise
    for net in &config.networks {
        frr.push_str(&format!("  network {}\n", net));
    }

    // Passive interfaces
    for iface in &config.passive_interfaces {
        frr.push_str(&format!("  passive-interface {}\n", iface));
    }

    // Redistribute
    if config.redistribute_connected {
        frr.push_str("  redistribute connected\n");
    }
    if config.redistribute_static {
        frr.push_str("  redistribute static\n");
    }
    if config.redistribute_ospf {
        frr.push_str("  redistribute ospf\n");
    }
    if config.redistribute_bgp {
        frr.push_str("  redistribute bgp\n");
    }

    if !config.poison_reverse {
        frr.push_str("  no poison-reverse\n");
    }
    if !config.triggered_updates {
        frr.push_str("  no triggered\n");
    }

    frr.push_str("exit\n");
    frr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rip_frr() {
        let config = RipConfig {
            enabled: true,
            router_id: Some("10.0.0.1".to_string()),
            networks: vec!["192.168.1.0/24".to_string()],
            redistribute_connected: true,
            ..Default::default()
        };

        let frr = generate_rip_frr(&config);
        assert!(frr.contains("router rip"));
        assert!(frr.contains("router-id 10.0.0.1"));
        assert!(frr.contains("network 192.168.1.0/24"));
    }

    #[test]
    fn test_validate_rip_config() {
        let mut config = RipConfig::default();
        assert!(validate_rip_config(&config).is_ok());

        config.enabled = true;
        config.router_id = Some("10.0.0.1".to_string());
        assert!(validate_rip_config(&config).is_ok());

        config.router_id = None;
        assert!(validate_rip_config(&config).is_err());
    }
}