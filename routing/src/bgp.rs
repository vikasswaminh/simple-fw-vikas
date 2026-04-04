//! BGP configuration and FRR config generation.

use serde::{Deserialize, Serialize};

const BGP_CONFIG_PATH: &str = "/etc/quickfw/bgp.yaml";

/// Complete BGP configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BgpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub local_as: u32,
    #[serde(default)]
    pub router_id: String,
    #[serde(default)]
    pub neighbors: Vec<BgpNeighbor>,
    #[serde(default)]
    pub address_families: Vec<AddressFamily>,
    #[serde(default)]
    pub redistribute: Vec<String>,
}

/// BGP neighbor configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpNeighbor {
    pub address: String,
    pub remote_as: u32,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_keepalive")]
    pub timers_keepalive: u32,
    #[serde(default = "default_hold")]
    pub timers_hold: u32,
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub ebgp_multihop: Option<u32>,
    #[serde(default)]
    pub update_source: Option<String>,
}

fn default_keepalive() -> u32 { 60 }
fn default_hold() -> u32 { 180 }

/// BGP address family configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddressFamily {
    pub afi: String, // ipv4, ipv6
    #[serde(default = "default_safi")]
    pub safi: String, // unicast, multicast
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub neighbors: Vec<BgpNeighborAf>,
    #[serde(default = "default_max_paths")]
    pub maximum_paths: u32,
    #[serde(default)]
    pub redistribute: Vec<String>,
}

fn default_safi() -> String { "unicast".to_string() }
fn default_max_paths() -> u32 { 1 }

/// BGP neighbor address-family specific settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BgpNeighborAf {
    pub address: String,
    #[serde(default)]
    pub activate: bool,
    #[serde(default)]
    pub prefix_list_in: Option<String>,
    #[serde(default)]
    pub prefix_list_out: Option<String>,
    #[serde(default)]
    pub route_map_in: Option<String>,
    #[serde(default)]
    pub route_map_out: Option<String>,
    #[serde(default)]
    pub next_hop_self: bool,
    #[serde(default)]
    pub soft_reconfiguration: bool,
}

/// Load BGP config from disk.
pub fn load_bgp_config() -> BgpConfig {
    match std::fs::read_to_string(BGP_CONFIG_PATH) {
        Ok(contents) => match serde_yaml::from_str(&contents) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("Failed to parse BGP config: {}", e);
                BgpConfig::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("No BGP config found, using defaults");
            BgpConfig::default()
        }
        Err(e) => {
            tracing::error!("Failed to read BGP config: {}", e);
            BgpConfig::default()
        }
    }
}

/// Save BGP config to disk.
pub fn save_bgp_config(config: &BgpConfig) -> Result<(), Box<dyn std::error::Error>> {
    let yaml = serde_yaml::to_string(config)?;
    std::fs::write(BGP_CONFIG_PATH, &yaml)?;
    Ok(())
}

/// Generate FRR BGP section.
pub fn generate_bgp_frr(config: &BgpConfig) -> String {
    if !config.enabled || config.local_as == 0 {
        return String::new();
    }

    let mut frr = String::new();
    frr.push_str(&format!("router bgp {}\n", config.local_as));

    if !config.router_id.is_empty() {
        frr.push_str(&format!(" bgp router-id {}\n", config.router_id));
    }

    // Global neighbor definitions
    for nb in &config.neighbors {
        frr.push_str(&format!(" neighbor {} remote-as {}\n", nb.address, nb.remote_as));

        if let Some(ref desc) = nb.description {
            frr.push_str(&format!(" neighbor {} description {}\n", nb.address, desc));
        }

        if let Some(ref pw) = nb.password {
            frr.push_str(&format!(" neighbor {} password {}\n", nb.address, pw));
        }

        if nb.timers_keepalive != 60 || nb.timers_hold != 180 {
            frr.push_str(&format!(" neighbor {} timers {} {}\n", nb.address, nb.timers_keepalive, nb.timers_hold));
        }

        if nb.passive {
            frr.push_str(&format!(" neighbor {} passive\n", nb.address));
        }

        if let Some(hops) = nb.ebgp_multihop {
            frr.push_str(&format!(" neighbor {} ebgp-multihop {}\n", nb.address, hops));
        }

        if let Some(ref src) = nb.update_source {
            frr.push_str(&format!(" neighbor {} update-source {}\n", nb.address, src));
        }
    }

    // Global redistribute
    for r in &config.redistribute {
        frr.push_str(&format!(" redistribute {}\n", r));
    }

    // Address families
    for af in &config.address_families {
        frr.push_str(&format!(" address-family {} {}\n", af.afi, af.safi));

        for net in &af.networks {
            frr.push_str(&format!("  network {}\n", net));
        }

        for naf in &af.neighbors {
            if naf.activate {
                frr.push_str(&format!("  neighbor {} activate\n", naf.address));
            }

            if let Some(ref pl) = naf.prefix_list_in {
                frr.push_str(&format!("  neighbor {} prefix-list {} in\n", naf.address, pl));
            }
            if let Some(ref pl) = naf.prefix_list_out {
                frr.push_str(&format!("  neighbor {} prefix-list {} out\n", naf.address, pl));
            }

            if let Some(ref rm) = naf.route_map_in {
                frr.push_str(&format!("  neighbor {} route-map {} in\n", naf.address, rm));
            }
            if let Some(ref rm) = naf.route_map_out {
                frr.push_str(&format!("  neighbor {} route-map {} out\n", naf.address, rm));
            }

            if naf.next_hop_self {
                frr.push_str(&format!("  neighbor {} next-hop-self\n", naf.address));
            }

            if naf.soft_reconfiguration {
                frr.push_str(&format!("  neighbor {} soft-reconfiguration inbound\n", naf.address));
            }
        }

        if af.maximum_paths > 1 {
            frr.push_str(&format!("  maximum-paths {}\n", af.maximum_paths));
        }

        for r in &af.redistribute {
            frr.push_str(&format!("  redistribute {}\n", r));
        }

        frr.push_str(" exit-address-family\n");
    }

    frr.push_str("!\n");
    frr
}

/// Validate BGP configuration.
pub fn validate_bgp_config(config: &BgpConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }

    // Validate ASN
    if config.local_as == 0 {
        return Err("BGP local-as must be non-zero".to_string());
    }
    if config.local_as > 65535 {
        return Err(format!("Invalid ASN: {}", config.local_as));
    }

    // Validate router-id
    if !config.router_id.is_empty() {
        config.router_id.parse::<std::net::IpAddr>()
            .map_err(|_| format!("Invalid router-id: {}", config.router_id))?;
    }

    // Validate neighbors
    for nb in &config.neighbors {
        nb.address.parse::<std::net::IpAddr>()
            .map_err(|_| format!("Invalid neighbor address: {}", nb.address))?;

        if nb.remote_as == 0 {
            return Err(format!("Neighbor {} remote-as must be non-zero", nb.address));
        }

        if nb.timers_hold <= nb.timers_keepalive {
            return Err(format!("Neighbor {} hold timer must be greater than keepalive", nb.address));
        }
    }

    // Validate address families
    for af in &config.address_families {
        match af.afi.as_str() {
            "ipv4" | "ipv6" => {}
            _ => return Err(format!("Invalid AFI: {}", af.afi)),
        }
        match af.safi.as_str() {
            "unicast" | "multicast" => {}
            _ => return Err(format!("Invalid SAFI: {}", af.safi)),
        }

        for net in &af.networks {
            validate_cidr(net)?;
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
        if prefix > 128 {
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
    fn test_validate_bgp_disabled() {
        let config = BgpConfig::default();
        assert!(validate_bgp_config(&config).is_ok());
    }

    #[test]
    fn test_validate_bgp_valid() {
        let config = BgpConfig {
            enabled: true,
            local_as: 65001,
            router_id: "1.1.1.1".to_string(),
            neighbors: vec![
                BgpNeighbor {
                    address: "10.0.0.1".to_string(),
                    remote_as: 65002,
                    ..Default::default()
                },
            ],
            address_families: vec![
                AddressFamily {
                    afi: "ipv4".to_string(),
                    safi: "unicast".to_string(),
                    networks: vec!["192.168.0.0/16".to_string()],
                    neighbors: vec![
                        BgpNeighborAf {
                            address: "10.0.0.1".to_string(),
                            activate: true,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(validate_bgp_config(&config).is_ok());
    }

    #[test]
    fn test_validate_bgp_invalid_asn() {
        let config = BgpConfig {
            enabled: true,
            local_as: 0,
            ..Default::default()
        };
        assert!(validate_bgp_config(&config).is_err());
    }

    #[test]
    fn test_generate_bgp_frr() {
        let config = BgpConfig {
            enabled: true,
            local_as: 65001,
            router_id: "1.1.1.1".to_string(),
            neighbors: vec![
                BgpNeighbor {
                    address: "10.0.0.1".to_string(),
                    remote_as: 65002,
                    description: Some("Transit".to_string()),
                    ..Default::default()
                },
            ],
            address_families: vec![
                AddressFamily {
                    afi: "ipv4".to_string(),
                    safi: "unicast".to_string(),
                    networks: vec!["192.168.0.0/16".to_string()],
                    neighbors: vec![
                        BgpNeighborAf {
                            address: "10.0.0.1".to_string(),
                            activate: true,
                            ..Default::default()
                        },
                    ],
                    maximum_paths: 4,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let frr = generate_bgp_frr(&config);
        assert!(frr.contains("router bgp 65001"));
        assert!(frr.contains("bgp router-id 1.1.1.1"));
        assert!(frr.contains("neighbor 10.0.0.1 remote-as 65002"));
        assert!(frr.contains("neighbor 10.0.0.1 description Transit"));
        assert!(frr.contains("address-family ipv4 unicast"));
        assert!(frr.contains("network 192.168.0.0/16"));
        assert!(frr.contains("neighbor 10.0.0.1 activate"));
        assert!(frr.contains("maximum-paths 4"));
    }
}
