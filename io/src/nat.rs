//! NAT/PAT management via nftables.
//!
//! Manages SNAT (masquerade) and DNAT (port forwarding) chains
//! within the existing `inet gfw_rs` nftables table.

use std::process::Command;

use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::nfqueue::{NFT_FAMILY, NFT_TABLE};

/// Top-level NAT configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatConfig {
    /// Config schema version — see io::firewall for migration notes.
    #[serde(default = "default_nat_schema_version")]
    pub schema_version: String,
    /// SNAT rules (masquerade outbound traffic on WAN).
    #[serde(default)]
    pub masquerade: Vec<MasqueradeRule>,
    /// DNAT rules (port forwarding from WAN to LAN hosts).
    #[serde(default)]
    pub port_forward: Vec<PortForwardRule>,
    /// Source NAT (static SNAT — translate source to specific IP).
    #[serde(default)]
    pub snat: Vec<SnatRule>,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            schema_version: default_nat_schema_version(),
            masquerade: Vec::new(),
            port_forward: Vec::new(),
            snat: Vec::new(),
        }
    }
}

fn default_nat_schema_version() -> String {
    "1.0".to_string()
}

/// Masquerade rule for SNAT — translates source addresses for outbound traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueradeRule {
    /// Outbound interface name (e.g., "eth0").
    pub out_interface: String,
    /// Source CIDR to masquerade (e.g., "192.168.1.0/24").
    pub source_cidr: String,
}

/// Source NAT rule — maps internal IP to specific external IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnatRule {
    /// Source network/CIDR to translate.
    pub source_cidr: String,
    /// Translated source IP address.
    pub to_address: String,
    /// Outbound interface (optional, for interface-based SNAT).
    #[serde(default)]
    pub out_interface: String,
}

/// Port forwarding rule for DNAT — redirects inbound traffic to a LAN host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardRule {
    /// Protocol: "tcp" or "udp".
    pub protocol: String,
    /// Destination port on the WAN interface.
    pub dest_port: u16,
    /// Forward target as "ip:port" (e.g., "192.168.1.100:8080").
    pub forward_to: String,
    /// Inbound interface name (e.g., "eth0").
    pub in_interface: String,
}

/// Generate nftables script for NAT chains.
///
/// These chains are added to the existing `inet gfw_rs` table
/// alongside the filter chains managed by `nfqueue.rs`.
fn generate_nat_nft_script(config: &NatConfig) -> String {
    let mut script = String::new();

    // We add chains to the existing table (created by nfqueue setup).
    // Using `add` so it doesn't fail if the table already exists.
    script.push_str(&format!("add table {} {}\n", NFT_FAMILY, NFT_TABLE));

    // POSTROUTING chain for SNAT/masquerade + static 1:1 SNAT.
    // Both feature types live in POSTROUTING — declare the chain once and
    // emit the rules for either type if present.
    let needs_postrouting = !config.masquerade.is_empty() || !config.snat.is_empty();
    if needs_postrouting {
        script.push_str(&format!(
            "add chain {} {} POSTROUTING {{ type nat hook postrouting priority srcnat; policy accept; }}\n",
            NFT_FAMILY, NFT_TABLE
        ));
        script.push_str(&format!(
            "flush chain {} {} POSTROUTING\n",
            NFT_FAMILY, NFT_TABLE
        ));
        for rule in &config.masquerade {
            if rule.source_cidr.is_empty() {
                script.push_str(&format!(
                    "add rule {} {} POSTROUTING oifname \"{}\" masquerade\n",
                    NFT_FAMILY, NFT_TABLE, rule.out_interface
                ));
            } else {
                script.push_str(&format!(
                    "add rule {} {} POSTROUTING oifname \"{}\" ip saddr {} masquerade\n",
                    NFT_FAMILY, NFT_TABLE, rule.out_interface, rule.source_cidr
                ));
            }
        }
        // Static 1:1 SNAT: translate a CIDR's source address to a fixed IP.
        // If out_interface is provided, scope the rule to that interface.
        for rule in &config.snat {
            if rule.out_interface.is_empty() {
                script.push_str(&format!(
                    "add rule {} {} POSTROUTING ip saddr {} snat ip to {}\n",
                    NFT_FAMILY, NFT_TABLE, rule.source_cidr, rule.to_address
                ));
            } else {
                script.push_str(&format!(
                    "add rule {} {} POSTROUTING oifname \"{}\" ip saddr {} snat ip to {}\n",
                    NFT_FAMILY, NFT_TABLE, rule.out_interface, rule.source_cidr, rule.to_address
                ));
            }
        }
    }

    // PREROUTING chain for DNAT/port forwarding
    if !config.port_forward.is_empty() {
        script.push_str(&format!(
            "add chain {} {} PREROUTING {{ type nat hook prerouting priority dstnat; policy accept; }}\n",
            NFT_FAMILY, NFT_TABLE
        ));
        script.push_str(&format!(
            "flush chain {} {} PREROUTING\n",
            NFT_FAMILY, NFT_TABLE
        ));
        for rule in &config.port_forward {
            script.push_str(&format!(
                "add rule {} {} PREROUTING iifname \"{}\" {} dport {} dnat ip to {}\n",
                NFT_FAMILY, NFT_TABLE, rule.in_interface, rule.protocol, rule.dest_port, rule.forward_to
            ));
        }
    }

    script
}

/// Apply NAT rules by generating and executing an nftables script.
pub fn apply_nat(config: &NatConfig) -> Result<(), Box<dyn std::error::Error>> {
    if config.masquerade.is_empty() && config.port_forward.is_empty() && config.snat.is_empty() {
        info!("No NAT rules configured, skipping");
        return Ok(());
    }

    let script = generate_nat_nft_script(config);
    info!("Applying NAT rules:\n{}", &script);

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(script.as_bytes())?;
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Failed to apply NAT rules: {}", stderr);
        return Err(format!("nft failed: {}", stderr).into());
    }

    info!("NAT rules applied successfully");
    Ok(())
}

/// Remove NAT chains from the nftables table.
pub fn remove_nat() -> Result<(), Box<dyn std::error::Error>> {
    // Delete NAT chains individually, not the whole table
    let chains = ["POSTROUTING", "PREROUTING"];
    for chain in &chains {
        let _ = Command::new("nft")
            .args(["delete", "chain", NFT_FAMILY, NFT_TABLE, chain])
            .output();
    }
    info!("NAT chains removed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nat_script_masquerade() {
        let config = NatConfig {
            schema_version: "1.0".to_string(),
            masquerade: vec![MasqueradeRule {
                out_interface: "eth0".to_string(),
                source_cidr: "192.168.1.0/24".to_string(),
            }],
            port_forward: vec![],
            snat: vec![],
        };
        let script = generate_nat_nft_script(&config);
        assert!(script.contains("POSTROUTING"));
        assert!(script.contains("masquerade"));
        assert!(script.contains("192.168.1.0/24"));
        assert!(script.contains("eth0"));
        assert!(!script.contains("PREROUTING"));
    }

    #[test]
    fn test_generate_nat_script_port_forward() {
        let config = NatConfig {
            schema_version: "1.0".to_string(),
            masquerade: vec![],
            port_forward: vec![PortForwardRule {
                protocol: "tcp".to_string(),
                dest_port: 8080,
                forward_to: "192.168.1.100:80".to_string(),
                in_interface: "eth0".to_string(),
            }],
            snat: vec![],
        };
        let script = generate_nat_nft_script(&config);
        assert!(script.contains("PREROUTING"));
        assert!(script.contains("dnat ip to 192.168.1.100:80"));
        assert!(script.contains("tcp dport 8080"));
    }

    #[test]
    fn test_generate_nat_script_static_snat() {
        let config = NatConfig {
            schema_version: "1.0".to_string(),
            masquerade: vec![],
            port_forward: vec![],
            snat: vec![SnatRule {
                source_cidr: "10.10.0.0/24".to_string(),
                to_address: "203.0.113.5".to_string(),
                out_interface: "eth0".to_string(),
            }],
        };
        let script = generate_nat_nft_script(&config);
        assert!(script.contains("POSTROUTING"));
        assert!(script.contains("snat ip to 203.0.113.5"));
        assert!(script.contains("ip saddr 10.10.0.0/24"));
        assert!(script.contains("oifname \"eth0\""));
    }

    #[test]
    fn test_generate_nat_script_empty() {
        let config = NatConfig::default();
        let script = generate_nat_nft_script(&config);
        assert!(!script.contains("POSTROUTING"));
        assert!(!script.contains("PREROUTING"));
    }

    #[test]
    fn test_generate_nat_script_both() {
        let config = NatConfig {
            schema_version: "1.0".to_string(),
            masquerade: vec![MasqueradeRule {
                out_interface: "wan0".to_string(),
                source_cidr: "10.0.0.0/8".to_string(),
            }],
            port_forward: vec![PortForwardRule {
                protocol: "udp".to_string(),
                dest_port: 53,
                forward_to: "10.0.0.2:53".to_string(),
                in_interface: "wan0".to_string(),
            }],
            snat: vec![],
        };
        let script = generate_nat_nft_script(&config);
        assert!(script.contains("POSTROUTING"));
        assert!(script.contains("PREROUTING"));
        assert!(script.contains("masquerade"));
        assert!(script.contains("dnat ip to 10.0.0.2:53"));
    }
}
