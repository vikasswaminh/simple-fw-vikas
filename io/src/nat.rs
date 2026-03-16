//! NAT/PAT management via nftables.
//!
//! Manages SNAT (masquerade) and DNAT (port forwarding) chains
//! within the existing `inet gfw_rs` nftables table.

use std::process::Command;

use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::nfqueue::{NFT_FAMILY, NFT_TABLE};

/// Top-level NAT configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NatConfig {
    /// SNAT rules (masquerade outbound traffic on WAN).
    #[serde(default)]
    pub masquerade: Vec<MasqueradeRule>,
    /// DNAT rules (port forwarding from WAN to LAN hosts).
    #[serde(default)]
    pub port_forward: Vec<PortForwardRule>,
}

/// Masquerade rule for SNAT — translates source addresses for outbound traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueradeRule {
    /// Outbound interface name (e.g., "eth0").
    pub out_interface: String,
    /// Source CIDR to masquerade (e.g., "192.168.1.0/24").
    pub source_cidr: String,
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

    // POSTROUTING chain for SNAT/masquerade
    if !config.masquerade.is_empty() {
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
    if config.masquerade.is_empty() && config.port_forward.is_empty() {
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
            masquerade: vec![MasqueradeRule {
                out_interface: "eth0".to_string(),
                source_cidr: "192.168.1.0/24".to_string(),
            }],
            port_forward: vec![],
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
            masquerade: vec![],
            port_forward: vec![PortForwardRule {
                protocol: "tcp".to_string(),
                dest_port: 8080,
                forward_to: "192.168.1.100:80".to_string(),
                in_interface: "eth0".to_string(),
            }],
        };
        let script = generate_nat_nft_script(&config);
        assert!(script.contains("PREROUTING"));
        assert!(script.contains("dnat to 192.168.1.100:80"));
        assert!(script.contains("tcp dport 8080"));
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
        };
        let script = generate_nat_nft_script(&config);
        assert!(script.contains("POSTROUTING"));
        assert!(script.contains("PREROUTING"));
        assert!(script.contains("masquerade"));
        assert!(script.contains("dnat to 10.0.0.2:53"));
    }
}
