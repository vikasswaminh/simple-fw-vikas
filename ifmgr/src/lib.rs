//! Network interface manager for gfw-rs firewall appliance.
//!
//! Provides interface detection, WAN/LAN configuration,
//! and dnsmasq config generation for DHCP/DNS on the LAN.

use std::fs;
use std::process::Command;

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

/// Information about a detected network interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "eth0", "ens33").
    pub name: String,
    /// MAC address.
    pub mac: String,
    /// Whether the link is up.
    pub link_up: bool,
    /// IPv4 addresses assigned to this interface.
    pub ipv4_addrs: Vec<String>,
}

/// Zone assignment for an interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Zone {
    Wan,
    Lan,
}

/// WAN address mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WanMode {
    Dhcp,
    Static,
}

impl Default for WanMode {
    fn default() -> Self {
        WanMode::Dhcp
    }
}

/// WAN interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanConfig {
    /// Interface name.
    pub interface: String,
    /// Address mode: DHCP or static.
    #[serde(default)]
    pub mode: WanMode,
    /// Static IP address with CIDR (e.g., "203.0.113.10/24"). Required if mode is Static.
    pub address: Option<String>,
    /// Default gateway. Required if mode is Static.
    pub gateway: Option<String>,
    /// DNS servers.
    #[serde(default)]
    pub dns: Vec<String>,
}

/// LAN interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanConfig {
    /// Interface name.
    pub interface: String,
    /// Static IP address with CIDR (e.g., "192.168.1.1/24").
    pub address: String,
    /// DHCP range as "start,end" (e.g., "192.168.1.100,192.168.1.200").
    pub dhcp_range: Option<String>,
}

/// Complete appliance network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplianceNetConfig {
    pub wan: WanConfig,
    pub lan: LanConfig,
}

/// List all non-loopback network interfaces by reading /sys/class/net/.
pub fn list_interfaces() -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();

    let net_dir = match fs::read_dir("/sys/class/net") {
        Ok(dir) => dir,
        Err(e) => {
            error!("Failed to read /sys/class/net: {}", e);
            return interfaces;
        }
    };

    for entry in net_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip loopback
        if name == "lo" {
            continue;
        }

        let mac = read_sys_file(&format!("/sys/class/net/{}/address", name))
            .unwrap_or_default()
            .trim()
            .to_string();

        let operstate = read_sys_file(&format!("/sys/class/net/{}/operstate", name))
            .unwrap_or_default();
        let link_up = operstate.trim() == "up";

        // Get IPv4 addresses via `ip addr show`
        let ipv4_addrs = get_ipv4_addrs(&name);

        interfaces.push(InterfaceInfo {
            name,
            mac,
            link_up,
            ipv4_addrs,
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

/// Apply the appliance network configuration.
pub fn apply_interface_config(config: &ApplianceNetConfig) -> Result<(), Box<dyn std::error::Error>> {
    info!("Applying network configuration...");

    // --- LAN interface ---
    info!("Configuring LAN interface: {}", config.lan.interface);

    // Bring up the interface
    run_cmd("ip", &["link", "set", &config.lan.interface, "up"])?;

    // Flush existing addresses
    run_cmd("ip", &["addr", "flush", "dev", &config.lan.interface])?;

    // Set static IP
    run_cmd("ip", &["addr", "add", &config.lan.address, "dev", &config.lan.interface])?;

    // --- WAN interface ---
    info!("Configuring WAN interface: {}", config.wan.interface);

    // Bring up the interface
    run_cmd("ip", &["link", "set", &config.wan.interface, "up"])?;

    match config.wan.mode {
        WanMode::Dhcp => {
            info!("Starting DHCP client on {}", config.wan.interface);
            // Kill any existing dhclient for this interface
            let _ = Command::new("pkill")
                .args(["-f", &format!("dhclient.*{}", config.wan.interface)])
                .output();
            // Start dhclient
            let output = Command::new("dhclient")
                .args(["-v", &config.wan.interface])
                .output()?;
            if !output.status.success() {
                warn!(
                    "dhclient returned non-zero: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        WanMode::Static => {
            // Flush existing addresses
            run_cmd("ip", &["addr", "flush", "dev", &config.wan.interface])?;

            if let Some(ref addr) = config.wan.address {
                run_cmd("ip", &["addr", "add", addr, "dev", &config.wan.interface])?;
            }

            if let Some(ref gw) = config.wan.gateway {
                // Remove existing default route and add new one
                let _ = Command::new("ip")
                    .args(["route", "del", "default"])
                    .output();
                run_cmd("ip", &["route", "add", "default", "via", gw, "dev", &config.wan.interface])?;
            }

            // Set DNS
            if !config.wan.dns.is_empty() {
                let resolv: String = config
                    .wan
                    .dns
                    .iter()
                    .map(|d| format!("nameserver {}\n", d))
                    .collect();
                fs::write("/etc/resolv.conf", resolv)?;
            }
        }
    }

    // Enable IP forwarding
    fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| format!("Failed to enable IPv4 forwarding: {}", e))?;
    fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        .map_err(|e| format!("Failed to enable IPv6 forwarding: {}", e))?;

    info!("Network configuration applied successfully");
    Ok(())
}

/// Generate dnsmasq configuration for DHCP/DNS on the LAN interface.
pub fn generate_dnsmasq_config(lan: &LanConfig) -> String {
    let mut config = String::new();

    config.push_str(&format!("# gfw-rs LAN DHCP/DNS configuration\n"));
    config.push_str(&format!("interface={}\n", lan.interface));
    config.push_str("bind-interfaces\n");

    // Extract the IP (without CIDR) for listen-address
    let listen_ip = lan.address.split('/').next().unwrap_or("192.168.1.1");
    config.push_str(&format!("listen-address={}\n", listen_ip));

    // DHCP range
    if let Some(ref range) = lan.dhcp_range {
        config.push_str(&format!("dhcp-range={},12h\n", range));
    }

    // Set this firewall as the gateway for DHCP clients
    config.push_str(&format!("dhcp-option=3,{}\n", listen_ip));
    // Set this firewall as the DNS server for DHCP clients
    config.push_str(&format!("dhcp-option=6,{}\n", listen_ip));

    // DNS forwarding (use system resolv.conf)
    config.push_str("no-resolv\n");
    config.push_str("server=8.8.8.8\n");
    config.push_str("server=1.1.1.1\n");

    config
}

/// Save the appliance network config to a YAML file.
pub fn save_config(config: &ApplianceNetConfig, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let yaml = serde_yaml::to_string(config)?;
    fs::write(path, yaml)?;
    Ok(())
}

/// Load the appliance network config from a YAML file.
pub fn load_config(path: &str) -> Result<ApplianceNetConfig, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let config: ApplianceNetConfig = serde_yaml::from_str(&contents)?;
    Ok(config)
}

// --- Helper functions ---

fn read_sys_file(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn get_ipv4_addrs(iface: &str) -> Vec<String> {
    let output = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output()
        .ok();

    match output {
        Some(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout
                .lines()
                .filter_map(|line| {
                    // Format: "2: eth0    inet 192.168.1.1/24 brd ..."
                    line.split_whitespace()
                        .nth(3)
                        .map(|s| s.to_string())
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(cmd).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{} {} failed: {}", cmd, args.join(" "), stderr).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dnsmasq_config() {
        let lan = LanConfig {
            interface: "eth1".to_string(),
            address: "192.168.1.1/24".to_string(),
            dhcp_range: Some("192.168.1.100,192.168.1.200".to_string()),
        };
        let config = generate_dnsmasq_config(&lan);
        assert!(config.contains("interface=eth1"));
        assert!(config.contains("listen-address=192.168.1.1"));
        assert!(config.contains("dhcp-range=192.168.1.100,192.168.1.200,12h"));
        assert!(config.contains("dhcp-option=3,192.168.1.1"));
        assert!(config.contains("dhcp-option=6,192.168.1.1"));
    }

    #[test]
    fn test_generate_dnsmasq_config_no_dhcp() {
        let lan = LanConfig {
            interface: "lan0".to_string(),
            address: "10.0.0.1/24".to_string(),
            dhcp_range: None,
        };
        let config = generate_dnsmasq_config(&lan);
        assert!(config.contains("interface=lan0"));
        assert!(config.contains("listen-address=10.0.0.1"));
        assert!(!config.contains("dhcp-range"));
    }
}
