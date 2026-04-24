//! L3/L4 stateful firewall rule engine.
//!
//! Generates nftables chains (gfw_fw_input, gfw_fw_forward, gfw_fw_output)
//! inside the existing inet gfw_rs table. Separate from the DPI engine rules.

use std::io::Write;
use std::process::Command;

use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::nfqueue::{NFT_FAMILY, NFT_TABLE};

/// Sanitize a string for safe interpolation into nftables scripts.
/// Removes characters that could break nft syntax or inject commands,
/// and truncates to `max_len` characters.
fn sanitize_nft_string(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| *c != '"' && *c != '\n' && *c != '\r' && *c != '\\' && *c != ';' && *c != '{' && *c != '}')
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect()
}

/// Validate that a time string is strictly HH:MM format.
fn is_valid_time(s: &str) -> bool {
    if s.len() != 5 {
        return false;
    }
    let bytes = s.as_bytes();
    bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2] == b':'
        && bytes[3].is_ascii_digit()
        && bytes[4].is_ascii_digit()
}

/// Complete firewall policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Config schema version — used by the migration framework on load. Newer
    /// binaries refuse to load configs with a version they don't understand.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    #[serde(default = "default_deny")]
    pub forward_policy: String,
    #[serde(default = "default_deny")]
    pub input_policy: String,
    #[serde(default = "default_deny")]
    pub output_policy: String,
    #[serde(default)]
    pub zones: Vec<ZoneMapping>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            rules: Vec::new(),
            forward_policy: "drop".to_string(),
            input_policy: "drop".to_string(),
            output_policy: "drop".to_string(),
            zones: Vec::new(),
        }
    }
}

fn default_deny() -> String {
    "drop".to_string()
}

fn default_schema_version() -> String {
    "1.0".to_string()
}

fn default_rule_accept() -> String {
    "accept".to_string()
}

/// Maps a network interface to a security zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneMapping {
    pub interface: String,
    pub zone: String,
    #[serde(default)]
    pub role: String,
}

/// A single L3/L4 firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_forward")]
    pub direction: String,
    #[serde(default)]
    pub in_interface: String,
    #[serde(default)]
    pub out_interface: String,
    #[serde(default)]
    pub src_zone: String,
    #[serde(default)]
    pub dst_zone: String,
    #[serde(default = "default_any")]
    pub protocol: String,
    #[serde(default)]
    pub src_ip: String,
    #[serde(default)]
    pub src_port: String,
    #[serde(default)]
    pub dst_ip: String,
    #[serde(default)]
    pub dst_port: String,
    #[serde(default = "default_rule_accept")]
    pub action: String,
    #[serde(default)]
    pub log: bool,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub schedule: Option<RuleSchedule>,
    /// Apply rule to IPv6 (default: IPv4 only)
    #[serde(default)]
    pub ipv6: bool,
}

/// Time-based schedule for a firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSchedule {
    #[serde(default)]
    pub days: Vec<String>,
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub end: String,
}

fn default_true() -> bool {
    true
}
fn default_forward() -> String {
    "forward".to_string()
}
fn default_any() -> String {
    "any".to_string()
}

const FW_INPUT_CHAIN: &str = "gfw_fw_input";
const FW_FORWARD_CHAIN: &str = "gfw_fw_forward";
const FW_OUTPUT_CHAIN: &str = "gfw_fw_output";

const FW_CONFIG_PATH: &str = "/etc/quickfw/firewall.yaml";

/// Load firewall config from disk.
///
/// Returns default deny-all config if the file doesn't exist (first boot).
/// Returns an error if the file exists but fails to parse, so callers can
/// decide to abort or apply a safe fallback.
pub fn load_firewall_config() -> Result<FirewallConfig, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(FW_CONFIG_PATH) {
        Ok(contents) => match serde_yaml::from_str(&contents) {
            Ok(config) => Ok(config),
            Err(e) => {
                error!(
                    "Failed to parse firewall config at {}: {}. Refusing to load.",
                    FW_CONFIG_PATH, e
                );
                Err(format!("parse error: {}", e).into())
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("No firewall config found at {}, using safe defaults", FW_CONFIG_PATH);
            Ok(FirewallConfig::default())
        }
        Err(e) => {
            error!("Failed to read firewall config at {}: {}", FW_CONFIG_PATH, e);
            Err(format!("read error: {}", e).into())
        }
    }
}

/// Save firewall config to disk.
pub fn save_firewall_config(config: &FirewallConfig) -> Result<(), Box<dyn std::error::Error>> {
    let yaml = serde_yaml::to_string(config)?;
    std::fs::write(FW_CONFIG_PATH, &yaml)?;
    Ok(())
}

fn generate_rule_nft(rule: &FirewallRule, zones: &[ZoneMapping]) -> Vec<String> {
    if !rule.enabled {
        return vec![];
    }

    let in_ifaces = resolve_zone_ifaces(&rule.in_interface, &rule.src_zone, zones);
    let out_ifaces = resolve_zone_ifaces(&rule.out_interface, &rule.dst_zone, zones);

    let chain = match rule.direction.as_str() {
        "input" => FW_INPUT_CHAIN,
        "output" => FW_OUTPUT_CHAIN,
        _ => FW_FORWARD_CHAIN,
    };

    let mut base_parts: Vec<String> = Vec::new();

    let protos = match rule.protocol.as_str() {
        "tcp" => vec!["tcp"],
        "udp" => vec!["udp"],
        "icmp" => vec!["icmp"],
        "tcp+udp" => vec!["tcp", "udp"],
        _ => vec![],
    };

    if let Some(ref s) = normalize_addr(&rule.src_ip) {
        base_parts.push(format!("ip saddr {}", s));
    }
    if let Some(ref d) = normalize_addr(&rule.dst_ip) {
        base_parts.push(format!("ip daddr {}", d));
    }

    let action_nft = match rule.action.as_str() {
        "drop" => "drop",
        "reject" => "reject",
        "log" => "log accept",
        _ => "accept",
    };

    let log_prefix = if rule.log {
        format!(
            "log prefix \"gfw:{}\" ",
            sanitize_nft_string(&rule.name, 16)
        )
    } else {
        String::new()
    };

    let comment_str = if !rule.name.is_empty() {
        format!(
            " comment \"{}\"",
            sanitize_nft_string(&rule.name, 32)
        )
    } else {
        String::new()
    };

    let proto_list: Vec<Option<&str>> = if protos.is_empty() {
        vec![None]
    } else {
        protos.iter().map(|p| Some(*p)).collect()
    };
    let in_list: Vec<Option<&str>> = if in_ifaces.is_empty() {
        vec![None]
    } else {
        in_ifaces.iter().map(|i| Some(i.as_str())).collect()
    };
    let out_list: Vec<Option<&str>> = if out_ifaces.is_empty() {
        vec![None]
    } else {
        out_ifaces.iter().map(|i| Some(i.as_str())).collect()
    };

    let mut lines = Vec::new();

    for proto in &proto_list {
        for in_if in &in_list {
            for out_if in &out_list {
                let mut parts = Vec::new();

                if let Some(iif) = in_if {
                    parts.push(format!("iifname \"{}\"", iif));
                }
                if let Some(oif) = out_if {
                    parts.push(format!("oifname \"{}\"", oif));
                }
                if let Some(p) = proto {
                    parts.push(format!("meta l4proto {}", p));
                }

                parts.extend(base_parts.iter().cloned());

                if proto.map(|p| p == "tcp" || p == "udp").unwrap_or(false) {
                    if let Some(sp) = normalize_port(&rule.src_port) {
                        parts.push(format!("{} sport {}", proto.unwrap(), sp));
                    }
                    if let Some(dp) = normalize_port(&rule.dst_port) {
                        parts.push(format!("{} dport {}", proto.unwrap(), dp));
                    }
                }

                // Schedule constraints (time-based rules)
                if let Some(ref sched) = rule.schedule {
                    if !sched.days.is_empty() {
                        let day_map: Vec<&str> = sched
                            .days
                            .iter()
                            .filter_map(|d| match d.to_lowercase().as_str() {
                                "mon" | "monday" => Some("Monday"),
                                "tue" | "tuesday" => Some("Tuesday"),
                                "wed" | "wednesday" => Some("Wednesday"),
                                "thu" | "thursday" => Some("Thursday"),
                                "fri" | "friday" => Some("Friday"),
                                "sat" | "saturday" => Some("Saturday"),
                                "sun" | "sunday" => Some("Sunday"),
                                _ => None,
                            })
                            .collect();
                        if !day_map.is_empty() {
                            parts.push(format!(
                                "meta day {{ {} }}",
                                day_map.join(", ")
                            ));
                        }
                    }
                    if !sched.start.is_empty() && !sched.end.is_empty()
                        && is_valid_time(&sched.start) && is_valid_time(&sched.end)
                    {
                        parts.push(format!(
                            "meta hour \"{}\"-\"{}\"",
                            sched.start, sched.end
                        ));
                    }
                }

                // nftables order: match → counter → log → action
                parts.push("counter".to_string());
                if !log_prefix.is_empty() {
                    parts.push(log_prefix.clone());
                }
                parts.push(action_nft.to_string());

                lines.push(format!(
                    "add rule {} {} {} {}{}",
                    NFT_FAMILY,
                    NFT_TABLE,
                    chain,
                    parts.join(" "),
                    comment_str
                ));
            }
        }
    }

    lines
}

fn resolve_zone_ifaces(iface: &str, zone: &str, zones: &[ZoneMapping]) -> Vec<String> {
    let iface = iface.trim();
    let zone = zone.trim();

    if !iface.is_empty() && iface != "any" {
        return vec![iface.to_string()];
    }

    if !zone.is_empty() && zone != "any" {
        let matched: Vec<String> = zones
            .iter()
            .filter(|z| z.zone.eq_ignore_ascii_case(zone) || z.role.eq_ignore_ascii_case(zone))
            .map(|z| z.interface.clone())
            .collect();
        if !matched.is_empty() {
            return matched;
        }
    }

    vec![]
}

fn normalize_addr(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s == "any" || s == "0.0.0.0/0" || s == "*" {
        None
    } else {
        Some(s.to_string())
    }
}

fn normalize_port(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s == "any" || s == "*" || s == "0" {
        None
    } else if s.contains(',') {
        let formatted = s
            .split(',')
            .map(|p| p.trim())
            .collect::<Vec<_>>()
            .join(", ");
        Some(format!("{{ {} }}", formatted))
    } else {
        Some(s.to_string())
    }
}

/// Generate the complete nftables script for all firewall rules.
pub fn generate_firewall_nft_script(config: &FirewallConfig) -> String {
    let mut script = String::new();

    script.push_str(&format!("add table {} {}\n", NFT_FAMILY, NFT_TABLE));

    // Create firewall chains at priority -10 (before DPI queue at priority 0).
    script.push_str(&format!(
        "add chain {} {} {} {{ type filter hook input priority -10; policy {}; }}\n",
        NFT_FAMILY, NFT_TABLE, FW_INPUT_CHAIN, config.input_policy
    ));
    script.push_str(&format!(
        "add chain {} {} {} {{ type filter hook forward priority -10; policy {}; }}\n",
        NFT_FAMILY, NFT_TABLE, FW_FORWARD_CHAIN, config.forward_policy
    ));
    script.push_str(&format!(
        "add chain {} {} {} {{ type filter hook output priority -10; policy {}; }}\n",
        NFT_FAMILY, NFT_TABLE, FW_OUTPUT_CHAIN, config.output_policy
    ));

    // Flush existing rules in firewall chains.
    for chain in [FW_INPUT_CHAIN, FW_FORWARD_CHAIN, FW_OUTPUT_CHAIN] {
        script.push_str(&format!(
            "flush chain {} {} {}\n",
            NFT_FAMILY, NFT_TABLE, chain
        ));
    }

    // MGMT_SAFETY bypass: packets marked 0x1 by MGMT_SAFETY chain are always accepted.
    // This ensures management access (SSH, HTTPS, ICMP) survives firewall rule changes.
    for chain in [FW_INPUT_CHAIN, FW_FORWARD_CHAIN, FW_OUTPUT_CHAIN] {
        script.push_str(&format!(
            "add rule {} {} {} meta mark 0x1 accept\n",
            NFT_FAMILY, NFT_TABLE, chain
        ));
    }

    // Stateful: allow established/related, drop invalid.
    for chain in [FW_INPUT_CHAIN, FW_FORWARD_CHAIN, FW_OUTPUT_CHAIN] {
        script.push_str(&format!(
            "add rule {} {} {} ct state established,related accept\n",
            NFT_FAMILY, NFT_TABLE, chain
        ));
        script.push_str(&format!(
            "add rule {} {} {} ct state invalid drop\n",
            NFT_FAMILY, NFT_TABLE, chain
        ));
    }

    // Allow loopback and ICMP on input.
    script.push_str(&format!(
        "add rule {} {} {} iifname \"lo\" accept\n",
        NFT_FAMILY, NFT_TABLE, FW_INPUT_CHAIN
    ));
    script.push_str(&format!(
        "add rule {} {} {} meta l4proto icmp accept\n",
        NFT_FAMILY, NFT_TABLE, FW_INPUT_CHAIN
    ));

    // User rules.
    for rule in &config.rules {
        for line in generate_rule_nft(rule, &config.zones) {
            script.push_str(&line);
            script.push('\n');
        }
    }

    script
}

/// Snapshot the current nftables ruleset to a temp file.
fn snapshot_nft_ruleset() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .output()?;

    if !output.status.success() {
        return Err("nft list ruleset failed".into());
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = std::path::PathBuf::from(format!("/tmp/nft-rollback-{}.nft", timestamp));
    std::fs::write(&path, &output.stdout)?;
    Ok(path)
}

/// Restore nftables ruleset from a snapshot file.
fn restore_nft_ruleset(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("nft")
        .args(["-f", &path.to_string_lossy()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nft restore failed: {}", stderr).into());
    }

    Ok(())
}

/// Apply a hardcoded emergency ruleset that keeps management access open.
fn apply_emergency_mgmt_ruleset() -> Result<(), Box<dyn std::error::Error>> {
    let emergency = format!(
        "table {} {} {{
  chain MGMT_SAFETY {{
    type filter hook input priority 100; policy accept;
    tcp dport {{ 22, 443, 3000 }} accept
    icmp type echo-request accept
  }}
}}\n",
        NFT_FAMILY, NFT_TABLE
    );

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(emergency.as_bytes())?;
    }

    let result = child.wait_with_output()?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(format!("Emergency ruleset failed: {}", stderr).into());
    }

    Ok(())
}

/// Apply firewall rules.
///
/// Snapshots the existing ruleset before applying. If the new ruleset fails,
/// automatically restores the snapshot. If restore also fails, applies a
/// minimal emergency management-access ruleset as a last resort.
pub fn apply_firewall(config: &FirewallConfig) -> Result<(), Box<dyn std::error::Error>> {
    let script = generate_firewall_nft_script(config);
    info!(
        "Applying firewall rules ({} rules):\n{}",
        config.rules.len(),
        &script
    );

    // Snapshot current ruleset for rollback
    let snapshot_path = match snapshot_nft_ruleset() {
        Ok(path) => Some(path),
        Err(e) => {
            error!("Failed to snapshot nftables ruleset: {}. Proceeding without rollback.", e);
            None
        }
    };

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(script.as_bytes())?;
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Failed to apply firewall rules: {}", stderr);

        // Attempt rollback
        if let Some(ref path) = snapshot_path {
            info!("Attempting rollback from {}", path.display());
            if let Err(restore_err) = restore_nft_ruleset(path) {
                error!("Rollback failed: {}. Applying emergency ruleset.", restore_err);
                if let Err(e) = apply_emergency_mgmt_ruleset() {
                    error!("Emergency ruleset also failed: {}", e);
                }
            } else {
                info!("Rollback successful");
            }
        }

        return Err(format!("nft failed: {}", stderr).into());
    }

    // Clean up snapshot on success (keep last 10)
    if let Some(path) = snapshot_path {
        let _ = std::fs::remove_file(&path);
        prune_rollback_files();
    }

    info!("Firewall rules applied successfully");
    Ok(())
}

/// Keep only the last 10 rollback snapshot files.
fn prune_rollback_files() {
    let mut files: Vec<_> = match std::fs::read_dir("/tmp") {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("nft-rollback-") && name.ends_with(".nft") {
                    e.metadata().ok().map(|m| (e.path(), m.modified().ok()))
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => return,
    };

    files.sort_by(|a, b| b.1.cmp(&a.1)); // newest first

    for (path, _) in files.iter().skip(10) {
        let _ = std::fs::remove_file(path);
    }
}

/// Remove firewall chains.
pub fn remove_firewall() -> Result<(), Box<dyn std::error::Error>> {
    for chain in [FW_INPUT_CHAIN, FW_FORWARD_CHAIN, FW_OUTPUT_CHAIN] {
        let _ = Command::new("nft")
            .args(["delete", "chain", NFT_FAMILY, NFT_TABLE, chain])
            .output();
    }
    info!("Firewall chains removed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_config_default_is_deny() {
        let config = FirewallConfig::default();
        assert_eq!(config.input_policy, "drop");
        assert_eq!(config.forward_policy, "drop");
        assert_eq!(config.output_policy, "drop");
        assert!(config.rules.is_empty());
        assert!(config.zones.is_empty());
    }

    #[test]
    fn firewall_config_deserialize_missing_policies_defaults_to_deny() {
        let yaml = "rules: []\n";
        let config: FirewallConfig = serde_yaml::from_str(yaml).expect("should parse");
        assert_eq!(config.input_policy, "drop");
        assert_eq!(config.forward_policy, "drop");
        assert_eq!(config.output_policy, "drop");
    }

    #[test]
    fn firewall_config_deserialize_rule_action_defaults_to_accept() {
        let yaml = r#"
rules:
  - name: test
"#;
        let config: FirewallConfig = serde_yaml::from_str(yaml).expect("should parse");
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].action, "accept");
    }

    #[test]
    fn firewall_config_deserialize_malformed_yaml_fails() {
        let yaml = "rules: [not_valid_yaml: :::";
        let result: Result<FirewallConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "Malformed YAML should fail to parse");
    }

}
