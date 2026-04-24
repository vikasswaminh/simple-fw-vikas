//! Input validation for all user-supplied fields that reach nftables or system commands.
//!
//! Every field that gets interpolated into nft scripts MUST pass through one of these
//! validators before use. This prevents nftables injection attacks.

use std::net::IpAddr;

use regex::Regex;
use std::sync::LazyLock;

static IFACE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9._\-]{1,15}$").unwrap());
static RULE_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9 _\-]{0,64}$").unwrap());
static ZONE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-]{0,32}$").unwrap());

/// Validate an interface name (e.g., "eth0", "wg0", "br-lan").
pub fn validate_interface(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() || s == "any" {
        return Ok(()); // empty/any means "match all", no injection risk
    }
    if !IFACE_RE.is_match(s) {
        return Err(format!(
            "Invalid interface name '{}': must be 1-15 alphanumeric/._- characters",
            s
        ));
    }
    Ok(())
}

/// Validate an IP address (v4 or v6, no CIDR).
pub fn validate_ip(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() || s == "any" || s == "*" || s == "0.0.0.0/0" {
        return Ok(());
    }
    // Could be a single IP or CIDR — handle both
    validate_cidr(s)
}

/// Validate a CIDR notation address (e.g., "192.168.1.0/24" or plain IP "10.0.0.1").
pub fn validate_cidr(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() || s == "any" || s == "*" || s == "0.0.0.0/0" {
        return Ok(());
    }

    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| format!("Invalid IP address in CIDR '{}'", s))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| format!("Invalid prefix length in CIDR '{}'", s))?;
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(format!(
                "Prefix length {} exceeds maximum {} for '{}'",
                prefix, max_prefix, s
            ));
        }
    } else {
        // Plain IP address
        s.parse::<IpAddr>()
            .map_err(|_| format!("Invalid IP address '{}'", s))?;
    }
    Ok(())
}

/// Validate a port number or port list (e.g., "80", "443", "80,443", "1024-65535").
pub fn validate_port(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() || s == "any" || s == "*" || s == "0" {
        return Ok(());
    }

    // Support comma-separated ports and ranges
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range start '{}' in '{}'", start, s))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range end '{}' in '{}'", end, s))?;
            if start == 0 || end == 0 {
                return Err(format!("Port 0 is not valid in '{}'", s));
            }
            if start > end {
                return Err(format!("Port range start > end in '{}'", s));
            }
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port number '{}' in '{}'", part, s))?;
            if port == 0 {
                return Err(format!("Port 0 is not valid in '{}'", s));
            }
        }
    }
    Ok(())
}

/// Validate a protocol field.
pub fn validate_protocol(s: &str) -> Result<(), String> {
    let s = s.trim().to_lowercase();
    match s.as_str() {
        "" | "any" | "tcp" | "udp" | "icmp" | "tcp+udp" => Ok(()),
        _ => Err(format!(
            "Invalid protocol '{}': must be tcp, udp, icmp, tcp+udp, or any",
            s
        )),
    }
}

/// Validate a firewall action.
pub fn validate_action(s: &str) -> Result<(), String> {
    let s = s.trim().to_lowercase();
    match s.as_str() {
        "" | "accept" | "drop" | "reject" | "log" => Ok(()),
        _ => Err(format!(
            "Invalid action '{}': must be accept, drop, reject, or log",
            s
        )),
    }
}

/// Validate a firewall rule name.
pub fn validate_rule_name(s: &str) -> Result<(), String> {
    if !RULE_NAME_RE.is_match(s) {
        return Err(format!(
            "Invalid rule name '{}': must be 0-64 alphanumeric/space/_- characters",
            s
        ));
    }
    Ok(())
}

/// Validate a direction field.
pub fn validate_direction(s: &str) -> Result<(), String> {
    let s = s.trim().to_lowercase();
    match s.as_str() {
        "" | "forward" | "input" | "output" => Ok(()),
        _ => Err(format!(
            "Invalid direction '{}': must be forward, input, or output",
            s
        )),
    }
}

/// Validate a zone name.
pub fn validate_zone(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() || s == "any" {
        return Ok(());
    }
    if !ZONE_RE.is_match(s) {
        return Err(format!(
            "Invalid zone name '{}': must be 1-32 alphanumeric/_- characters",
            s
        ));
    }
    Ok(())
}

/// Validate a forward_to field for DNAT (e.g., "192.168.1.100:8080").
pub fn validate_forward_to(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("forward_to cannot be empty".to_string());
    }
    // Must be ip:port
    if let Some((ip_str, port_str)) = s.rsplit_once(':') {
        ip_str
            .parse::<IpAddr>()
            .map_err(|_| format!("Invalid IP in forward_to '{}'", s))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port in forward_to '{}'", s))?;
        if port == 0 {
            return Err(format!("Port 0 is not valid in forward_to '{}'", s));
        }
        Ok(())
    } else {
        Err(format!(
            "forward_to '{}' must be in ip:port format",
            s
        ))
    }
}

/// Validate a firewall policy (accept or drop).
pub fn validate_policy(s: &str) -> Result<(), String> {
    let s = s.trim().to_lowercase();
    match s.as_str() {
        "accept" | "drop" => Ok(()),
        _ => Err(format!(
            "Invalid policy '{}': must be accept or drop",
            s
        )),
    }
}

/// Validate a rule schedule.
pub fn validate_schedule(
    sched: &gfw_io::firewall::RuleSchedule,
) -> Result<(), String> {
    let valid_days = [
        "mon", "tue", "wed", "thu", "fri", "sat", "sun",
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    ];
    for day in &sched.days {
        if !valid_days.contains(&day.to_lowercase().as_str()) {
            return Err(format!("Invalid schedule day: '{}'", day));
        }
    }
    // Validate time format HH:MM
    for t in [&sched.start, &sched.end] {
        if t.is_empty() {
            continue;
        }
        let parts: Vec<&str> = t.split(':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid time format '{}': must be HH:MM", t));
        }
        let hour: u8 = parts[0]
            .parse()
            .map_err(|_| format!("Invalid hour in '{}'", t))?;
        let min: u8 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid minute in '{}'", t))?;
        if hour > 23 || min > 59 {
            return Err(format!("Time '{}' out of range (00:00-23:59)", t));
        }
    }
    Ok(())
}

/// Validate an entire FirewallRule's user-supplied fields.
pub fn validate_firewall_rule(rule: &gfw_io::firewall::FirewallRule) -> Result<(), String> {
    validate_rule_name(&rule.name)?;
    validate_direction(&rule.direction)?;
    validate_interface(&rule.in_interface)?;
    validate_interface(&rule.out_interface)?;
    validate_zone(&rule.src_zone)?;
    validate_zone(&rule.dst_zone)?;
    validate_protocol(&rule.protocol)?;
    validate_ip(&rule.src_ip)?;
    validate_port(&rule.src_port)?;
    validate_ip(&rule.dst_ip)?;
    validate_port(&rule.dst_port)?;
    validate_action(&rule.action)?;
    if let Some(ref sched) = rule.schedule {
        validate_schedule(sched)?;
    }
    Ok(())
}

/// Validate an entire FirewallConfig.
pub fn validate_firewall_config(config: &gfw_io::firewall::FirewallConfig) -> Result<(), String> {
    validate_policy(&config.forward_policy)?;
    validate_policy(&config.input_policy)?;
    validate_policy(&config.output_policy)?;
    for rule in &config.rules {
        validate_firewall_rule(rule)?;
    }
    for zone in &config.zones {
        validate_interface(&zone.interface)?;
        validate_zone(&zone.zone)?;
    }
    Ok(())
}

/// Validate a MasqueradeRule.
pub fn validate_masquerade_rule(rule: &gfw_io::nat::MasqueradeRule) -> Result<(), String> {
    validate_interface(&rule.out_interface)?;
    validate_cidr(&rule.source_cidr)?;
    Ok(())
}

/// Validate a PortForwardRule.
pub fn validate_port_forward_rule(rule: &gfw_io::nat::PortForwardRule) -> Result<(), String> {
    validate_interface(&rule.in_interface)?;
    validate_protocol(&rule.protocol)?;
    if rule.dest_port == 0 {
        return Err("dest_port cannot be 0".to_string());
    }
    validate_forward_to(&rule.forward_to)?;
    Ok(())
}

/// Validate a static SnatRule (1:1 NAT).
pub fn validate_snat_rule(rule: &gfw_io::nat::SnatRule) -> Result<(), String> {
    validate_cidr(&rule.source_cidr)?;
    validate_ip(&rule.to_address)?;
    // out_interface is optional — only validate when set.
    if !rule.out_interface.is_empty() {
        validate_interface(&rule.out_interface)?;
    }
    Ok(())
}

/// Validate an entire NatConfig.
pub fn validate_nat_config(config: &gfw_io::nat::NatConfig) -> Result<(), String> {
    for rule in &config.masquerade {
        validate_masquerade_rule(rule)?;
    }
    for rule in &config.port_forward {
        validate_port_forward_rule(rule)?;
    }
    for rule in &config.snat {
        validate_snat_rule(rule)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_interfaces() {
        assert!(validate_interface("eth0").is_ok());
        assert!(validate_interface("wg0").is_ok());
        assert!(validate_interface("br-lan").is_ok());
        assert!(validate_interface("ens3.100").is_ok());
        assert!(validate_interface("").is_ok());
        assert!(validate_interface("any").is_ok());
    }

    #[test]
    fn test_invalid_interfaces() {
        assert!(validate_interface("eth0\"").is_err());
        assert!(validate_interface("eth0; drop").is_err());
        assert!(validate_interface("$(reboot)").is_err());
        assert!(validate_interface("`rm -rf /`").is_err());
        assert!(validate_interface("a".repeat(16).as_str()).is_err());
        // Note: "eth0 " is valid because validate_interface() trims whitespace
        assert!(validate_interface("eth0 ").is_ok());
    }

    #[test]
    fn test_valid_cidrs() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.1").is_ok());
        assert!(validate_cidr("::1/128").is_ok());
        assert!(validate_cidr("").is_ok());
        assert!(validate_cidr("any").is_ok());
    }

    #[test]
    fn test_invalid_cidrs() {
        assert!(validate_cidr("not-an-ip").is_err());
        assert!(validate_cidr("192.168.1.0/33").is_err());
        assert!(validate_cidr("192.168.1.0/24; drop").is_err());
        assert!(validate_cidr("$(reboot)").is_err());
    }

    #[test]
    fn test_valid_ports() {
        assert!(validate_port("80").is_ok());
        assert!(validate_port("443").is_ok());
        assert!(validate_port("80,443").is_ok());
        assert!(validate_port("1024-65535").is_ok());
        assert!(validate_port("").is_ok());
        assert!(validate_port("any").is_ok());
    }

    #[test]
    fn test_invalid_ports() {
        assert!(validate_port("abc").is_err());
        assert!(validate_port("99999").is_err());
        assert!(validate_port("80; drop").is_err());
        assert!(validate_port("-1").is_err());
    }

    #[test]
    fn test_injection_payloads() {
        let payloads = vec![
            "\" ; delete table inet gfw_rs ; echo \"",
            "$(reboot)",
            "`reboot`",
            "; flush ruleset ;",
            "\\n add rule inet gfw_rs FORWARD accept",
            "' OR '1'='1",
            "../../../etc/passwd",
            "AAAA%n%n%n%n",
            "{{7*7}}",
            "<script>alert(1)</script>",
        ];
        for payload in &payloads {
            assert!(
                validate_interface(payload).is_err(),
                "Interface should reject: {}",
                payload
            );
        }
        for payload in &payloads {
            assert!(
                validate_cidr(payload).is_err(),
                "CIDR should reject: {}",
                payload
            );
        }
        for payload in &payloads {
            assert!(
                validate_port(payload).is_err(),
                "Port should reject: {}",
                payload
            );
        }
    }

    // --- SNAT rule validation (Phase C) ---

    #[test]
    fn snat_rule_valid_shapes() {
        // With out_interface
        assert!(validate_snat_rule(&gfw_io::nat::SnatRule {
            source_cidr: "10.10.0.0/24".to_string(),
            to_address: "203.0.113.5".to_string(),
            out_interface: "eth0".to_string(),
        })
        .is_ok());
        // Without out_interface (empty string = unset)
        assert!(validate_snat_rule(&gfw_io::nat::SnatRule {
            source_cidr: "192.168.5.0/24".to_string(),
            to_address: "198.51.100.1".to_string(),
            out_interface: "".to_string(),
        })
        .is_ok());
    }

    #[test]
    fn snat_rule_rejects_injection_in_cidr() {
        let bad = gfw_io::nat::SnatRule {
            source_cidr: "10.0.0.0/24; reboot".to_string(),
            to_address: "10.0.0.1".to_string(),
            out_interface: "eth0".to_string(),
        };
        assert!(validate_snat_rule(&bad).is_err());
    }

    #[test]
    fn snat_rule_rejects_invalid_to_address() {
        let bad = gfw_io::nat::SnatRule {
            source_cidr: "10.0.0.0/24".to_string(),
            to_address: "not-an-ip".to_string(),
            out_interface: "eth0".to_string(),
        };
        assert!(validate_snat_rule(&bad).is_err());

        let bad2 = gfw_io::nat::SnatRule {
            source_cidr: "10.0.0.0/24".to_string(),
            to_address: "$(whoami)".to_string(),
            out_interface: "".to_string(),
        };
        assert!(validate_snat_rule(&bad2).is_err());
    }

    #[test]
    fn snat_rule_rejects_bad_interface() {
        let bad = gfw_io::nat::SnatRule {
            source_cidr: "10.0.0.0/24".to_string(),
            to_address: "10.0.0.1".to_string(),
            out_interface: "eth0; rm -rf /".to_string(),
        };
        assert!(validate_snat_rule(&bad).is_err());
    }

    #[test]
    fn nat_config_with_snat_roundtrip_validation() {
        // A mixed config — masquerade + port_forward + snat all valid.
        let config = gfw_io::nat::NatConfig {
            masquerade: vec![gfw_io::nat::MasqueradeRule {
                out_interface: "eth0".to_string(),
                source_cidr: "192.168.1.0/24".to_string(),
            }],
            port_forward: vec![gfw_io::nat::PortForwardRule {
                in_interface: "eth0".to_string(),
                protocol: "tcp".to_string(),
                dest_port: 8080,
                forward_to: "192.168.1.100:80".to_string(),
            }],
            snat: vec![gfw_io::nat::SnatRule {
                source_cidr: "10.10.0.0/24".to_string(),
                to_address: "203.0.113.5".to_string(),
                out_interface: "eth0".to_string(),
            }],
        };
        assert!(validate_nat_config(&config).is_ok());

        // Injecting a bad snat rule should fail the whole config.
        let mut bad = config.clone();
        bad.snat.push(gfw_io::nat::SnatRule {
            source_cidr: "bogus".to_string(),
            to_address: "10.0.0.1".to_string(),
            out_interface: "eth0".to_string(),
        });
        assert!(validate_nat_config(&bad).is_err());
    }
}
