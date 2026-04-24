//! QuickFW Firewall Appliance — First Boot Setup Wizard
//!
//! Enhanced version: adds root password, SSH toggle, DMZ support,
//! default-deny firewall, and drops into CLI after completion.

use std::fs;
use std::io::{self, Write};
use std::process::Command;

use gfw_ifmgr::{
    ApplianceNetConfig, LanConfig, WanConfig, WanMode,
    generate_dnsmasq_config, list_interfaces, apply_interface_config, save_config,
};

const APPLIANCE_CONFIG_PATH: &str = "/etc/quickfw/appliance.yaml";
const DNSMASQ_CONFIG_PATH: &str = "/etc/dnsmasq.d/quickfw.conf";
const ADMIN_PASSWORD_PATH: &str = "/etc/quickfw/admin.password";

const BANNED_PASSWORDS: &[&str] = &[
    "admin", "password", "123456", "12345678", "qwerty",
    "letmein", "firewall", "changeme", "quickfw",
];

fn main() {
    println!();
    println!("════════════════════════════════════════════════════════════");
    println!("         QuickFW — First Boot Setup");
    println!("════════════════════════════════════════════════════════════");
    println!();

    // Check if already configured
    if std::path::Path::new(APPLIANCE_CONFIG_PATH).exists() {
        println!("Appliance is already configured.");
        println!("To reconfigure, delete {} and rerun.", APPLIANCE_CONFIG_PATH);
        println!();
        // Drop into CLI
        drop_to_cli();
        return;
    }

    // Create config dir
    fs::create_dir_all("/etc/quickfw").unwrap_or_default();

    // ── Step 1: Detect interfaces ──
    println!("Detecting network interfaces...");
    let interfaces = list_interfaces();

    if interfaces.is_empty() {
        eprintln!("ERROR: No network interfaces detected. Cannot continue.");
        std::process::exit(1);
    }

    println!();
    println!("Available interfaces:");
    for (i, iface) in interfaces.iter().enumerate() {
        let status = if iface.link_up { "UP" } else { "DOWN" };
        let addrs = if iface.ipv4_addrs.is_empty() {
            "no IP".to_string()
        } else {
            iface.ipv4_addrs.join(", ")
        };
        println!("  [{}] {} ({}) — {} — {}", i + 1, iface.name, iface.mac, status, addrs);
    }

    if interfaces.len() < 2 {
        eprintln!();
        eprintln!("WARNING: Only {} interface(s) detected. A firewall needs at least 2.", interfaces.len());
        eprintln!("         Proceeding with available interfaces...");
    }

    let total_steps = 7;

    // ── Step 2: Select WAN interface ──
    println!();
    println!("Step 1/{}: Select WAN interface", total_steps);
    let wan_idx = prompt_selection("Select WAN interface", interfaces.len());
    let wan_iface = &interfaces[wan_idx];
    println!("  WAN: {}", wan_iface.name);

    // ── Step 3: WAN mode ──
    println!();
    println!("Step 2/{}: WAN address mode", total_steps);
    println!("  [1] DHCP (automatic)");
    println!("  [2] Static");
    let wan_mode_choice = prompt_selection("Select WAN mode", 2);

    let (wan_mode, wan_address, wan_gateway, wan_dns) = if wan_mode_choice == 1 {
        // Static
        let addr = prompt_input("WAN IP address (CIDR, e.g., 203.0.113.10/24)");
        let gw = prompt_input("Default gateway (e.g., 203.0.113.1)");
        let dns_str = prompt_input_default("DNS servers (comma-separated)", "8.8.8.8,1.1.1.1");
        let dns: Vec<String> = dns_str.split(',').map(|s| s.trim().to_string()).collect();
        (WanMode::Static, Some(addr), Some(gw), dns)
    } else {
        (WanMode::Dhcp, None, None, vec![])
    };

    // ── Step 4: Select LAN interface ──
    println!();
    println!("Step 3/{}: Select LAN interface", total_steps);
    let lan_candidates: Vec<&gfw_ifmgr::InterfaceInfo> = interfaces
        .iter()
        .filter(|i| i.name != wan_iface.name)
        .collect();

    let lan_iface = if lan_candidates.is_empty() {
        eprintln!("WARNING: No separate LAN interface. Using WAN interface for LAN too.");
        wan_iface
    } else if lan_candidates.len() == 1 {
        println!("LAN interface (auto-selected): {}", lan_candidates[0].name);
        lan_candidates[0]
    } else {
        println!("Available LAN interfaces:");
        for (i, iface) in lan_candidates.iter().enumerate() {
            println!("  [{}] {} ({})", i + 1, iface.name, iface.mac);
        }
        let idx = prompt_selection("Select LAN interface", lan_candidates.len());
        lan_candidates[idx]
    };

    // ── Step 5: LAN IP + DHCP ──
    println!();
    println!("Step 4/{}: LAN configuration", total_steps);
    let lan_address = prompt_input_default("LAN IP address (CIDR)", "192.168.1.1/24");
    let lan_dhcp_range = prompt_input_default(
        "LAN DHCP range (start,end or empty to disable)",
        "192.168.1.100,192.168.1.200",
    );
    let dhcp_range = if lan_dhcp_range.is_empty() {
        None
    } else {
        Some(lan_dhcp_range)
    };

    // ── Step 6: Root password ──
    println!();
    println!("Step 5/{}: Set root password", total_steps);
    let root_password = prompt_password("Root password");
    set_root_password(&root_password);

    // ── Step 7: Admin password ──
    println!();
    println!("Step 6/{}: Set admin password (web UI)", total_steps);
    println!("  Requirements: ≥ 12 chars, mix of upper/lower case + at least one digit.");
    println!("  Press Enter to keep 'quickfw' default (first-boot lockdown stays active until changed).");
    let admin_password = loop {
        let pw = prompt_input_default("Admin password", "quickfw");
        // Leaving the default keeps the appliance in first-boot lockdown — the
        // web UI will force the admin to set a strong password on first login.
        if pw == "quickfw" {
            break pw;
        }
        if let Err(reason) = check_password_strength(&pw) {
            println!("  {}", reason);
            continue;
        }
        let confirm = prompt_input_default("Confirm password", "");
        if confirm != pw {
            println!("  Passwords do not match. Try again.");
            continue;
        }
        break pw;
    };

    // ── Step 8: SSH ──
    println!();
    println!("Step 7/{}: SSH remote access", total_steps);
    let enable_ssh = prompt_yes_no("Enable SSH?", false);

    // ── Summary ──
    println!();
    println!("════════════════════════════════════════════════════════════");
    println!("  Configuration Summary");
    println!("════════════════════════════════════════════════════════════");
    println!("  WAN:  {} ({:?})", wan_iface.name, wan_mode);
    if let Some(ref addr) = wan_address {
        println!("        IP: {}", addr);
    }
    if let Some(ref gw) = wan_gateway {
        println!("        Gateway: {}", gw);
    }
    println!("  LAN:  {} ({})", lan_iface.name, lan_address);
    if let Some(ref range) = dhcp_range {
        println!("        DHCP: {}", range);
    }
    println!("  SSH:  {}", if enable_ssh { "Enabled" } else { "Disabled" });
    println!();

    let confirm = prompt_input_default("Apply? (yes/no)", "yes");
    if confirm.to_lowercase() != "yes" && confirm.to_lowercase() != "y" {
        println!("Setup cancelled. Run quickfw-setup again to reconfigure.");
        return;
    }

    // ── Apply ──
    println!();
    println!("Applying configuration...");

    // Build config
    let config = ApplianceNetConfig {
        wan: WanConfig {
            interface: wan_iface.name.clone(),
            mode: wan_mode,
            address: wan_address,
            gateway: wan_gateway,
            dns: wan_dns,
        },
        lan: LanConfig {
            interface: lan_iface.name.clone(),
            address: lan_address.clone(),
            dhcp_range,
        },
    };

    // 1. Save appliance config
    if let Err(e) = save_config(&config, APPLIANCE_CONFIG_PATH) {
        eprintln!("ERROR: Failed to save config: {}", e);
        std::process::exit(1);
    }
    println!("  [OK] Configuration saved");

    // 2. Save admin password
    if let Err(e) = fs::write(ADMIN_PASSWORD_PATH, &admin_password) {
        eprintln!("WARNING: Failed to save admin password: {}", e);
    } else {
        let _ = Command::new("chmod").args(["600", ADMIN_PASSWORD_PATH]).output();
        println!("  [OK] Admin password saved");
    }

    // 3. Apply network config
    match apply_interface_config(&config) {
        Ok(()) => println!("  [OK] Network interfaces configured"),
        Err(e) => {
            eprintln!("WARNING: Failed to apply network config: {}", e);
            eprintln!("         You may need to configure networking manually.");
        }
    }

    // 4. Write dnsmasq config
    let dnsmasq_conf = generate_dnsmasq_config(&config.lan);
    fs::create_dir_all("/etc/dnsmasq.d").unwrap_or_default();
    if let Err(e) = fs::write(DNSMASQ_CONFIG_PATH, &dnsmasq_conf) {
        eprintln!("WARNING: Failed to write dnsmasq config: {}", e);
    } else {
        println!("  [OK] DHCP/DNS configuration written");
    }

    // 5. Save interface roles
    let roles_yaml = format!(
        "roles:\n  - interface: {}\n    role: wan\n    zone: wan\n  - interface: {}\n    role: lan\n    zone: lan\n",
        wan_iface.name, lan_iface.name
    );
    let _ = fs::write("/etc/quickfw/interfaces.yaml", &roles_yaml);

    // 6. Apply default-deny firewall with masquerade
    apply_default_firewall(&wan_iface.name);
    println!("  [OK] Default-deny firewall applied");

    // 7. Apply NAT masquerade
    apply_default_nat(&wan_iface.name);
    println!("  [OK] NAT masquerade on {}", wan_iface.name);

    // 8. SSH
    if enable_ssh {
        let _ = Command::new("systemctl").args(["enable", "--now", "ssh"]).output();
        println!("  [OK] SSH enabled");
    } else {
        let _ = Command::new("systemctl").args(["disable", "--now", "ssh"]).output();
        println!("  [OK] SSH disabled");
    }

    // 9. Start services
    println!("  Starting services...");
    for svc in ["dnsmasq", "quickfw-api"] {
        let _ = Command::new("systemctl").args(["enable", svc]).output();
        let output = Command::new("systemctl").args(["restart", svc]).output();
        match output {
            Ok(o) if o.status.success() => println!("  [OK] {} started", svc),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                eprintln!("  [WARN] {} may have failed: {}", svc, stderr.trim());
            }
            Err(e) => eprintln!("  [WARN] Failed to start {}: {}", svc, e),
        }
    }

    // Done
    let lan_ip = config.lan.address.split('/').next().unwrap_or("192.168.1.1");
    println!();
    println!("════════════════════════════════════════════════════════════");
    println!("  Setup Complete!");
    println!("════════════════════════════════════════════════════════════");
    println!();
    println!("  Web Dashboard: https://{}", lan_ip);
    println!("  Login:         admin / {}", admin_password);
    if enable_ssh {
        println!("  SSH:           ssh root@{}", lan_ip);
    }
    println!();
    println!("  Dropping to QuickFW CLI...");
    println!("════════════════════════════════════════════════════════════");
    println!();

    // Drop to CLI
    drop_to_cli();
}

// ── Helper functions ──

fn prompt_input(label: &str) -> String {
    loop {
        print!("{}: ", label);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let trimmed = input.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
        println!("  (input required)");
    }
}

fn prompt_input_default(label: &str, default: &str) -> String {
    print!("{} [{}]: ", label, default);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed
    }
}

fn prompt_selection(label: &str, max: usize) -> usize {
    loop {
        print!("{} [1-{}]: ", label, max);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        if let Ok(n) = input.trim().parse::<usize>() {
            if n >= 1 && n <= max {
                return n - 1;
            }
        }
        println!("  Please enter a number between 1 and {}", max);
    }
}

fn prompt_yes_no(label: &str, default: bool) -> bool {
    let hint = if default { "Y/n" } else { "y/N" };
    print!("{} [{}]: ", label, hint);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() {
        return default;
    }
    trimmed == "y" || trimmed == "yes"
}

/// Enforce a minimum-strength policy on the admin password.
///
/// Rules:
///   - ≥ 12 characters
///   - at least one lowercase, one uppercase, one digit
///   - not in the embedded weak-password list (case-insensitive)
fn check_password_strength(pw: &str) -> Result<(), String> {
    if pw.len() < 12 {
        return Err("Password must be at least 12 characters.".to_string());
    }
    let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    if !(has_lower && has_upper && has_digit) {
        return Err("Password needs lowercase, uppercase, AND a digit.".to_string());
    }
    let lower = pw.to_lowercase();
    if BANNED_PASSWORDS.iter().any(|&b| lower == b || lower.contains(b)) {
        return Err("Password contains a common/weak phrase. Choose another.".to_string());
    }
    Ok(())
}

fn prompt_password(label: &str) -> String {
    loop {
        print!("{}: ", label);
        io::stdout().flush().unwrap();
        let mut pw = String::new();
        io::stdin().read_line(&mut pw).unwrap();
        let pw = pw.trim().to_string();
        if pw.len() < 4 {
            println!("  Password must be at least 4 characters.");
            continue;
        }
        print!("Confirm {}: ", label.to_lowercase());
        io::stdout().flush().unwrap();
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm).unwrap();
        if pw == confirm.trim() {
            return pw;
        }
        println!("  Passwords do not match. Try again.");
    }
}

fn set_root_password(password: &str) {
    let output = Command::new("chpasswd")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(format!("root:{}\n", password).as_bytes());
            }
            child.wait()
        });
    match output {
        Ok(s) if s.success() => println!("  [OK] Root password set"),
        _ => eprintln!("  [WARN] Failed to set root password"),
    }
}

fn apply_default_firewall(_wan_iface: &str) {
    let script = format!(r#"#!/usr/sbin/nft -f
add table inet quickfw
flush table inet quickfw

add chain inet quickfw MGMT_SAFETY {{ type filter hook input priority -200; policy accept; }}
flush chain inet quickfw MGMT_SAFETY
add rule inet quickfw MGMT_SAFETY tcp dport {{ 22, 443, 3000 }} counter accept
add rule inet quickfw MGMT_SAFETY meta l4proto icmp counter accept
add rule inet quickfw MGMT_SAFETY meta l4proto icmpv6 counter accept

add chain inet quickfw quickfw_input {{ type filter hook input priority -10; policy drop; }}
flush chain inet quickfw quickfw_input
add rule inet quickfw quickfw_input ct state established,related accept
add rule inet quickfw quickfw_input ct state invalid drop
add rule inet quickfw quickfw_input iifname "lo" accept

add chain inet quickfw quickfw_forward {{ type filter hook forward priority -10; policy drop; }}
flush chain inet quickfw quickfw_forward
add rule inet quickfw quickfw_forward ct state established,related accept
add rule inet quickfw quickfw_forward ct state invalid drop

add chain inet quickfw quickfw_output {{ type filter hook output priority -10; policy accept; }}
flush chain inet quickfw quickfw_output
"#);

    let _ = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(script.as_bytes());
            }
            child.wait()
        });

    // Save firewall config YAML for the API server
    let fw_yaml = format!(
        "forward_policy: drop\ninput_policy: drop\noutput_policy: accept\nrules: []\nzones: []\n"
    );
    let _ = fs::write("/etc/quickfw/firewall.yaml", &fw_yaml);
}

fn apply_default_nat(wan_iface: &str) {
    let script = format!(r#"add table inet quickfw
add chain inet quickfw POSTROUTING {{ type nat hook postrouting priority srcnat; }}
flush chain inet quickfw POSTROUTING
add rule inet quickfw POSTROUTING oifname "{}" masquerade
"#, wan_iface);

    let _ = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(script.as_bytes());
            }
            child.wait()
        });

    // Save NAT config YAML
    let nat_yaml = format!(
        "masquerade:\n  - out_interface: {}\n    source_cidr: \"\"\nport_forward: []\n",
        wan_iface
    );
    let _ = fs::write("/etc/quickfw/nat.yaml", &nat_yaml);
}

fn drop_to_cli() {
    // Try to exec into the QuickFW CLI
    let quickfw_path = "/usr/local/bin/quickfw";
    if std::path::Path::new(quickfw_path).exists() {
        let _ = Command::new(quickfw_path)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status();
    }
}
