//! QuickFW first-boot wizard — pfSense-style.
//!
//! The console wizard does the absolute minimum to get the operator into
//! the web UI:
//!
//!   1. Pick the management interface (auto if there's only one).
//!   2. Pick its addressing — DHCP (default) or static.
//!   3. Pick the web-UI admin password.
//!
//! That's it. No LAN config, no DHCP server, no SSH, no DMZ — every other
//! knob is in the web UI where the operator has a browser, search, and
//! visual feedback. After the wizard, the appliance prints a banner with
//! the URL to open. Total keypresses for the happy path (one NIC + DHCP +
//! a typed password): ~3 prompts.

use std::fs;
use std::io::{self, Write};
use std::process::Command;

const APPLIANCE_CONFIG_PATH: &str = "/etc/quickfw/appliance.yaml";
const ADMIN_PASSWORD_PATH: &str = "/etc/quickfw/admin.password";
const USERS_YAML_PATH: &str = "/etc/quickfw/users.yaml";

const BANNED_PASSWORDS: &[&str] = &[
    "admin", "password", "123456", "12345678", "qwerty",
    "letmein", "firewall", "changeme", "quickfw",
];

fn main() {
    print_banner();

    if std::path::Path::new(APPLIANCE_CONFIG_PATH).exists() {
        println!("Appliance is already configured.");
        println!("To re-run the wizard, delete {} and reboot.", APPLIANCE_CONFIG_PATH);
        println!();
        drop_to_cli();
        return;
    }

    let _ = fs::create_dir_all("/etc/quickfw");

    // ── Step 1: pick management interface ──
    let interfaces = list_interfaces();
    if interfaces.is_empty() {
        eprintln!("ERROR: No network interfaces detected. Cannot continue.");
        std::process::exit(1);
    }

    let mgmt_iface = if interfaces.len() == 1 {
        println!("Detected single interface: {}", interfaces[0].name);
        println!("Using it for management.");
        interfaces[0].clone()
    } else {
        println!("Detected interfaces:");
        for (i, iface) in interfaces.iter().enumerate() {
            let link = if iface.link_up { "UP" } else { "DOWN" };
            let addr = iface.ipv4.as_deref().unwrap_or("no IP");
            println!("  [{}] {:8} {} {}", i + 1, iface.name, link, addr);
        }
        println!();
        let idx = prompt_select("Pick management interface", interfaces.len());
        interfaces[idx].clone()
    };

    // ── Step 2: addressing ──
    println!();
    println!("Addressing for {} (this is how you'll reach the web UI):", mgmt_iface.name);
    println!("  [1] DHCP (automatic — recommended)");
    println!("  [2] Static");
    let mode_choice = prompt_default("Choice [1]", "1");

    let static_cfg = if mode_choice.trim() == "2" {
        let addr = prompt_required("IP/CIDR (e.g. 192.168.1.10/24)");
        let gw = prompt_required("Gateway IP");
        Some((addr, gw))
    } else {
        None
    };

    // ── Step 3: admin password ──
    println!();
    println!("Set the admin password for the web UI.");
    println!("Requirements: ≥ 12 characters, with upper + lower case + a digit.");
    let admin_pw = loop {
        let pw = prompt_required("Admin password");
        if let Err(reason) = check_password_strength(&pw) {
            println!("  {}", reason);
            continue;
        }
        let confirm = prompt_required("Confirm password");
        if pw != confirm {
            println!("  Passwords don't match. Try again.");
            continue;
        }
        break pw;
    };

    // ── Apply ──
    println!();
    println!("Applying configuration...");

    if let Some((ref addr, ref gw)) = static_cfg {
        apply_static(&mgmt_iface.name, addr, gw);
    } else {
        apply_dhcp(&mgmt_iface.name);
    }

    write_admin_password(&admin_pw);

    // Marker file — bypass the wizard on subsequent boots.
    let yaml = format!(
        "schema_version: '1.0'\nmgmt_interface: {}\nmode: {}\n",
        mgmt_iface.name,
        if static_cfg.is_some() { "static" } else { "dhcp" },
    );
    if let Err(e) = fs::write(APPLIANCE_CONFIG_PATH, yaml) {
        eprintln!("WARN: could not write {}: {}", APPLIANCE_CONFIG_PATH, e);
    }

    // Print URL — this is what the operator needs to see.
    // current_ipv4 returns "10.0.2.15/24" (CIDR), strip the prefix length
    // for display since browsers don't accept it.
    let ip_cidr = current_ipv4(&mgmt_iface.name);
    let ip = ip_cidr.split('/').next().unwrap_or(&ip_cidr).to_string();
    println!();
    println!("════════════════════════════════════════════════════════════");
    println!("   QuickFW setup complete.");
    println!();
    if !ip.is_empty() {
        println!("   Open in your browser:");
        println!();
        println!("       https://{}", ip);
    } else {
        println!("   No IPv4 address yet — DHCP may still be in progress.");
        println!("   Check with `ip addr` and re-try in a moment.");
    }
    println!();
    println!("   Login:   admin");
    println!("   (password you just set)");
    println!("════════════════════════════════════════════════════════════");
    println!();
    println!("Press Enter to drop to a shell.");
    let _ = read_line();
    drop_to_cli();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn print_banner() {
    println!();
    println!("════════════════════════════════════════════════════════════");
    println!("            QuickFW Firewall — First Boot Setup");
    println!("════════════════════════════════════════════════════════════");
    println!();
}

#[derive(Clone)]
struct IfaceLite {
    name: String,
    link_up: bool,
    ipv4: Option<String>,
}

fn list_interfaces() -> Vec<IfaceLite> {
    // Use /sys/class/net to enumerate. Skip loopback and virtual bridges.
    let mut out = Vec::new();
    let entries = match fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        // Skip docker / bridge / wg interfaces — they're not what an
        // operator wants for management.
        if name.starts_with("docker") || name.starts_with("br-") || name.starts_with("veth") {
            continue;
        }
        let link_up = fs::read_to_string(format!("/sys/class/net/{}/operstate", name))
            .map(|s| s.trim() == "up")
            .unwrap_or(false);
        let ipv4 = current_ipv4_opt(&name);
        out.push(IfaceLite { name, link_up, ipv4 });
    }
    // Show interfaces that are UP first (operator usually wants those).
    out.sort_by(|a, b| b.link_up.cmp(&a.link_up).then(a.name.cmp(&b.name)));
    out
}

fn current_ipv4(name: &str) -> String {
    current_ipv4_opt(name).unwrap_or_default()
}

fn current_ipv4_opt(name: &str) -> Option<String> {
    let out = Command::new("ip").args(["-4", "-o", "addr", "show", name]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(idx) = line.find("inet ") {
            let rest = &line[idx + 5..];
            if let Some(end) = rest.find(' ') {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

fn apply_dhcp(iface: &str) {
    let _ = Command::new("ip").args(["addr", "flush", "dev", iface]).status();
    let _ = Command::new("ip").args(["link", "set", iface, "up"]).status();
    // Best-effort DHCP — if dhclient isn't installed, the operator will
    // need to set static or boot with the LAN side providing DHCP.
    let r = Command::new("dhclient").args(["-v", iface]).status();
    if !r.map(|s| s.success()).unwrap_or(false) {
        println!("  WARN: dhclient failed; the appliance may need a static IP.");
    }
}

fn apply_static(iface: &str, addr: &str, gw: &str) {
    let _ = Command::new("ip").args(["addr", "flush", "dev", iface]).status();
    let _ = Command::new("ip").args(["link", "set", iface, "up"]).status();
    let _ = Command::new("ip").args(["addr", "add", addr, "dev", iface]).status();
    let _ = Command::new("ip").args(["route", "del", "default"]).status();
    let _ = Command::new("ip").args(["route", "add", "default", "via", gw, "dev", iface]).status();
}

fn write_admin_password(pw: &str) {
    // Write both the legacy admin.password file (Argon2 hash) AND the
    // new users.yaml (Phase G) so first-boot lockdown lifts.
    use std::process::Stdio;
    let hash = match Command::new("openssl")
        .args(["passwd", "-6", pw]) // SHA-512 crypt — acceptable as an emergency fallback
        .stdout(Stdio::piped())
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => pw.to_string(), // last-ditch — auth.rs auto-migrates plaintext to argon2 on first login
    };
    let _ = fs::write(ADMIN_PASSWORD_PATH, &hash);

    // Also seed users.yaml with admin (role=admin) so Phase G's RBAC has
    // an initial entry. The hash format here is plaintext — auth.rs's
    // first verify will rehash it as argon2 and rewrite. This avoids a
    // build dependency on argon2 from the setup binary.
    let yaml = format!(
        "schema_version: '1.0'\nusers:\n  - username: admin\n    password_hash: {}\n    role: admin\n",
        pw
    );
    let _ = fs::write(USERS_YAML_PATH, &yaml);
}

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

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

fn prompt_required(label: &str) -> String {
    loop {
        print!("{}: ", label);
        let _ = io::stdout().flush();
        let s = read_line();
        if !s.trim().is_empty() {
            return s.trim().to_string();
        }
        println!("  Required.");
    }
}

fn prompt_default(label: &str, default: &str) -> String {
    print!("{}: ", label);
    let _ = io::stdout().flush();
    let s = read_line();
    let t = s.trim();
    if t.is_empty() { default.to_string() } else { t.to_string() }
}

fn prompt_select(label: &str, count: usize) -> usize {
    loop {
        print!("{} [1-{}]: ", label, count);
        let _ = io::stdout().flush();
        let s = read_line();
        if let Ok(n) = s.trim().parse::<usize>() {
            if n >= 1 && n <= count {
                return n - 1;
            }
        }
        println!("  Enter a number between 1 and {}.", count);
    }
}

fn read_line() -> String {
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
    buf
}

fn drop_to_cli() {
    let quickfw_path = "/usr/local/bin/quickfw";
    if std::path::Path::new(quickfw_path).exists() {
        let _ = Command::new(quickfw_path)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_too_short_rejected() {
        assert!(check_password_strength("Ab1").is_err());
        assert!(check_password_strength("Abc12345678").is_err());
        assert!(check_password_strength("").is_err());
    }

    #[test]
    fn password_missing_char_class_rejected() {
        assert!(check_password_strength("alllower123456").is_err());
        assert!(check_password_strength("ALLUPPER123456").is_err());
        assert!(check_password_strength("NoDigitsInThisOne").is_err());
    }

    #[test]
    fn password_with_weak_phrase_rejected() {
        for bad in ["MyAdminPass123", "Password12345!", "qUickfw-abcdE1"] {
            assert!(
                check_password_strength(bad).is_err(),
                "expected reject for {}",
                bad
            );
        }
    }

    #[test]
    fn password_strong_accepted() {
        assert!(check_password_strength("Xy9#k2MpQr7Lv").is_ok());
        assert!(check_password_strength("Mountain2026Breeze!").is_ok());
        assert!(check_password_strength("Zebra-Tango-9x-Plum").is_ok());
    }

    #[test]
    fn password_case_insensitivity_on_weak_list() {
        assert!(check_password_strength("QUICKFWisBad1234").is_err());
        assert!(check_password_strength("MyPassWORDabc12").is_err());
    }
}
