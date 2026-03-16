use colored::*;
use reqwest::blocking::Client;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::io::{self, Write};
use std::process::Command;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VERSION: &str = "1.0.0";
const DEFAULT_API_URL: &str = "http://127.0.0.1:3000";
const HISTORY_FILE: &str = ".quickfw_history";

const MGMT_SAFETY_RULESET: &str = r#"table inet quickfw {
  chain MGMT_SAFETY {
    type filter hook input priority -200; policy accept;
    tcp dport { 22, 443, 3000 } counter accept
    meta l4proto icmp counter accept
  }
}"#;

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Mode {
    User,
    Privileged,
    Config,
    ConfigInterface(String),
    ConfigFirewallRule(String),
}

// ---------------------------------------------------------------------------
// Firewall rule builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FirewallRuleBuilder {
    name: String,
    direction: Option<String>,
    protocol: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    source_port: Option<String>,
    destination_port: Option<String>,
    in_interface: Option<String>,
    out_interface: Option<String>,
    action: Option<String>,
    log: bool,
    enabled: bool,
}

impl FirewallRuleBuilder {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            enabled: true,
            ..Default::default()
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "direction": self.direction.as_deref().unwrap_or("forward"),
            "protocol": self.protocol.as_deref().unwrap_or("any"),
            "source": self.source.as_deref().unwrap_or("any"),
            "destination": self.destination.as_deref().unwrap_or("any"),
            "source_port": self.source_port.as_deref().unwrap_or("any"),
            "destination_port": self.destination_port.as_deref().unwrap_or("any"),
            "in_interface": self.in_interface.as_deref().unwrap_or("any"),
            "out_interface": self.out_interface.as_deref().unwrap_or("any"),
            "action": self.action.as_deref().unwrap_or("accept"),
            "log": self.log,
            "enabled": self.enabled,
        })
    }
}

// ---------------------------------------------------------------------------
// CLI State
// ---------------------------------------------------------------------------

struct CliState {
    mode: Mode,
    api_url: String,
    username: String,
    password: String,
    hostname: String,
    client: Client,
    current_rule: Option<FirewallRuleBuilder>,
    current_interface: Option<String>,
}

impl CliState {
    fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());

        let mut state = Self {
            mode: Mode::User,
            api_url: DEFAULT_API_URL.to_string(),
            username: "admin".to_string(),
            password: "quickfw".to_string(),
            hostname: "quickfw".to_string(),
            client,
            current_rule: None,
            current_interface: None,
        };

        // Try to fetch hostname from API
        if let Ok(info) = state.api_get("/api/system/info") {
            if let Some(h) = info.get("hostname").and_then(|v| v.as_str()) {
                if !h.is_empty() {
                    state.hostname = h.to_string();
                }
            }
        }

        state
    }

    fn prompt(&self) -> String {
        match &self.mode {
            Mode::User => format!("{}> ", self.hostname),
            Mode::Privileged => format!("{}# ", self.hostname),
            Mode::Config => format!("{}(config)# ", self.hostname),
            Mode::ConfigInterface(name) => {
                format!("{}(config-if-{})# ", self.hostname, name)
            }
            Mode::ConfigFirewallRule(name) => {
                format!("{}(config-fw-{})# ", self.hostname, name)
            }
        }
    }

    // -----------------------------------------------------------------------
    // API helpers
    // -----------------------------------------------------------------------

    fn api_get(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.api_url, path);
        let resp = self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .map_err(|e| format!("API unreachable: {}", e))?;

        if resp.status().as_u16() == 401 {
            return Err("Authentication failed (401). Try 'password admin' to update credentials.".into());
        }
        if !resp.status().is_success() {
            return Err(format!("API error: HTTP {}", resp.status()));
        }

        resp.json::<Value>()
            .map_err(|e| format!("Failed to parse response: {}", e))
    }

    fn api_post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let url = format!("{}{}", self.api_url, path);
        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.username, Some(&self.password))
            .json(body)
            .send()
            .map_err(|e| format!("API unreachable: {}", e))?;

        if resp.status().as_u16() == 401 {
            return Err("Authentication failed (401).".into());
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(format!("API error: HTTP {} - {}", status, text));
        }

        resp.json::<Value>()
            .or_else(|_| Ok(json!({"status": "ok"})))
    }

    fn api_delete(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.api_url, path);
        let resp = self
            .client
            .delete(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .map_err(|e| format!("API unreachable: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(format!("API error: HTTP {} - {}", status, text));
        }

        resp.json::<Value>()
            .or_else(|_| Ok(json!({"status": "ok"})))
    }

    fn api_put(&self, path: &str, body: &Value) -> Result<Value, String> {
        let url = format!("{}{}", self.api_url, path);
        let resp = self
            .client
            .put(&url)
            .basic_auth(&self.username, Some(&self.password))
            .json(body)
            .send()
            .map_err(|e| format!("API unreachable: {}", e))?;

        if resp.status().as_u16() == 401 {
            return Err("Authentication failed (401).".into());
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(format!("API error: HTTP {} - {}", status, text));
        }

        resp.json::<Value>()
            .or_else(|_| Ok(json!({"status": "ok"})))
    }
}

// ---------------------------------------------------------------------------
// Tab completion
// ---------------------------------------------------------------------------

struct CliHelper {
    mode: Mode,
}

impl CliHelper {
    fn new(mode: Mode) -> Self {
        Self { mode }
    }

    fn candidates(&self) -> Vec<&'static str> {
        let mut cmds: Vec<&'static str> = vec!["?", "exit"];

        match &self.mode {
            Mode::User => {
                cmds.extend_from_slice(&[
                    "show system",
                    "show interfaces",
                    "show interfaces brief",
                    "show firewall",
                    "show firewall summary",
                    "show nat",
                    "show routes",
                    "show connections",
                    "show connections count",
                    "show running-config",
                    "show arp",
                    "show dhcp leases",
                    "show version",
                    "enable",
                ]);
            }
            Mode::Privileged => {
                cmds.extend_from_slice(&[
                    "show system",
                    "show interfaces",
                    "show interfaces brief",
                    "show firewall",
                    "show firewall summary",
                    "show nat",
                    "show routes",
                    "show connections",
                    "show connections count",
                    "show running-config",
                    "show arp",
                    "show dhcp leases",
                    "show version",
                    "show log",
                    "configure",
                    "configure terminal",
                    "write memory",
                    "reload",
                    "shutdown",
                    "password admin",
                    "password root",
                    "ssh enable",
                    "ssh disable",
                    "ssh status",
                    "ping",
                    "traceroute",
                    "shell",
                    "factory-reset",
                    "flush firewall",
                ]);
            }
            Mode::Config => {
                cmds.extend_from_slice(&[
                    "hostname",
                    "timezone",
                    "dns-server",
                    "ntp-server",
                    "interface",
                    "firewall rule",
                    "firewall input-policy",
                    "firewall forward-policy",
                    "firewall output-policy",
                    "nat masquerade",
                    "nat port-forward",
                    "no nat masquerade",
                    "no nat port-forward",
                    "route",
                    "no route",
                ]);
            }
            Mode::ConfigInterface(_) => {
                cmds.extend_from_slice(&[
                    "ip address",
                    "ip address dhcp",
                    "gateway",
                    "role",
                    "mtu",
                    "description",
                    "dhcp-range",
                    "no dhcp-range",
                    "shutdown",
                    "no shutdown",
                    "show",
                ]);
            }
            Mode::ConfigFirewallRule(_) => {
                cmds.extend_from_slice(&[
                    "direction",
                    "protocol",
                    "source",
                    "destination",
                    "source-port",
                    "destination-port",
                    "in-interface",
                    "out-interface",
                    "action",
                    "log",
                    "enable",
                    "disable",
                    "show",
                ]);
            }
        }

        cmds
    }
}

impl Completer for CliHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let input = &line[..pos];
        let candidates = self.candidates();
        let mut matches: Vec<Pair> = Vec::new();

        for cmd in &candidates {
            if cmd.starts_with(input) {
                matches.push(Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                });
            }
        }

        Ok((0, matches))
    }
}

impl Hinter for CliHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<Self::Hint> {
        if pos < line.len() {
            return None;
        }
        let candidates = self.candidates();
        for cmd in &candidates {
            if cmd.starts_with(line) && cmd.len() > line.len() {
                return Some(cmd[line.len()..].to_string());
            }
        }
        None
    }
}

impl Highlighter for CliHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Owned(hint.dimmed().to_string())
    }
}

impl Validator for CliHelper {}

impl Helper for CliHelper {}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn print_separator(widths: &[usize]) {
    let parts: Vec<String> = widths.iter().map(|w| "\u{2500}".repeat(*w)).collect();
    println!("  {}", parts.join("  "));
}

fn print_row(values: &[&str], widths: &[usize]) {
    let parts: Vec<String> = values
        .iter()
        .zip(widths.iter())
        .map(|(v, w)| format!("{:<width$}", v, width = w))
        .collect();
    println!("  {}", parts.join("  "));
}

fn print_error(msg: &str) {
    eprintln!("  {} {}", "% Error:".red().bold(), msg);
}

fn print_info(msg: &str) {
    println!("  {}", msg);
}

fn print_ok(msg: &str) {
    println!("  {}", msg.green());
}

fn prompt_confirm(msg: &str) -> bool {
    print!("  {} [y/N]: ", msg);
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

fn prompt_password(msg: &str) -> String {
    print!("  {}: ", msg);
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    input.trim().to_string()
}

fn val_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("-")
}

fn val_u64(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(|x| x.as_u64()).unwrap_or(0)
}

fn val_f64(v: &Value, key: &str) -> f64 {
    v.get(key).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

fn val_bool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Show commands
// ---------------------------------------------------------------------------

fn cmd_show_system(state: &CliState) {
    match state.api_get("/api/system/info") {
        Ok(info) => {
            let uptime_secs = val_u64(&info, "uptime_seconds");
            let days = uptime_secs / 86400;
            let hours = (uptime_secs % 86400) / 3600;
            let mins = (uptime_secs % 3600) / 60;

            println!();
            println!(
                "  {}:     {}",
                "Hostname".cyan().bold(),
                val_str(&info, "hostname")
            );
            println!(
                "  {}:      {}",
                "Version".cyan().bold(),
                val_str(&info, "version")
            );
            println!(
                "  {}:       {}d {}h {}m",
                "Uptime".cyan().bold(),
                days,
                hours,
                mins
            );
            println!(
                "  {}:    {:.1}%",
                "CPU Usage".cyan().bold(),
                val_f64(&info, "cpu_usage_percent")
            );
            println!(
                "  {}:     {:.2} / {:.2} / {:.2}",
                "Load Avg".cyan().bold(),
                val_f64(&info, "load_avg_1"),
                val_f64(&info, "load_avg_5"),
                val_f64(&info, "load_avg_15")
            );
            println!(
                "  {}:       {} MB used / {} MB total ({:.0}%)",
                "Memory".cyan().bold(),
                val_u64(&info, "memory_used_mb"),
                val_u64(&info, "memory_total_mb"),
                val_f64(&info, "memory_percent")
            );
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_interfaces(state: &CliState, brief: bool) {
    match state.api_get("/api/interfaces") {
        Ok(data) => {
            let interfaces = data
                .get("interfaces")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if interfaces.is_empty() {
                print_info("No interfaces found.");
                return;
            }

            println!();
            if brief {
                let widths = [10, 6, 4, 17, 10, 10];
                print_row(
                    &["Interface", "Status", "Role", "IP Address", "RX", "TX"],
                    &widths,
                );
                print_separator(&widths);

                for iface in &interfaces {
                    let name = val_str(iface, "name");
                    let up = if val_bool(iface, "link_up") {
                        "UP"
                    } else {
                        "DOWN"
                    };
                    let role = val_str(iface, "role");
                    let ips = iface
                        .get("ipv4_addrs")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_else(|| "-".to_string());
                    let rx = format_bytes(val_u64(iface, "rx_bytes"));
                    let tx = format_bytes(val_u64(iface, "tx_bytes"));

                    print_row(&[name, up, role, &ips, &rx, &tx], &widths);
                }
            } else {
                for iface in &interfaces {
                    let name = val_str(iface, "name");
                    let up = if val_bool(iface, "link_up") {
                        "UP".green().bold().to_string()
                    } else {
                        "DOWN".red().bold().to_string()
                    };
                    let mac = val_str(iface, "mac");
                    let role = val_str(iface, "role");
                    let mtu = val_u64(iface, "mtu");
                    let ips = iface
                        .get("ipv4_addrs")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_else(|| "-".to_string());
                    let rx_b = format_bytes(val_u64(iface, "rx_bytes"));
                    let tx_b = format_bytes(val_u64(iface, "tx_bytes"));
                    let rx_p = val_u64(iface, "rx_packets");
                    let tx_p = val_u64(iface, "tx_packets");

                    println!(
                        "  {} is {}, role: {}, MAC: {}",
                        name.bold(),
                        up,
                        role.yellow(),
                        mac
                    );
                    println!("    IPv4: {}  MTU: {}", ips, mtu);
                    println!(
                        "    RX: {} ({} packets)  TX: {} ({} packets)",
                        rx_b, rx_p, tx_b, tx_p
                    );
                    println!();
                }
            }
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_firewall(state: &CliState) {
    match state.api_get("/api/firewall") {
        Ok(fw) => {
            let rules = fw
                .get("rules")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            // Attempt to get counters
            let counters = state.api_get("/api/firewall/counters").ok();

            println!();
            let widths = [4, 20, 8, 8, 18, 18, 8, 8, 12, 12];
            print_row(
                &[
                    "#", "Name", "Dir", "Proto", "Source", "Destination", "Action", "State",
                    "Packets", "Bytes",
                ],
                &widths,
            );
            print_separator(&widths);

            for (i, rule) in rules.iter().enumerate() {
                let idx = format!("{}", i + 1);
                let name = val_str(rule, "name");
                let dir = val_str(rule, "direction");
                let proto = val_str(rule, "protocol");
                let src = val_str(rule, "source");
                let dst = val_str(rule, "destination");
                let action = val_str(rule, "action");
                let enabled = if val_bool(rule, "enabled") {
                    "enabled"
                } else {
                    "disabled"
                };

                // Look up counters by rule name
                let (pkts, bytes) = if let Some(ref c) = counters {
                    let cr = c
                        .get(name)
                        .or_else(|| {
                            c.get("rules")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| arr.get(i))
                        });
                    match cr {
                        Some(cv) => (
                            format!("{}", val_u64(cv, "packets")),
                            format_bytes(val_u64(cv, "bytes")),
                        ),
                        None => ("-".to_string(), "-".to_string()),
                    }
                } else {
                    ("-".to_string(), "-".to_string())
                };

                print_row(
                    &[&idx, name, dir, proto, src, dst, action, enabled, &pkts, &bytes],
                    &widths,
                );
            }

            println!();
            print_info(&format!("Total rules: {}", rules.len()));
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_firewall_summary(state: &CliState) {
    match state.api_get("/api/firewall") {
        Ok(fw) => {
            let rules = fw
                .get("rules")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let input_policy = fw
                .get("input_policy")
                .and_then(|v| v.as_str())
                .unwrap_or("accept");
            let forward_policy = fw
                .get("forward_policy")
                .and_then(|v| v.as_str())
                .unwrap_or("accept");
            let output_policy = fw
                .get("output_policy")
                .and_then(|v| v.as_str())
                .unwrap_or("accept");

            let mut input_count = 0;
            let mut forward_count = 0;
            let mut output_count = 0;
            for rule in &rules {
                match val_str(rule, "direction") {
                    "input" => input_count += 1,
                    "forward" => forward_count += 1,
                    "output" => output_count += 1,
                    _ => {}
                }
            }

            println!();
            println!(
                "  {} chain: policy {} ({} rules)",
                "INPUT".bold(),
                input_policy.yellow(),
                input_count
            );
            println!(
                "  {} chain: policy {} ({} rules)",
                "FORWARD".bold(),
                forward_policy.yellow(),
                forward_count
            );
            println!(
                "  {} chain: policy {} ({} rules)",
                "OUTPUT".bold(),
                output_policy.yellow(),
                output_count
            );
            println!(
                "\n  Total: {} rules",
                rules.len()
            );
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_nat(state: &CliState) {
    match state.api_get("/api/nat") {
        Ok(nat) => {
            println!();

            // Masquerade
            let masq = nat
                .get("masquerade")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!("  {}", "Masquerade Rules:".bold());
            if masq.is_empty() {
                println!("    (none)");
            } else {
                let widths = [4, 12, 18];
                print_row(&["#", "Interface", "Source CIDR"], &widths);
                print_separator(&widths);
                for (i, m) in masq.iter().enumerate() {
                    let idx = format!("{}", i + 1);
                    let iface = val_str(m, "interface");
                    let src = val_str(m, "source");
                    print_row(&[&idx, iface, src], &widths);
                }
            }

            println!();

            // Port forwards
            let pf = nat
                .get("port_forward")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!("  {}", "Port Forward Rules:".bold());
            if pf.is_empty() {
                println!("    (none)");
            } else {
                let widths = [4, 6, 8, 22, 12];
                print_row(&["#", "Proto", "Port", "Destination", "Interface"], &widths);
                print_separator(&widths);
                for (i, f) in pf.iter().enumerate() {
                    let idx = format!("{}", i + 1);
                    let proto = val_str(f, "protocol");
                    let port = val_str(f, "port");
                    let dest = val_str(f, "destination");
                    let iface = val_str(f, "interface");
                    print_row(&[&idx, proto, port, dest, iface], &widths);
                }
            }

            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_routes(state: &CliState) {
    match state.api_get("/api/routes") {
        Ok(data) => {
            let routes = data
                .get("routes")
                .and_then(|v| v.as_array())
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();

            println!();
            if routes.is_empty() {
                print_info("No static routes configured.");
            } else {
                let widths = [20, 16, 8, 12];
                print_row(&["Destination", "Gateway", "Metric", "Interface"], &widths);
                print_separator(&widths);
                for r in &routes {
                    let dst = val_str(r, "destination");
                    let gw = val_str(r, "gateway");
                    let metric = format!("{}", val_u64(r, "metric"));
                    let iface = val_str(r, "interface");
                    print_row(&[dst, gw, &metric, iface], &widths);
                }
            }
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_connections(state: &CliState) {
    match state.api_get("/api/conntrack") {
        Ok(data) => {
            let conns = data
                .get("connections")
                .and_then(|v| v.as_array())
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();

            println!();
            println!("  Active connections: {}", conns.len().to_string().bold());

            if !conns.is_empty() {
                println!();
                let widths = [6, 18, 8, 18, 8, 12];
                print_row(
                    &["Proto", "Source", "SPort", "Destination", "DPort", "State"],
                    &widths,
                );
                print_separator(&widths);

                let limit = conns.len().min(50);
                for c in &conns[..limit] {
                    let proto = val_str(c, "protocol");
                    let src = val_str(c, "source");
                    let sport = val_str(c, "source_port");
                    let dst = val_str(c, "destination");
                    let dport = val_str(c, "destination_port");
                    let st = val_str(c, "state");
                    print_row(&[proto, src, sport, dst, dport, st], &widths);
                }

                if conns.len() > 50 {
                    println!("  ... and {} more", conns.len() - 50);
                }
            }

            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_connections_count(state: &CliState) {
    match state.api_get("/api/system/traffic") {
        Ok(data) => {
            println!();
            println!(
                "  Active connections: {}",
                val_u64(&data, "active_connections").to_string().bold()
            );
            println!(
                "  Total RX: {} ({} packets)",
                format_bytes(val_u64(&data, "total_rx_bytes")),
                val_u64(&data, "total_rx_packets")
            );
            println!(
                "  Total TX: {} ({} packets)",
                format_bytes(val_u64(&data, "total_tx_bytes")),
                val_u64(&data, "total_tx_packets")
            );
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_running_config(state: &CliState) {
    match state.api_get("/api/config/export") {
        Ok(data) => {
            println!();
            if let Some(s) = data.as_str() {
                println!("{}", s);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string())
                );
            }
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_arp(state: &CliState) {
    match state.api_get("/api/tools/arp") {
        Ok(data) => {
            let entries = data
                .get("entries")
                .and_then(|v| v.as_array())
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();

            println!();
            if entries.is_empty() {
                print_info("ARP table is empty.");
            } else {
                let widths = [16, 18, 12, 8];
                print_row(&["IP Address", "MAC Address", "Interface", "State"], &widths);
                print_separator(&widths);
                for e in &entries {
                    let ip = val_str(e, "ip");
                    let mac = val_str(e, "mac");
                    let iface = val_str(e, "interface");
                    let st = val_str(e, "state");
                    print_row(&[ip, mac, iface, st], &widths);
                }
            }
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_dhcp_leases(state: &CliState) {
    match state.api_get("/api/tools/dhcp-leases") {
        Ok(data) => {
            let leases = data
                .get("leases")
                .and_then(|v| v.as_array())
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();

            println!();
            if leases.is_empty() {
                print_info("No DHCP leases found.");
            } else {
                let widths = [16, 18, 20, 20];
                print_row(&["IP Address", "MAC Address", "Hostname", "Expires"], &widths);
                print_separator(&widths);
                for l in &leases {
                    let ip = val_str(l, "ip");
                    let mac = val_str(l, "mac");
                    let host = val_str(l, "hostname");
                    let exp = val_str(l, "expires");
                    print_row(&[ip, mac, host, exp], &widths);
                }
            }
            println!();
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_show_version() {
    println!();
    println!("  QuickFW version {}", VERSION.bold());
    println!("  Firewall Appliance CLI");
    println!();
}

fn cmd_show_log(state: &CliState, args: &[&str]) {
    let n = args.first().and_then(|s| s.parse::<u32>().ok()).unwrap_or(20);
    let output = Command::new("journalctl")
        .args(["-n", &n.to_string(), "--no-pager"])
        .output();
    match output {
        Ok(o) => {
            let _ = state; // suppress unused warning
            println!();
            println!("{}", String::from_utf8_lossy(&o.stdout));
            if !o.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&o.stderr));
            }
        }
        Err(e) => print_error(&format!("Failed to run journalctl: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Privileged-mode commands
// ---------------------------------------------------------------------------

fn cmd_write_memory(state: &CliState) {
    print_info("Saving configuration...");
    match state.api_post("/save/config", &json!({})) {
        Ok(_) => print_ok("Configuration saved."),
        Err(e) => print_error(&e),
    }
}

fn cmd_reload(state: &CliState) {
    if !prompt_confirm("Are you sure you want to reboot the system?") {
        print_info("Reload cancelled.");
        return;
    }
    let pw = prompt_password("Enter admin password to confirm");
    match state.api_post("/api/system/reboot", &json!({"password": pw})) {
        Ok(_) => print_ok("System is rebooting..."),
        Err(e) => print_error(&e),
    }
}

fn cmd_shutdown() {
    if !prompt_confirm("Are you sure you want to power off the system?") {
        print_info("Shutdown cancelled.");
        return;
    }
    let output = Command::new("systemctl").arg("poweroff").output();
    match output {
        Ok(_) => print_ok("System is shutting down..."),
        Err(e) => print_error(&format!("Failed to power off: {}", e)),
    }
}

fn cmd_password_admin(state: &mut CliState) {
    let pw = prompt_password("Enter new admin password");
    if pw.is_empty() {
        print_error("Password cannot be empty.");
        return;
    }
    let pw2 = prompt_password("Confirm new admin password");
    if pw != pw2 {
        print_error("Passwords do not match.");
        return;
    }
    match state.api_post(
        "/api/auth/password",
        &json!({"username": "admin", "password": pw}),
    ) {
        Ok(_) => {
            state.password = pw;
            print_ok("Admin password updated.");
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_password_root() {
    let pw = prompt_password("Enter new root password");
    if pw.is_empty() {
        print_error("Password cannot be empty.");
        return;
    }
    let pw2 = prompt_password("Confirm new root password");
    if pw != pw2 {
        print_error("Passwords do not match.");
        return;
    }
    let output = Command::new("chpasswd")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                let _ = write!(stdin, "root:{}", pw);
            }
            child.wait_with_output()
        });
    match output {
        Ok(o) if o.status.success() => print_ok("Root password updated."),
        Ok(o) => print_error(&format!(
            "chpasswd failed: {}",
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => print_error(&format!("Failed to run chpasswd: {}", e)),
    }
}

fn cmd_ssh(action: &str) {
    match action {
        "enable" => {
            let output = Command::new("systemctl")
                .args(["enable", "--now", "ssh"])
                .output();
            match output {
                Ok(o) if o.status.success() => print_ok("SSH enabled and started."),
                Ok(o) => print_error(&format!(
                    "Failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                )),
                Err(e) => print_error(&format!("Failed: {}", e)),
            }
        }
        "disable" => {
            let _ = Command::new("systemctl").args(["stop", "ssh"]).output();
            let output = Command::new("systemctl")
                .args(["disable", "ssh"])
                .output();
            match output {
                Ok(o) if o.status.success() => print_ok("SSH stopped and disabled."),
                Ok(o) => print_error(&format!(
                    "Failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                )),
                Err(e) => print_error(&format!("Failed: {}", e)),
            }
        }
        "status" => {
            let output = Command::new("systemctl")
                .args(["is-active", "ssh"])
                .output();
            match output {
                Ok(o) => {
                    let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    println!("  SSH service: {}", if status == "active" {
                        status.green().to_string()
                    } else {
                        status.red().to_string()
                    });
                }
                Err(e) => print_error(&format!("Failed: {}", e)),
            }
        }
        _ => print_error("Usage: ssh <enable|disable|status>"),
    }
}

fn cmd_ping(state: &CliState, host: &str) {
    // Try API first, fall back to direct
    match state.api_post("/api/tools/ping", &json!({"host": host})) {
        Ok(data) => {
            println!();
            if let Some(output) = data.get("output").and_then(|v| v.as_str()) {
                println!("{}", output);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string())
                );
            }
            println!();
        }
        Err(_) => {
            // Fall back to direct execution
            let output = Command::new("ping")
                .args(["-c", "4", host])
                .output();
            match output {
                Ok(o) => {
                    println!();
                    println!("{}", String::from_utf8_lossy(&o.stdout));
                    if !o.stderr.is_empty() {
                        eprintln!("{}", String::from_utf8_lossy(&o.stderr));
                    }
                }
                Err(e) => print_error(&format!("ping failed: {}", e)),
            }
        }
    }
}

fn cmd_traceroute(state: &CliState, host: &str) {
    match state.api_post("/api/tools/traceroute", &json!({"host": host})) {
        Ok(data) => {
            println!();
            if let Some(output) = data.get("output").and_then(|v| v.as_str()) {
                println!("{}", output);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string())
                );
            }
            println!();
        }
        Err(_) => {
            let output = Command::new("traceroute").arg(host).output();
            match output {
                Ok(o) => {
                    println!();
                    println!("{}", String::from_utf8_lossy(&o.stdout));
                    if !o.stderr.is_empty() {
                        eprintln!("{}", String::from_utf8_lossy(&o.stderr));
                    }
                }
                Err(e) => print_error(&format!("traceroute failed: {}", e)),
            }
        }
    }
}

fn cmd_shell() {
    print_info("Entering shell. Type 'exit' to return to QuickFW CLI.");
    let status = Command::new("/bin/bash")
        .arg("--login")
        .status();
    match status {
        Ok(_) => print_info("Returned to QuickFW CLI."),
        Err(e) => print_error(&format!("Failed to start shell: {}", e)),
    }
}

fn cmd_factory_reset() {
    println!();
    println!(
        "  {}",
        "WARNING: This will erase ALL configuration and reboot!".red().bold()
    );
    if !prompt_confirm("Type 'y' to confirm factory reset") {
        print_info("Factory reset cancelled.");
        return;
    }

    // Remove config files
    let _ = Command::new("rm")
        .args(["-rf", "/etc/quickfw/*.yaml"])
        .output();

    // Flush nftables
    let _ = Command::new("nft").args(["flush", "ruleset"]).output();

    print_ok("Configuration erased. Rebooting...");

    let _ = Command::new("reboot").output();
}

fn cmd_flush_firewall() {
    if !prompt_confirm("Flush all firewall rules and recreate MGMT_SAFETY?") {
        print_info("Cancelled.");
        return;
    }

    // Flush
    let flush = Command::new("nft").args(["flush", "ruleset"]).output();
    match flush {
        Ok(o) if !o.status.success() => {
            print_error(&format!(
                "nft flush failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ));
            return;
        }
        Err(e) => {
            print_error(&format!("Failed to run nft: {}", e));
            return;
        }
        _ => {}
    }

    // Recreate MGMT_SAFETY
    let recreate = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(MGMT_SAFETY_RULESET.as_bytes());
            }
            child.wait_with_output()
        });

    match recreate {
        Ok(o) if o.status.success() => {
            print_ok("Firewall flushed. MGMT_SAFETY chain recreated (SSH/443/3000 + ICMP).");
        }
        Ok(o) => print_error(&format!(
            "Failed to recreate MGMT_SAFETY: {}",
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => print_error(&format!("Failed: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Config mode commands
// ---------------------------------------------------------------------------

fn cmd_config_hostname(state: &mut CliState, name: &str) {
    match state.api_post("/api/settings", &json!({"hostname": name})) {
        Ok(_) => {
            state.hostname = name.to_string();
            print_ok(&format!("Hostname set to '{}'", name));
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_config_timezone(state: &CliState, tz: &str) {
    match state.api_post("/api/settings", &json!({"timezone": tz})) {
        Ok(_) => print_ok(&format!("Timezone set to '{}'", tz)),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_dns(state: &CliState, servers: &[&str]) {
    let dns: Vec<&str> = servers.to_vec();
    match state.api_post("/api/settings", &json!({"dns_servers": dns})) {
        Ok(_) => print_ok(&format!("DNS servers set: {}", servers.join(", "))),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_ntp(state: &CliState, servers: &[&str]) {
    let ntp: Vec<&str> = servers.to_vec();
    match state.api_post("/api/settings", &json!({"ntp_servers": ntp})) {
        Ok(_) => print_ok(&format!("NTP servers set: {}", servers.join(", "))),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_fw_policy(state: &CliState, chain: &str, policy: &str) {
    if policy != "accept" && policy != "drop" {
        print_error("Policy must be 'accept' or 'drop'.");
        return;
    }
    let key = format!("{}_policy", chain);
    match state.api_post("/api/firewall", &json!({key: policy})) {
        Ok(_) => print_ok(&format!("{} policy set to '{}'", chain, policy)),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_nat_masquerade(state: &CliState, args: &[&str]) {
    if args.is_empty() {
        print_error("Usage: nat masquerade <wan-interface> [source-cidr]");
        return;
    }
    let iface = args[0];
    let source = args.get(1).copied().unwrap_or("0.0.0.0/0");
    match state.api_post(
        "/api/nat",
        &json!({
            "type": "masquerade",
            "interface": iface,
            "source": source
        }),
    ) {
        Ok(_) => print_ok(&format!(
            "Masquerade added: interface={}, source={}",
            iface, source
        )),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_nat_port_forward(state: &CliState, args: &[&str]) {
    if args.len() < 3 {
        print_error("Usage: nat port-forward <proto> <port> <dest-ip:port> [interface]");
        return;
    }
    let proto = args[0];
    let port = args[1];
    let dest = args[2];
    let iface = args.get(3).copied().unwrap_or("any");

    match state.api_post(
        "/api/nat",
        &json!({
            "type": "port_forward",
            "protocol": proto,
            "port": port,
            "destination": dest,
            "interface": iface
        }),
    ) {
        Ok(_) => print_ok(&format!(
            "Port forward added: {} {} -> {} (if={})",
            proto, port, dest, iface
        )),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_no_nat_masquerade(state: &CliState, index_str: &str) {
    let idx: usize = match index_str.parse() {
        Ok(i) => i,
        Err(_) => {
            print_error("Usage: no nat masquerade <index>");
            return;
        }
    };
    match state.api_delete(&format!("/api/nat/masquerade/{}", idx)) {
        Ok(_) => print_ok(&format!("Masquerade rule {} removed.", idx)),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_no_nat_port_forward(state: &CliState, index_str: &str) {
    let idx: usize = match index_str.parse() {
        Ok(i) => i,
        Err(_) => {
            print_error("Usage: no nat port-forward <index>");
            return;
        }
    };
    match state.api_delete(&format!("/api/nat/port_forward/{}", idx)) {
        Ok(_) => print_ok(&format!("Port forward rule {} removed.", idx)),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_route(state: &CliState, args: &[&str]) {
    // route <cidr> via <gw> [metric <n>]
    if args.len() < 3 || args[1] != "via" {
        print_error("Usage: route <cidr> via <gateway> [metric <n>]");
        return;
    }
    let cidr = args[0];
    let gw = args[2];
    let metric: u64 = if args.len() >= 5 && args[3] == "metric" {
        args[4].parse().unwrap_or(100)
    } else {
        100
    };

    match state.api_post(
        "/api/routes",
        &json!({
            "destination": cidr,
            "gateway": gw,
            "metric": metric
        }),
    ) {
        Ok(_) => print_ok(&format!(
            "Route added: {} via {} metric {}",
            cidr, gw, metric
        )),
        Err(e) => print_error(&e),
    }
}

fn cmd_config_no_route(state: &CliState, cidr: &str) {
    match state.api_delete(&format!("/api/routes/{}", cidr.replace('/', "%2F"))) {
        Ok(_) => print_ok(&format!("Route to {} removed.", cidr)),
        Err(e) => print_error(&e),
    }
}

// ---------------------------------------------------------------------------
// Interface config mode commands
// ---------------------------------------------------------------------------

fn cmd_if_ip_address(state: &CliState, iface: &str, args: &[&str]) {
    if args.is_empty() {
        print_error("Usage: ip address <cidr> | ip address dhcp");
        return;
    }
    if args[0] == "dhcp" {
        match state.api_put(
            &format!("/api/interfaces/{}", iface),
            &json!({"mode": "dhcp"}),
        ) {
            Ok(_) => print_ok(&format!("{}: set to DHCP mode.", iface)),
            Err(e) => print_error(&e),
        }
    } else {
        match state.api_put(
            &format!("/api/interfaces/{}", iface),
            &json!({"mode": "static", "ipv4_address": args[0]}),
        ) {
            Ok(_) => print_ok(&format!("{}: IP address set to {}", iface, args[0])),
            Err(e) => print_error(&e),
        }
    }
}

fn cmd_if_gateway(state: &CliState, iface: &str, gw: &str) {
    match state.api_put(
        &format!("/api/interfaces/{}", iface),
        &json!({"gateway": gw}),
    ) {
        Ok(_) => print_ok(&format!("{}: gateway set to {}", iface, gw)),
        Err(e) => print_error(&e),
    }
}

fn cmd_if_role(state: &CliState, iface: &str, role: &str) {
    if !["wan", "lan", "dmz"].contains(&role) {
        print_error("Role must be 'wan', 'lan', or 'dmz'.");
        return;
    }
    match state.api_put(
        &format!("/api/interfaces/{}", iface),
        &json!({"role": role}),
    ) {
        Ok(_) => print_ok(&format!("{}: role set to {}", iface, role)),
        Err(e) => print_error(&e),
    }
}

fn cmd_if_mtu(state: &CliState, iface: &str, mtu_str: &str) {
    let mtu: u64 = match mtu_str.parse() {
        Ok(v) => v,
        Err(_) => {
            print_error("MTU must be a number.");
            return;
        }
    };
    match state.api_put(
        &format!("/api/interfaces/{}", iface),
        &json!({"mtu": mtu}),
    ) {
        Ok(_) => print_ok(&format!("{}: MTU set to {}", iface, mtu)),
        Err(e) => print_error(&e),
    }
}

fn cmd_if_description(state: &CliState, iface: &str, desc: &str) {
    match state.api_put(
        &format!("/api/interfaces/{}", iface),
        &json!({"description": desc}),
    ) {
        Ok(_) => print_ok(&format!("{}: description set.", iface)),
        Err(e) => print_error(&e),
    }
}

fn cmd_if_dhcp_range(state: &CliState, iface: &str, start: &str, end: &str) {
    match state.api_put(
        &format!("/api/interfaces/{}", iface),
        &json!({"dhcp_range_start": start, "dhcp_range_end": end}),
    ) {
        Ok(_) => print_ok(&format!("{}: DHCP range set {}-{}", iface, start, end)),
        Err(e) => print_error(&e),
    }
}

fn cmd_if_no_dhcp(state: &CliState, iface: &str) {
    match state.api_put(
        &format!("/api/interfaces/{}", iface),
        &json!({"dhcp_range_start": null, "dhcp_range_end": null}),
    ) {
        Ok(_) => print_ok(&format!("{}: DHCP server disabled.", iface)),
        Err(e) => print_error(&e),
    }
}

fn cmd_if_shutdown(state: &CliState, iface: &str, enable: bool) {
    let body = if enable {
        json!({"admin_state": "up"})
    } else {
        json!({"admin_state": "down"})
    };
    match state.api_put(&format!("/api/interfaces/{}", iface), &body) {
        Ok(_) => {
            if enable {
                print_ok(&format!("{}: interface enabled.", iface));
            } else {
                print_ok(&format!("{}: interface disabled.", iface));
            }
        }
        Err(e) => print_error(&e),
    }
}

fn cmd_if_show(state: &CliState, iface: &str) {
    match state.api_get(&format!("/api/interfaces/{}", iface)) {
        Ok(data) => {
            println!();
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string())
            );
            println!();
        }
        Err(_) => {
            // Try getting all interfaces and filter
            match state.api_get("/api/interfaces") {
                Ok(all) => {
                    if let Some(interfaces) = all.get("interfaces").and_then(|v| v.as_array()) {
                        for i in interfaces {
                            if val_str(i, "name") == iface {
                                println!();
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(i)
                                        .unwrap_or_else(|_| i.to_string())
                                );
                                println!();
                                return;
                            }
                        }
                    }
                    print_error(&format!("Interface '{}' not found.", iface));
                }
                Err(e) => print_error(&e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Firewall rule config commands
// ---------------------------------------------------------------------------

fn cmd_fw_rule_apply(state: &CliState, rule: &FirewallRuleBuilder) {
    match state.api_post("/api/firewall", &json!({"rule": rule.to_json()})) {
        Ok(_) => print_ok(&format!("Rule '{}' applied.", rule.name)),
        Err(e) => print_error(&e),
    }
}

fn cmd_fw_rule_show(rule: &FirewallRuleBuilder) {
    println!();
    println!("  Rule: {}", rule.name.bold());
    println!(
        "    direction:        {}",
        rule.direction.as_deref().unwrap_or("(not set)")
    );
    println!(
        "    protocol:         {}",
        rule.protocol.as_deref().unwrap_or("(not set)")
    );
    println!(
        "    source:           {}",
        rule.source.as_deref().unwrap_or("(not set)")
    );
    println!(
        "    destination:      {}",
        rule.destination.as_deref().unwrap_or("(not set)")
    );
    println!(
        "    source-port:      {}",
        rule.source_port.as_deref().unwrap_or("(not set)")
    );
    println!(
        "    destination-port: {}",
        rule.destination_port.as_deref().unwrap_or("(not set)")
    );
    println!(
        "    in-interface:     {}",
        rule.in_interface.as_deref().unwrap_or("(not set)")
    );
    println!(
        "    out-interface:    {}",
        rule.out_interface.as_deref().unwrap_or("(not set)")
    );
    println!(
        "    action:           {}",
        rule.action.as_deref().unwrap_or("(not set)")
    );
    println!("    log:              {}", rule.log);
    println!("    enabled:          {}", rule.enabled);
    println!();
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

fn print_help(mode: &Mode) {
    println!();
    match mode {
        Mode::User => {
            println!("  {}", "Available commands:".bold().underline());
            println!("    show system              Show system information");
            println!("    show interfaces          Show interface details");
            println!("    show interfaces brief    Show interface summary");
            println!("    show firewall            Show firewall rules with counters");
            println!("    show firewall summary    Show chain policies and rule counts");
            println!("    show nat                 Show NAT rules");
            println!("    show routes              Show static routes");
            println!("    show connections          Show active connections");
            println!("    show connections count    Show connection count");
            println!("    show running-config      Show running configuration");
            println!("    show arp                 Show ARP table");
            println!("    show dhcp leases         Show DHCP leases");
            println!("    show version             Show QuickFW version");
            println!("    enable                   Enter privileged mode");
            println!("    exit                     Exit CLI");
        }
        Mode::Privileged => {
            println!("  {}", "Available commands:".bold().underline());
            println!("    show ...                 (all show commands from user mode)");
            println!("    show log [N]             Show last N journal entries (default 20)");
            println!("    configure [terminal]     Enter configuration mode");
            println!("    write memory             Save running configuration");
            println!("    reload                   Reboot the system");
            println!("    shutdown                 Power off the system");
            println!("    password admin           Change admin password");
            println!("    password root            Change root password");
            println!("    ssh enable|disable|status Manage SSH service");
            println!("    ping <host>              Ping a host");
            println!("    traceroute <host>        Traceroute to a host");
            println!("    shell                    Open a bash shell");
            println!("    factory-reset            Erase config and reboot");
            println!("    flush firewall           Flush rules, restore MGMT_SAFETY");
            println!("    exit                     Return to user mode");
        }
        Mode::Config => {
            println!("  {}", "Available commands:".bold().underline());
            println!("    hostname <name>                        Set system hostname");
            println!("    timezone <tz>                          Set timezone");
            println!("    dns-server <ip> [<ip2>]                Set DNS servers");
            println!("    ntp-server <ip> [<ip2>]                Set NTP servers");
            println!("    interface <name>                       Configure interface");
            println!("    firewall rule <name>                   Configure firewall rule");
            println!("    firewall input-policy <accept|drop>    Set INPUT chain policy");
            println!("    firewall forward-policy <accept|drop>  Set FORWARD chain policy");
            println!("    firewall output-policy <accept|drop>   Set OUTPUT chain policy");
            println!("    nat masquerade <wan-if> [<src-cidr>]   Add masquerade rule");
            println!("    nat port-forward <p> <port> <ip:port>  Add port forward");
            println!("    no nat masquerade <index>              Remove masquerade rule");
            println!("    no nat port-forward <index>            Remove port forward rule");
            println!("    route <cidr> via <gw> [metric <n>]     Add static route");
            println!("    no route <cidr>                        Remove static route");
            println!("    exit                                   Return to privileged mode");
        }
        Mode::ConfigInterface(name) => {
            println!(
                "  {} ({})",
                "Available commands:".bold().underline(),
                name
            );
            println!("    ip address <cidr>        Set static IP address");
            println!("    ip address dhcp          Set DHCP mode");
            println!("    gateway <ip>             Set default gateway");
            println!("    role <wan|lan|dmz>       Set interface role");
            println!("    mtu <value>              Set MTU");
            println!("    description <text>       Set description");
            println!("    dhcp-range <start> <end> Enable DHCP server");
            println!("    no dhcp-range            Disable DHCP server");
            println!("    shutdown                 Disable interface");
            println!("    no shutdown              Enable interface");
            println!("    show                     Show interface config");
            println!("    exit                     Return to config mode");
        }
        Mode::ConfigFirewallRule(name) => {
            println!(
                "  {} ({})",
                "Available commands:".bold().underline(),
                name
            );
            println!("    direction <forward|input|output>  Set rule direction");
            println!("    protocol <tcp|udp|icmp|any>       Set protocol");
            println!("    source <cidr|any>                 Set source address");
            println!("    destination <cidr|any>            Set destination address");
            println!("    source-port <port|any>            Set source port");
            println!("    destination-port <port|any>       Set destination port");
            println!("    in-interface <name|any>           Set input interface");
            println!("    out-interface <name|any>          Set output interface");
            println!("    action <accept|drop|reject|log>   Set rule action");
            println!("    log                               Enable logging");
            println!("    enable                            Enable rule");
            println!("    disable                           Disable rule");
            println!("    show                              Show rule config");
            println!("    exit                              Apply and return to config mode");
        }
    }
    println!();
}

// ---------------------------------------------------------------------------
// Command dispatcher
// ---------------------------------------------------------------------------

fn dispatch(state: &mut CliState, line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let cmd = parts[0];

    match &state.mode.clone() {
        Mode::User => dispatch_user(state, cmd, &parts),
        Mode::Privileged => dispatch_privileged(state, cmd, &parts),
        Mode::Config => dispatch_config(state, cmd, &parts),
        Mode::ConfigInterface(iface) => {
            let iface = iface.clone();
            dispatch_config_interface(state, &iface, cmd, &parts)
        }
        Mode::ConfigFirewallRule(name) => {
            let name = name.clone();
            dispatch_config_fw_rule(state, &name, cmd, &parts)
        }
    }
}

fn dispatch_user(state: &mut CliState, cmd: &str, parts: &[&str]) -> bool {
    match cmd {
        "show" => {
            if parts.len() < 2 {
                print_error("Incomplete command. Type '?' for help.");
                return true;
            }
            dispatch_show(state, &parts[1..]);
        }
        "enable" => {
            state.mode = Mode::Privileged;
        }
        "?" | "help" => print_help(&state.mode),
        "exit" | "quit" | "logout" => return false,
        _ => print_error(&format!(
            "Unknown command: '{}'. Type '?' for help.",
            cmd
        )),
    }
    true
}

fn dispatch_privileged(state: &mut CliState, cmd: &str, parts: &[&str]) -> bool {
    match cmd {
        "show" => {
            if parts.len() < 2 {
                print_error("Incomplete command. Type '?' for help.");
                return true;
            }
            dispatch_show(state, &parts[1..]);
        }
        "configure" => {
            // "configure" or "configure terminal"
            state.mode = Mode::Config;
        }
        "write" => {
            if parts.len() >= 2 && parts[1] == "memory" {
                cmd_write_memory(state);
            } else {
                print_error("Usage: write memory");
            }
        }
        "reload" => cmd_reload(state),
        "shutdown" => cmd_shutdown(),
        "password" => {
            if parts.len() < 2 {
                print_error("Usage: password <admin|root>");
                return true;
            }
            match parts[1] {
                "admin" => cmd_password_admin(state),
                "root" => cmd_password_root(),
                _ => print_error("Usage: password <admin|root>"),
            }
        }
        "ssh" => {
            if parts.len() < 2 {
                print_error("Usage: ssh <enable|disable|status>");
                return true;
            }
            cmd_ssh(parts[1]);
        }
        "ping" => {
            if parts.len() < 2 {
                print_error("Usage: ping <host>");
                return true;
            }
            cmd_ping(state, parts[1]);
        }
        "traceroute" => {
            if parts.len() < 2 {
                print_error("Usage: traceroute <host>");
                return true;
            }
            cmd_traceroute(state, parts[1]);
        }
        "shell" => cmd_shell(),
        "factory-reset" => cmd_factory_reset(),
        "flush" => {
            if parts.len() >= 2 && parts[1] == "firewall" {
                cmd_flush_firewall();
            } else {
                print_error("Usage: flush firewall");
            }
        }
        "?" | "help" => print_help(&state.mode),
        "exit" | "disable" => {
            state.mode = Mode::User;
        }
        _ => print_error(&format!(
            "Unknown command: '{}'. Type '?' for help.",
            cmd
        )),
    }
    true
}

fn dispatch_show(state: &CliState, args: &[&str]) {
    if args.is_empty() {
        print_error("Incomplete show command. Type '?' for help.");
        return;
    }

    match args[0] {
        "system" => cmd_show_system(state),
        "interfaces" => {
            let brief = args.len() >= 2 && args[1] == "brief";
            cmd_show_interfaces(state, brief);
        }
        "firewall" => {
            if args.len() >= 2 && args[1] == "summary" {
                cmd_show_firewall_summary(state);
            } else {
                cmd_show_firewall(state);
            }
        }
        "nat" => cmd_show_nat(state),
        "routes" => cmd_show_routes(state),
        "connections" => {
            if args.len() >= 2 && args[1] == "count" {
                cmd_show_connections_count(state);
            } else {
                cmd_show_connections(state);
            }
        }
        "running-config" => cmd_show_running_config(state),
        "arp" => cmd_show_arp(state),
        "dhcp" => {
            if args.len() >= 2 && args[1] == "leases" {
                cmd_show_dhcp_leases(state);
            } else {
                print_error("Usage: show dhcp leases");
            }
        }
        "version" => cmd_show_version(),
        "log" => {
            if matches!(state.mode, Mode::Privileged | Mode::Config) {
                cmd_show_log(state, &args[1..]);
            } else {
                print_error("'show log' requires privileged mode.");
            }
        }
        _ => print_error(&format!(
            "Unknown show target: '{}'. Type '?' for help.",
            args[0]
        )),
    }
}

fn dispatch_config(state: &mut CliState, cmd: &str, parts: &[&str]) -> bool {
    match cmd {
        "hostname" => {
            if parts.len() < 2 {
                print_error("Usage: hostname <name>");
                return true;
            }
            cmd_config_hostname(state, parts[1]);
        }
        "timezone" => {
            if parts.len() < 2 {
                print_error("Usage: timezone <tz>");
                return true;
            }
            cmd_config_timezone(state, parts[1]);
        }
        "dns-server" => {
            if parts.len() < 2 {
                print_error("Usage: dns-server <ip> [<ip2>]");
                return true;
            }
            cmd_config_dns(state, &parts[1..]);
        }
        "ntp-server" => {
            if parts.len() < 2 {
                print_error("Usage: ntp-server <ip> [<ip2>]");
                return true;
            }
            cmd_config_ntp(state, &parts[1..]);
        }
        "interface" => {
            if parts.len() < 2 {
                print_error("Usage: interface <name>");
                return true;
            }
            let iface = parts[1].to_string();
            state.current_interface = Some(iface.clone());
            state.mode = Mode::ConfigInterface(iface);
        }
        "firewall" => {
            if parts.len() < 2 {
                print_error("Usage: firewall rule <name> | firewall <chain>-policy <policy>");
                return true;
            }
            match parts[1] {
                "rule" => {
                    if parts.len() < 3 {
                        print_error("Usage: firewall rule <name>");
                        return true;
                    }
                    let name = parts[2].to_string();
                    state.current_rule = Some(FirewallRuleBuilder::new(&name));
                    state.mode = Mode::ConfigFirewallRule(name);
                }
                "input-policy" => {
                    if parts.len() < 3 {
                        print_error("Usage: firewall input-policy <accept|drop>");
                        return true;
                    }
                    cmd_config_fw_policy(state, "input", parts[2]);
                }
                "forward-policy" => {
                    if parts.len() < 3 {
                        print_error("Usage: firewall forward-policy <accept|drop>");
                        return true;
                    }
                    cmd_config_fw_policy(state, "forward", parts[2]);
                }
                "output-policy" => {
                    if parts.len() < 3 {
                        print_error("Usage: firewall output-policy <accept|drop>");
                        return true;
                    }
                    cmd_config_fw_policy(state, "output", parts[2]);
                }
                _ => print_error(&format!("Unknown firewall subcommand: '{}'", parts[1])),
            }
        }
        "nat" => {
            if parts.len() < 2 {
                print_error("Usage: nat masquerade ... | nat port-forward ...");
                return true;
            }
            match parts[1] {
                "masquerade" => cmd_config_nat_masquerade(state, &parts[2..]),
                "port-forward" => cmd_config_nat_port_forward(state, &parts[2..]),
                _ => print_error(&format!("Unknown nat subcommand: '{}'", parts[1])),
            }
        }
        "no" => {
            if parts.len() < 2 {
                print_error("Usage: no nat ... | no route ...");
                return true;
            }
            match parts[1] {
                "nat" => {
                    if parts.len() < 4 {
                        print_error("Usage: no nat masquerade <index> | no nat port-forward <index>");
                        return true;
                    }
                    match parts[2] {
                        "masquerade" => cmd_config_no_nat_masquerade(state, parts[3]),
                        "port-forward" => cmd_config_no_nat_port_forward(state, parts[3]),
                        _ => print_error(&format!("Unknown: no nat {}", parts[2])),
                    }
                }
                "route" => {
                    if parts.len() < 3 {
                        print_error("Usage: no route <cidr>");
                        return true;
                    }
                    cmd_config_no_route(state, parts[2]);
                }
                _ => print_error(&format!("Unknown: no {}", parts[1])),
            }
        }
        "route" => {
            cmd_config_route(state, &parts[1..]);
        }
        "show" => {
            if parts.len() >= 2 {
                dispatch_show(state, &parts[1..]);
            } else {
                print_error("Incomplete show command.");
            }
        }
        "?" | "help" => print_help(&state.mode),
        "exit" | "end" => {
            state.mode = Mode::Privileged;
        }
        _ => print_error(&format!(
            "Unknown command: '{}'. Type '?' for help.",
            cmd
        )),
    }
    true
}

fn dispatch_config_interface(
    state: &mut CliState,
    iface: &str,
    cmd: &str,
    parts: &[&str],
) -> bool {
    match cmd {
        "ip" => {
            if parts.len() < 2 || parts[1] != "address" {
                print_error("Usage: ip address <cidr> | ip address dhcp");
                return true;
            }
            cmd_if_ip_address(state, iface, &parts[2..]);
        }
        "gateway" => {
            if parts.len() < 2 {
                print_error("Usage: gateway <ip>");
                return true;
            }
            cmd_if_gateway(state, iface, parts[1]);
        }
        "role" => {
            if parts.len() < 2 {
                print_error("Usage: role <wan|lan|dmz>");
                return true;
            }
            cmd_if_role(state, iface, parts[1]);
        }
        "mtu" => {
            if parts.len() < 2 {
                print_error("Usage: mtu <value>");
                return true;
            }
            cmd_if_mtu(state, iface, parts[1]);
        }
        "description" => {
            if parts.len() < 2 {
                print_error("Usage: description <text>");
                return true;
            }
            let desc = parts[1..].join(" ");
            cmd_if_description(state, iface, &desc);
        }
        "dhcp-range" => {
            if parts.len() < 3 {
                print_error("Usage: dhcp-range <start-ip> <end-ip>");
                return true;
            }
            cmd_if_dhcp_range(state, iface, parts[1], parts[2]);
        }
        "shutdown" => {
            cmd_if_shutdown(state, iface, false);
        }
        "no" => {
            if parts.len() < 2 {
                print_error("Usage: no shutdown | no dhcp-range");
                return true;
            }
            match parts[1] {
                "shutdown" => cmd_if_shutdown(state, iface, true),
                "dhcp-range" => cmd_if_no_dhcp(state, iface),
                _ => print_error(&format!("Unknown: no {}", parts[1])),
            }
        }
        "show" => {
            cmd_if_show(state, iface);
        }
        "?" | "help" => print_help(&state.mode),
        "exit" | "end" => {
            state.current_interface = None;
            state.mode = Mode::Config;
        }
        _ => print_error(&format!(
            "Unknown command: '{}'. Type '?' for help.",
            cmd
        )),
    }
    true
}

fn dispatch_config_fw_rule(
    state: &mut CliState,
    _name: &str,
    cmd: &str,
    parts: &[&str],
) -> bool {
    // Get mutable reference to the current rule
    match cmd {
        "direction" => {
            if parts.len() < 2 {
                print_error("Usage: direction <forward|input|output>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.direction = Some(parts[1].to_string());
                print_ok(&format!("direction set to '{}'", parts[1]));
            }
        }
        "protocol" => {
            if parts.len() < 2 {
                print_error("Usage: protocol <tcp|udp|icmp|any>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.protocol = Some(parts[1].to_string());
                print_ok(&format!("protocol set to '{}'", parts[1]));
            }
        }
        "source" => {
            if parts.len() < 2 {
                print_error("Usage: source <cidr|any>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.source = Some(parts[1].to_string());
                print_ok(&format!("source set to '{}'", parts[1]));
            }
        }
        "destination" => {
            if parts.len() < 2 {
                print_error("Usage: destination <cidr|any>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.destination = Some(parts[1].to_string());
                print_ok(&format!("destination set to '{}'", parts[1]));
            }
        }
        "source-port" => {
            if parts.len() < 2 {
                print_error("Usage: source-port <port|any>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.source_port = Some(parts[1].to_string());
                print_ok(&format!("source-port set to '{}'", parts[1]));
            }
        }
        "destination-port" => {
            if parts.len() < 2 {
                print_error("Usage: destination-port <port|any>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.destination_port = Some(parts[1].to_string());
                print_ok(&format!("destination-port set to '{}'", parts[1]));
            }
        }
        "in-interface" => {
            if parts.len() < 2 {
                print_error("Usage: in-interface <name|any>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.in_interface = Some(parts[1].to_string());
                print_ok(&format!("in-interface set to '{}'", parts[1]));
            }
        }
        "out-interface" => {
            if parts.len() < 2 {
                print_error("Usage: out-interface <name|any>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.out_interface = Some(parts[1].to_string());
                print_ok(&format!("out-interface set to '{}'", parts[1]));
            }
        }
        "action" => {
            if parts.len() < 2 {
                print_error("Usage: action <accept|drop|reject|log>");
                return true;
            }
            if let Some(ref mut rule) = state.current_rule {
                rule.action = Some(parts[1].to_string());
                print_ok(&format!("action set to '{}'", parts[1]));
            }
        }
        "log" => {
            if let Some(ref mut rule) = state.current_rule {
                rule.log = true;
                print_ok("logging enabled");
            }
        }
        "enable" => {
            if let Some(ref mut rule) = state.current_rule {
                rule.enabled = true;
                print_ok("rule enabled");
            }
        }
        "disable" => {
            if let Some(ref mut rule) = state.current_rule {
                rule.enabled = false;
                print_ok("rule disabled");
            }
        }
        "show" => {
            if let Some(ref rule) = state.current_rule {
                cmd_fw_rule_show(rule);
            }
        }
        "?" | "help" => print_help(&state.mode),
        "exit" | "end" => {
            // Apply the rule via API then return to config mode
            if let Some(ref rule) = state.current_rule {
                cmd_fw_rule_apply(state, rule);
            }
            state.current_rule = None;
            state.mode = Mode::Config;
        }
        _ => print_error(&format!(
            "Unknown command: '{}'. Type '?' for help.",
            cmd
        )),
    }
    true
}

// ---------------------------------------------------------------------------
// Startup banner
// ---------------------------------------------------------------------------

fn print_banner() {
    println!();
    println!(
        "{}",
        "\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}"
            .cyan()
    );
    println!(
        "{}{}{}",
        "\u{2551}".cyan(),
        format!("         QuickFW v{}                    ", VERSION).white().bold(),
        "\u{2551}".cyan()
    );
    println!(
        "{}{}{}",
        "\u{2551}".cyan(),
        "         Firewall Appliance                ".white(),
        "\u{2551}".cyan()
    );
    println!(
        "{}{}{}",
        "\u{2551}".cyan(),
        "                                           ".white(),
        "\u{2551}".cyan()
    );
    println!(
        "{}{}{}",
        "\u{2551}".cyan(),
        "  Console ready. Type ? for help.          ".white(),
        "\u{2551}".cyan()
    );
    println!(
        "{}",
        "\u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}"
            .cyan()
    );
    println!();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    print_banner();

    let mut state = CliState::new();

    let history_path = dirs_home().join(HISTORY_FILE);

    let helper = CliHelper::new(state.mode.clone());
    let config = rustyline::Config::builder()
        .history_ignore_space(true)
        .completion_type(rustyline::CompletionType::List)
        .build();

    let mut rl: Editor<CliHelper, rustyline::history::DefaultHistory> =
        Editor::with_config(config).expect("Failed to create editor");
    rl.set_helper(Some(helper));

    let _ = rl.load_history(&history_path);

    loop {
        // Update helper to match current mode
        rl.set_helper(Some(CliHelper::new(state.mode.clone())));

        let prompt = state.prompt();
        match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    let _ = rl.add_history_entry(&trimmed);
                    if !dispatch(&mut state, &trimmed) {
                        break;
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C — ignore, just show new prompt
                println!();
            }
            Err(ReadlineError::Eof) => {
                // Ctrl+D — exit
                println!();
                break;
            }
            Err(err) => {
                print_error(&format!("Input error: {}", err));
                break;
            }
        }
    }

    let _ = rl.save_history(&history_path);

    println!("  Goodbye.");
}

// ---------------------------------------------------------------------------
// Utility: get home directory without additional deps
// ---------------------------------------------------------------------------

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/root"))
}
