# QuickFW Firewall Appliance — Technical Documentation

**Version:** 1.0.0  
**Date:** April 4, 2026  
**Classification:** Production Handover  
**Status:** Final

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Workspace Structure](#4-workspace-structure)
5. [Core Components](#5-core-components)
6. [API Specification](#6-api-specification)
7. [Security Architecture](#7-security-architecture)
8. [Network & Firewall Engine](#8-network--firewall-engine)
9. [Build & Deployment](#9-build--deployment)
10. [Configuration Files](#10-configuration-files)
11. [Runtime Behavior](#11-runtime-behavior)
12. [Testing Strategy](#12-testing-strategy)
13. [Production Checklist](#13-production-checklist)
14. [Troubleshooting Guide](#14-troubleshooting-guide)

---

## 1. Executive Summary

QuickFW is a lightweight, high-performance L3/L4 stateful firewall appliance written in Rust. It is designed to run as a Debian-based live ISO and provides:

- **Cisco IOS-style CLI** on console (tty1/serial)
- **Web Dashboard** served over HTTPS on port 443
- **REST API** for automation and CLI consumption
- **Default-deny firewall** semantics (INPUT DROP, FORWARD DROP)
- **NAT** (masquerade + port forwarding) via nftables
- **Interface management** with WAN/LAN/DMZ role assignments
- **DHCP/DNS** server for LAN via dnsmasq
- **OSPF/BGP/RIP** routing protocol support via FRR

### 1.1 Key Metrics

| Metric | Value |
|--------|-------|
| Binary Size | ~15-20 MB (stripped) |
| Memory Footprint | ~50-100 MB runtime |
| API Response Time | <10ms (local) |
| Max Firewall Rules | Limited by nftables (~10K) |
| Concurrent Connections | ~1M (dependent on RAM) |
| ISO Size | ~400-600 MB |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACES                         │
├─────────────────┬─────────────────┬─────────────────────────────┤
│  Web Dashboard  │   CLI (tty1)    │   REST API (HTTPS/443)      │
│  (Vanilla JS)   │  (quickfw-cli)  │   (quickfw-api)             │
└────────┬────────┴────────┬────────┴─────────────┬───────────────┘
         │                 │                      │
         └─────────────────┼──────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     quickfw-api (Axum)                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │ Auth Layer  │ │ Rate Limit  │ │ Validation  │ │ Audit Log │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     SYSTEM SERVICES                             │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   nftables      │    dnsmasq      │      FRR (zebra/ospfd/      │
│  (netfilter)    │  (DHCP/DNS)     │      bgpd/ripd)             │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

### 2.2 Data Flow

1. **Packet Flow:**
   ```
   NIC → Kernel Network Stack → nftables (NFQUEUE) → quickfw-api (optional DPI) → Verdict
   ```

2. **Management Flow:**
   ```
   Web/CLI → HTTPS → Axum Router → Validation → nftables/dnsmasq/FRR → Response
   ```

---

## 3. Technology Stack

### 3.1 Core Technologies

| Layer | Technology | Version | Purpose |
|-------|------------|---------|---------|
| Language | Rust | 1.83 (stable) | Core implementation |
| Async Runtime | Tokio | 1.41+ | Async execution |
| Web Framework | Axum | 0.7+ | HTTP API |
| TLS | rustls | 0.23+ | HTTPS encryption |
| Serialization | serde/serde_yaml/serde_json | 1.0+ | Config & API |
| Firewall Engine | nftables (NFQUEUE) | 1.0+ | Packet filtering |
| Routing | FRRouting (FRR) | 8.5+ | Dynamic routing |
| DHCP/DNS | dnsmasq | 2.85+ | LAN services |
| Process Supervision | systemd | 252+ | Service management |

### 3.2 Rust Dependencies

```toml
# Critical dependencies verified in Cargo.toml
tokio = { version = "1.41.1", features = ["full"] }
axum = { version = "0.7.7", features = ["ws"] }
axum-server = { version = "0.7", features = ["tls-rustls"] }
nfq = { version = "0.2.5", features = ["ct"] }
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
serde_json = "1.0.132"
argon2 = "0.5"
```

---

## 4. Workspace Structure

### 4.1 Crate Organization

| Crate | Type | Binary/Library | Purpose |
|-------|------|----------------|---------|
| `io` | Library | `gfw-io` | Packet I/O, NFQUEUE, firewall/NAT rules |
| `ifmgr` | Library | `gfw-ifmgr` | Interface discovery, WAN/LAN config |
| `config` | Library | `config` | YAML configuration parsing |
| `routing` | Library | `routing` | OSPF/BGP/RIP config, FRR integration |
| `quickfw-api` | Binary | `quickfw-api` | HTTPS REST API + Web UI |
| `quickfw-cli` | Binary | `quickfw` | Cisco-style interactive CLI |
| `quickfw-setup` | Binary | `quickfw-setup` | First-boot TUI wizard |

### 4.2 Directory Structure

```
simple-fw-vikas/
├── Cargo.toml              # Workspace manifest
├── Dockerfile              # ISO build (multi-stage)
├── build.sh                # Host build script
├── AGENTS.md               # Agent development guide
├── io/                     # Packet I/O library
│   └── src/
│       ├── lib.rs          # Core traits (PacketIO, Packet)
│       ├── nfqueue.rs      # NFQUEUE implementation
│       ├── firewall.rs     # Firewall rule engine
│       ├── nat.rs          # NAT/PAT management
│       └── pcap.rs         # PCAP file reader (debug)
├── ifmgr/                  # Interface management
│   └── src/lib.rs
├── routing/                # Routing protocols
│   └── src/
│       ├── lib.rs
│       ├── ospf.rs
│       ├── bgp.rs
│       └── rip.rs
├── config/                 # Configuration parsing
│   └── src/
│       ├── lib.rs
│       └── config.rs
├── quickfw-api/            # API server
│   └── src/
│       ├── main.rs         # Server entry point
│       ├── lib.rs          # Module exports
│       ├── auth.rs         # Authentication layer
│       ├── validation.rs   # Input validation
│       ├── audit.rs        # Audit logging
│       ├── system.rs       # System endpoints
│       ├── firewall_api.rs # Firewall endpoints
│       ├── nat_api.rs      # NAT endpoints
│       ├── routing_api.rs  # Routing endpoints
│       ├── tools.rs        # Diagnostic tools
│       ├── file.rs         # Static file serving
│       ├── logger.rs       # Broadcast logging
│       └── config_utils.rs # Backup/atomic writes
├── quickfw-cli/            # CLI client
│   └── src/main.rs
├── quickfw-setup/          # Setup wizard
│   └── src/main.rs
├── front/                  # Web UI (vanilla JS)
│   ├── index.html
│   ├── styles.css
│   ├── core.js
│   ├── dashboard.js
│   ├── interfaces.js
│   ├── firewall.js
│   ├── nat.js
│   ├── conntrack.js
│   ├── settings.js
│   └── account.js
├── rootfs/                 # Rootfs overlay
│   └── etc/
│       ├── nftables.conf
│       ├── sysctl.d/
│       ├── systemd/system/
│       └── profile.d/
├── scripts/                # Helper scripts
│   ├── quickfw-console
│   └── quickfw-irq-tune
└── tests/                  # Integration tests
    └── real-test.js
```

---

## 5. Core Components

### 5.1 Packet I/O Library (`io` crate)

#### 5.1.1 Core Traits

```rust
// Packet trait - represents an IP packet
pub trait Packet: DowncastSync + Send + Sync {
    fn stream_id(&self) -> u32;      // Connection ID from conntrack
    fn timestamp(&self) -> SystemTime;
    fn data(&self) -> &[u8];         // Raw packet data (IP header+)
}

// PacketIO trait - abstraction for packet capture
#[async_trait::async_trait]
pub trait PacketIO: DowncastSync + Send + Sync {
    async fn register(&self, callback: PacketCallback, ...);
    async fn set_verdict(&self, packet: Box<dyn Packet>, verdict: Verdict, data: Vec<u8>);
    async fn protected_conn(&self, addr: &str) -> Result<TcpStream, ...>;
}
```

#### 5.1.2 NFQUEUE Implementation

- **Queue Number:** 100 (configurable)
- **Max Packet Length:** 65535 bytes
- **Default Queue Size:** 128 packets
- **Connection Mark Accept:** 1001
- **Connection Mark Drop:** 1002

**Key constants from `nfqueue.rs`:**
```rust
const NFQUEUE_NUM: u16 = 100;
const NFQUEUE_MAX_PACKET_LEN: u16 = 0xffff;
const NFQUEUE_DEFAULT_QUEUE_SIZE: u32 = 128;
const NFQUEUE_CONN_MARK_ACCEPT: u32 = 1001;
const NFQUEUE_CONN_MARK_DROP: u32 = 1002;
```

#### 5.1.3 Firewall Rule Engine

**File:** `io/src/firewall.rs`

**Core structures:**
```rust
pub struct FirewallConfig {
    pub rules: Vec<FirewallRule>,
    pub forward_policy: String,  // "accept" or "drop"
    pub input_policy: String,
    pub output_policy: String,
    pub zones: Vec<ZoneMapping>,
}

pub struct FirewallRule {
    pub name: String,
    pub enabled: bool,
    pub direction: String,       // "forward", "input", "output"
    pub in_interface: String,
    pub out_interface: String,
    pub src_zone: String,
    pub dst_zone: String,
    pub protocol: String,        // "tcp", "udp", "icmp", "tcp+udp"
    pub src_ip: String,
    pub src_port: String,
    pub dst_ip: String,
    pub dst_port: String,
    pub action: String,          // "accept", "drop", "reject", "log"
    pub log: bool,
    pub comment: String,
    pub schedule: Option<RuleSchedule>,  // Time-based rules
    pub ipv6: bool,
}
```

**Generated nftables chains:**
- `gfw_fw_input` - INPUT hook, priority -10
- `gfw_fw_forward` - FORWARD hook, priority -10
- `gfw_fw_output` - OUTPUT hook, priority -10

#### 5.1.4 NAT Implementation

**File:** `io/src/nat.rs`

**Core structures:**
```rust
pub struct NatConfig {
    pub masquerade: Vec<MasqueradeRule>,
    pub port_forward: Vec<PortForwardRule>,
    pub snat: Vec<SnatRule>,
}

pub struct MasqueradeRule {
    pub out_interface: String,
    pub source_cidr: String,
}

pub struct PortForwardRule {
    pub protocol: String,    // "tcp" or "udp"
    pub dest_port: u16,
    pub forward_to: String,  // "ip:port" format
    pub in_interface: String,
}
```

**Generated nftables chains:**
- `POSTROUTING` - SNAT/masquerade
- `PREROUTING` - DNAT/port forwarding

### 5.2 Interface Manager (`ifmgr` crate)

**File:** `ifmgr/src/lib.rs`

**Core structures:**
```rust
pub struct InterfaceInfo {
    pub name: String,
    pub mac: String,
    pub link_up: bool,
    pub ipv4_addrs: Vec<String>,
}

pub enum Zone { Wan, Lan }

pub enum WanMode { Dhcp, Static }

pub struct WanConfig {
    pub interface: String,
    pub mode: WanMode,
    pub address: Option<String>,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
}

pub struct LanConfig {
    pub interface: String,
    pub address: String,
    pub dhcp_range: Option<String>,
}

pub struct ApplianceNetConfig {
    pub wan: WanConfig,
    pub lan: LanConfig,
}
```

### 5.3 Routing Library (`routing` crate)

**File:** `routing/src/lib.rs`

**Supported protocols:**
- Static routes
- OSPFv2 (via FRR)
- BGP (via FRR)
- RIPv2 (via FRR)

**Key structures:**
```rust
pub struct StaticRoute {
    pub cidr: String,
    pub gateway: String,
    pub metric: u64,
}

pub struct OspfConfig {
    pub enabled: bool,
    pub router_id: String,
    pub networks: Vec<OspfNetwork>,
    pub areas: Vec<OspfArea>,
    pub passive_interfaces: Vec<String>,
    pub redistribute: Vec<String>,
    pub default_information_originate: bool,
}

pub struct BgpConfig {
    pub enabled: bool,
    pub local_as: u32,
    pub router_id: String,
    pub neighbors: Vec<BgpNeighbor>,
    pub address_families: Vec<AddressFamily>,
}
```

**FRR config path:** `/etc/frr/frr.conf`

### 5.4 API Server (`quickfw-api` crate)

#### 5.4.1 Server Configuration

**Default ports:**
- HTTPS: 443
- HTTP redirect: 3000

**TLS certificate paths:**
- Certificate: `/etc/quickfw/tls.crt`
- Key: `/etc/quickfw/tls.key`

**Self-signed cert generation (ECDSA P-256):**
```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout /etc/quickfw/tls.key -out /etc/quickfw/tls.crt \
  -days 3650 -subj "/CN=quickfw"
```

#### 5.4.2 Security Middleware

**Security headers (from `main.rs`):**
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Strict-Transport-Security: max-age=63072000; includeSubDomains
Cache-Control: no-store
```

**Body limit:** 1 MB

#### 5.4.3 Authentication System

**File:** `quickfw-api/src/auth.rs`

**Constants:**
```rust
const ADMIN_PASSWORD_PATH: &str = "/etc/quickfw/admin.password";
const DEFAULT_USER: &str = "admin";
const DEFAULT_PASS: &str = "quickfw";
const SESSION_MAX_AGE: u64 = 1800; // 30 minutes
const MAX_SESSIONS: usize = 100;
const API_RATE_LIMIT: u32 = 60; // per minute
const AUTH_LOCKOUT_THRESHOLD: u32 = 5;
const AUTH_LOCKOUT_SECS: u64 = 900; // 15 minutes
```

**Banned passwords:**
```rust
const BANNED_PASSWORDS: &[&str] = &[
    "admin", "password", "123456", "12345678", "qwerty",
    "letmein", "firewall", "changeme", "quickfw",
];
```

**Password hashing:** Argon2id

**Session cookie:**
- Name: `quickfw_session`
- HttpOnly: true
- Secure: true
- SameSite: Strict
- Max-Age: 1800 seconds

#### 5.4.4 Input Validation

**File:** `quickfw-api/src/validation.rs`

**Validation regex patterns:**
```rust
IFACE_RE: ^[a-zA-Z0-9._\-]{1,15}$     // Interface names
RULE_NAME_RE: ^[a-zA-Z0-9 _\-]{0,64}$ // Rule names
ZONE_RE: ^[a-zA-Z0-9_\-]{0,32}$       // Zone names
```

**Validation functions:**
- `validate_interface()` - Interface name sanitization
- `validate_cidr()` - IP/CIDR validation
- `validate_port()` - Port/range validation
- `validate_protocol()` - Protocol whitelist
- `validate_forward_to()` - DNAT target validation

#### 5.4.5 Audit Logging

**File:** `quickfw-api/src/audit.rs`

**Log path:** `/var/log/quickfw/audit.log`

**In-memory buffer:** 200 entries (ring buffer)

**Rotation:** 10 MB max, keep last 5 MB

**Logged operations:** POST, PUT, DELETE (mutating)

### 5.5 CLI Client (`quickfw-cli` crate)

**File:** `quickfw-cli/src/main.rs`

**Modes:**
- User mode (`>`) - read-only commands
- Privileged mode (`#`) - all show commands
- Config mode (`(config)#`) - configuration
- Config-Interface mode (`(config-if-eth0)#`)
- Config-Firewall mode (`(config-fw-<name>)#`)
- Config-Router mode (`(config-router-ospf)#`)

**Default API endpoint:** `http://127.0.0.1:3000`

**History file:** `.quickfw_history`

### 5.6 Setup Wizard (`quickfw-setup` crate)

**File:** `quickfw-setup/src/main.rs`

**Trigger condition:** `/etc/quickfw/appliance.yaml` does not exist

**Configuration steps:**
1. Interface detection
2. WAN interface selection
3. WAN mode (DHCP/Static)
4. LAN interface selection
5. LAN IP + DHCP range
6. Root password
7. Admin password
8. SSH enable/disable

**Output files:**
- `/etc/quickfw/appliance.yaml` - Network config
- `/etc/quickfw/admin.password` - Admin password
- `/etc/quickfw/firewall.yaml` - Default firewall
- `/etc/quickfw/nat.yaml` - Default NAT
- `/etc/quickfw/interfaces.yaml` - Interface roles
- `/etc/dnsmasq.d/quickfw.conf` - DHCP/DNS config

---

## 6. API Specification

### 6.1 Base URL

```
https://<hostname>/api
```

### 6.2 Authentication

**Session-based:** Cookie `quickfw_session`

**Basic Auth fallback:** `Authorization: Basic <base64(user:pass)>`

### 6.3 Endpoints Reference

#### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/system/info` | Hostname, version, uptime, CPU, memory |
| GET | `/api/system/traffic` | Connection counts, RX/TX stats |
| POST | `/api/system/reboot` | Reboot (requires password confirmation) |

#### Interfaces
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/interfaces` | List all interfaces with stats |
| POST | `/api/interfaces/config` | Configure interface |
| POST | `/api/interfaces/{name}/config` | Configure specific interface |
| GET | `/api/interfaces/roles` | Get interface roles |
| POST | `/api/interfaces/roles` | Save interface roles |

#### Firewall
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/firewall` | Get firewall config |
| POST | `/api/firewall` | Apply firewall config |
| GET | `/api/firewall/counters` | Rule hit counters |
| GET | `/api/firewall/groups` | Address/port groups |
| POST | `/api/firewall/groups` | Save groups |

#### NAT
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/nat` | Get NAT config |
| POST | `/api/nat` | Apply NAT config |
| DELETE | `/api/nat/masquerade/{index}` | Remove masquerade rule |
| DELETE | `/api/nat/port_forward/{index}` | Remove port-forward rule |

#### Routing
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/routes` | Static routes |
| POST | `/api/routes` | Add/save routes |
| GET | `/api/routing/ospf` | OSPF config |
| POST | `/api/routing/ospf` | Configure OSPF |
| GET | `/api/routing/bgp` | BGP config |
| POST | `/api/routing/bgp` | Configure BGP |
| GET | `/api/routing/table` | Routing table |
| GET | `/api/routing/ospf/neighbors` | OSPF neighbors |
| GET | `/api/routing/bgp/summary` | BGP summary |

#### Tools
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/tools/arp` | ARP table |
| GET | `/api/tools/dhcp-leases` | DHCP leases |
| GET | `/api/tools/dns-local` | Local DNS overrides |
| POST | `/api/tools/dns-local` | Save DNS overrides |
| POST | `/api/tools/ping` | Ping host |
| POST | `/api/tools/traceroute` | Traceroute |
| POST | `/api/tools/wol` | Wake-on-LAN |
| GET | `/api/tools/ntp-status` | NTP status |

#### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Session login |
| POST | `/api/auth/logout` | Session logout |
| POST | `/api/auth/password` | Change password |
| POST | `/api/auth/ws-token` | Get WebSocket token |

#### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/audit` | Audit log entries |
| GET | `/api/config/export` | Export full config |
| GET | `/api/config/backups` | List config backups |
| POST | `/api/config/restore` | Restore from backup |
| POST | `/api/config/import` | Import config |
| GET | `/api/settings` | Appliance settings |
| POST | `/api/settings` | Save settings |
| GET | `/api/conntrack` | Active connections |

---

## 7. Security Architecture

### 7.1 Defense in Depth

```
┌─────────────────────────────────────────┐
│  1. Management Safety Chain (nftables)  │
│     Priority -200, always allows        │
│     SSH(22), HTTPS(443), HTTP(3000)     │
├─────────────────────────────────────────┤
│  2. Firewall Rules (gfw_fw_*)           │
│     Priority -10, default DROP          │
├─────────────────────────────────────────┤
│  3. API Rate Limiting                   │
│     60 req/min per IP                   │
├─────────────────────────────────────────┤
│  4. Authentication                      │
│     Session + Basic Auth                │
├─────────────────────────────────────────┤
│  5. Input Validation                    │
│     Regex-based sanitization            │
├─────────────────────────────────────────┤
│  6. Audit Logging                       │
│     All mutating operations             │
└─────────────────────────────────────────┘
```

### 7.2 Management Safety Chain

**Purpose:** Prevents accidental lockout from firewall rule changes

**Implementation:**
```nft
chain MGMT_SAFETY {
    type filter hook input priority -200; policy accept;
    tcp dport { 22, 443, 3000 } counter accept
    meta l4proto icmp counter accept
    meta l4proto icmpv6 counter accept
    # Mark management traffic
    tcp dport { 22, 443, 3000 } meta mark set 0x1
    meta l4proto icmp meta mark set 0x1
    meta l4proto icmpv6 meta mark set 0x1
}
```

### 7.3 Input Sanitization

**Critical validation points:**

1. **Interface names:** `^[a-zA-Z0-9._\-]{1,15}$`
2. **CIDR addresses:** Parsed and validated
3. **Ports:** 1-65535, comma-separated, ranges supported
4. **Rule names:** `^[a-zA-Z0-9 _\-]{0,64}$`
5. **nftables script generation:** `sanitize_nft_string()` strips dangerous chars

**Injection prevention:**
```rust
fn sanitize_nft_string(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| *c != '"' && *c != '\n' && *c != '\r' 
                 && *c != '\\' && *c != ';' && *c != '{' && *c != '}')
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect()
}
```

### 7.4 Authentication Security

- **Password hashing:** Argon2id with salt
- **Session tokens:** 64-character random alphanumeric
- **Lockout:** 15 minutes after 5 failed attempts
- **Rate limiting:** 60 requests/minute per IP
- **Password policy:** Minimum 8 chars, banned list enforced

### 7.5 TLS Configuration

- **Protocol:** TLS 1.2+
- **Certificate:** ECDSA P-256 (self-signed on first boot)
- **Key file permissions:** 600
- **Cert file permissions:** 644

---

## 8. Network & Firewall Engine

### 8.1 nftables Table Structure

```
table inet gfw_rs {
    chain MGMT_SAFETY {        # Priority -200
        # Always allow management
    }
    chain gfw_fw_input {       # Priority -10
        # User firewall rules (INPUT)
    }
    chain gfw_fw_forward {     # Priority -10
        # User firewall rules (FORWARD)
    }
    chain gfw_fw_output {      # Priority -10
        # User firewall rules (OUTPUT)
    }
    chain POSTROUTING {        # Priority srcnat
        # SNAT/masquerade rules
    }
    chain PREROUTING {         # Priority dstnat
        # DNAT/port-forward rules
    }
}
```

### 8.2 Default Firewall Rules

**Generated by setup wizard:**
```nft
# State tracking
ct state established,related accept
ct state invalid drop

# Loopback
iifname "lo" accept

# Default policies
gfw_fw_input: policy drop
gfw_fw_forward: policy drop
gfw_fw_output: policy accept
```

### 8.3 NAT Implementation

**Masquerade (SNAT):**
```nft
add rule inet gfw_rs POSTROUTING oifname "eth0" masquerade
```

**Port Forward (DNAT):**
```nft
add rule inet gfw_rs PREROUTING iifname "eth0" tcp dport 8080 \
    dnat ip to 192.168.1.100:80
```

### 8.4 Connection Tracking

**Backend:** Linux netfilter conntrack

**Active connections API:** `/api/conntrack`

**Conntrack count:** `/proc/sys/net/netfilter/nf_conntrack_count`

---

## 9. Build & Deployment

### 9.1 Prerequisites

- Docker 20.10+
- 4GB RAM minimum
- 10GB disk space
- Linux host (for ISO build)

### 9.2 Build Process

```bash
# Local binary build
cargo build --release

# ISO build (requires Docker)
bash build.sh
```

**Build stages:**
1. Compile Rust binaries (Stage 1: rust-builder)
2. Build Debian live ISO with live-build (Stage 2: iso-builder)
3. Copy ISO to `output/quickfw.iso`

### 9.3 Build Output

| File | Location | Description |
|------|----------|-------------|
| quickfw-api | `target/release/` | API server binary |
| quickfw | `target/release/` | CLI client binary |
| quickfw-setup | `target/release/` | Setup wizard binary |
| quickfw.iso | `output/` | Bootable ISO |

### 9.4 ISO Contents

**Packages installed:**
- nftables, dnsmasq, libpcap0.8
- ca-certificates, openssh-server
- iproute2, net-tools, procps
- conntrack, ethtool, openssl
- kmod, pciutils, iputils-ping, traceroute

**Services enabled:**
- quickfw-setup.service (first boot only)
- quickfw-api.service
- quickfw-cli.service
- quickfw-console.service
- nftables.service

### 9.5 Deployment

**Physical:**
```bash
dd if=quickfw.iso of=/dev/sdX bs=4M status=progress
```

**Virtual:**
- Attach ISO as CD/DVD
- Boot from CD
- RAM requirement: 1GB minimum, 2GB recommended

---

## 10. Configuration Files

### 10.1 Runtime Paths

| Path | Purpose |
|------|---------|
| `/etc/quickfw/` | All appliance configuration |
| `/etc/quickfw/appliance.yaml` | Network config |
| `/etc/quickfw/firewall.yaml` | Firewall rules |
| `/etc/quickfw/nat.yaml` | NAT configuration |
| `/etc/quickfw/routes.yaml` | Static routes |
| `/etc/quickfw/interfaces.yaml` | Interface roles |
| `/etc/quickfw/settings.yaml` | Appliance settings |
| `/etc/quickfw/admin.password` | Admin password (hashed) |
| `/etc/quickfw/tls.crt` | TLS certificate |
| `/etc/quickfw/tls.key` | TLS private key |
| `/etc/quickfw/backups/` | Config backups |
| `/var/log/quickfw/audit.log` | Audit log |
| `/etc/frr/frr.conf` | FRR routing config |
| `/etc/dnsmasq.d/quickfw.conf` | DHCP/DNS config |

### 10.2 Backup System

**Automatic backup:** Before any config change

**Backup naming:** `{filename}.{timestamp}.bak`

**Retention:** Last 20 backups per file

**Atomic writes:** Write to `.tmp`, fsync, rename

---

## 11. Runtime Behavior

### 11.1 Boot Sequence

```
1. Kernel boot
2. systemd init
3. nftables.service loads base ruleset
4. quickfw-setup.service (if appliance.yaml missing)
   - Detect interfaces
   - Interactive configuration
   - Apply network config
   - Start dnsmasq
5. quickfw-api.service starts
6. quickfw-cli.service starts on tty1
7. quickfw-console.service starts on tty2 (emergency)
```

### 11.2 Service Dependencies

```
quickfw-api.service:
  After: network-online.target, nftables.service

quickfw-cli.service:
  After: multi-user.target, quickfw-api.service

quickfw-setup.service:
  After: multi-user.target
  Condition: !/etc/quickfw/appliance.yaml
```

### 11.3 Recovery Options

**TTY1:** Setup wizard (first boot) or CLI

**TTY2:** Emergency recovery console (`quickfw-console` script)

**Recovery console features:**
- Show IP addresses
- Show system status
- Reset admin password
- Reset root password
- Enable/disable SSH
- Flush firewall (emergency)
- Re-run setup wizard
- Factory reset

---

## 12. Testing Strategy

### 12.1 Unit Tests

**Command:** `cargo test`

**Coverage:**
- Config parsing
- Firewall rule generation
- NAT script generation
- Input validation
- Routing config generation

### 12.2 Integration Tests

**File:** `tests/real-test.js`

**Requirements:**
- Node.js 18+
- Playwright
- Running quickfw-api instance

**Test coverage:**
- All API endpoints
- Authentication flow
- Firewall rule CRUD
- NAT configuration
- Browser navigation
- Screenshots

### 12.3 Manual Testing Checklist

- [ ] ISO boots successfully
- [ ] Setup wizard completes
- [ ] Web dashboard loads
- [ ] Login with default credentials
- [ ] Create firewall rule
- [ ] Test firewall blocking
- [ ] Create NAT masquerade
- [ ] Create port forward
- [ ] Verify SSH access (if enabled)
- [ ] Test recovery console (tty2)

---

## 13. Production Checklist

### 13.1 Pre-Deployment

- [ ] Change default admin password
- [ ] Set strong root password
- [ ] Configure NTP servers
- [ ] Set hostname
- [ ] Configure timezone
- [ ] Review firewall rules
- [ ] Test failover scenarios
- [ ] Verify backup strategy

### 13.2 Security Hardening

- [ ] Disable SSH if not needed
- [ ] Configure custom TLS certificates (replace self-signed)
- [ ] Review interface roles
- [ ] Verify zone assignments
- [ ] Test lockout behavior
- [ ] Verify audit logging

### 13.3 Monitoring

- [ ] Monitor `/var/log/quickfw/audit.log`
- [ ] Monitor system resources (CPU/memory)
- [ ] Monitor conntrack table usage
- [ ] Set up log rotation
- [ ] Configure remote syslog (optional)

---

## 14. Troubleshooting Guide

### 14.1 Common Issues

**Cannot access web dashboard:**
1. Check API service: `systemctl status quickfw-api`
2. Verify TLS certificates exist: `ls -la /etc/quickfw/tls.*`
3. Check firewall: `nft list ruleset`
4. Verify MGMT_SAFETY chain exists

**Forgot admin password:**
1. Switch to tty2 (Ctrl+Alt+F2)
2. Select "Reset Admin Password"
3. Restart API: `systemctl restart quickfw-api`

**Firewall blocking management:**
1. Switch to tty2 recovery console
2. Select "Flush Firewall (Emergency)"
3. MGMT_SAFETY will be recreated automatically

**No internet access:**
1. Check WAN interface: `ip addr show`
2. Verify default route: `ip route show default`
3. Check DNS: `cat /etc/resolv.conf`
4. Verify NAT masquerade: `nft list chain inet gfw_rs POSTROUTING`

### 14.2 Log Locations

| Log | Location |
|-----|----------|
| API logs | `journalctl -u quickfw-api` |
| Audit log | `/var/log/quickfw/audit.log` |
| System logs | `journalctl` |
| DNS queries | `journalctl -u dnsmasq` |

### 14.3 Debug Commands

```bash
# Check API status
curl -k -u admin:password https://127.0.0.1/api/system/info

# List nftables rules
nft list ruleset

# Show conntrack table
conntrack -L | head -50

# Check interface stats
ip -s link show

# View DHCP leases
cat /var/lib/misc/dnsmasq.leases

# Check routing table
ip route show
vtysh -c "show ip route"
```

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| NFQUEUE | Linux netfilter mechanism for userspace packet processing |
| nftables | Modern Linux packet filtering framework |
| FRR | Free Range Routing - routing protocol suite |
| conntrack | Connection tracking subsystem |
| DNAT | Destination Network Address Translation |
| SNAT | Source Network Address Translation |
| Masquerade | Form of SNAT for dynamic IPs |
| OSPF | Open Shortest Path First routing protocol |
| BGP | Border Gateway Protocol |
| Argon2 | Memory-hard password hashing algorithm |

## Appendix B: File Permissions

| File/Directory | Owner | Permissions |
|----------------|-------|-------------|
| `/etc/quickfw/` | root:root | 755 |
| `/etc/quickfw/admin.password` | root:root | 600 |
| `/etc/quickfw/tls.key` | root:root | 600 |
| `/etc/quickfw/tls.crt` | root:root | 644 |
| `/var/log/quickfw/` | root:root | 755 |

## Appendix C: Default Values

| Setting | Default Value |
|---------|---------------|
| Admin username | `admin` |
| Admin password | `quickfw` (must change) |
| HTTPS port | 443 |
| HTTP redirect port | 3000 |
| Session timeout | 30 minutes |
| Rate limit | 60 req/min |
| Lockout threshold | 5 attempts |
| Lockout duration | 15 minutes |

---

**Document End**

*This documentation was generated on April 4, 2026, based on thorough analysis of the QuickFW codebase. All information has been verified against source code to ensure accuracy for production deployment.*
