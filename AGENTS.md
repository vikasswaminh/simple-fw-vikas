# QuickFW — Agent Guide

This document provides everything an AI coding agent needs to know about the QuickFW project.

---

## 1. Project Overview

**QuickFW** is a lightweight, high-performance L3/L4 stateful firewall appliance written in Rust. It is designed to run as a Debian-based live ISO and provides:

- A **Cisco IOS-style CLI** on the console (tty1/serial)
- A **web dashboard** served over HTTPS on port 443 (with HTTP redirect on port 3000)
- A **REST API** for automation and for the CLI to consume
- **Default-deny firewall** semantics (INPUT DROP, FORWARD DROP)
- **NAT** (masquerade + port forwarding) via nftables
- **Interface management** with WAN/LAN role assignments
- **DHCP/DNS** server for the LAN via dnsmasq
- **OSPF / BGP / RIP** routing protocol support via FRR

### Architecture Diagram

```
Console CLI ──┐
              ├──→ quickfw-api (Axum REST) ──→ nftables (kernel)
Web Browser ──┘
```

---

## 2. Technology Stack

| Layer | Technology |
|-------|------------|
| Language | Rust (Edition 2021, stable toolchain) |
| Async runtime | Tokio |
| Web framework | Axum + axum-server (TLS via rustls) |
| Serialization | serde, serde_yaml, serde_json |
| Firewall engine | nftables + Linux NFQUEUE (via `nfq` crate) |
| Routing | FRR (Free Range Routing) — `zebra`, `ospfd`, `bgpd` |
| DHCP/DNS | dnsmasq |
| Process supervision | systemd |
| ISO build | Docker + Debian `live-build` |
| Frontend | Vanilla JS SPA (Vite + TypeScript + Tailwind CSS) |

---

## 3. Workspace Structure

This is a Cargo workspace. The root `Cargo.toml` lists the following members:

| Crate | Binary / Library | Purpose |
|-------|------------------|---------|
| `io` | `lib` (package `io`, imported as `gfw-io`) | Packet I/O abstraction, NFQUEUE integration, nftables script generation for firewall & NAT |
| `ifmgr` | `lib` (package `ifmgr`, imported as `gfw-ifmgr`) | Network interface discovery, WAN/LAN configuration, dnsmasq config generation |
| `config` | `lib` | YAML configuration parsing for generic CLI configs |
| `routing` | `lib` | OSPF, BGP, RIP config models and FRR config generation |
| `quickfw-api` | `quickfw-api` | Axum REST API server and static web UI host |
| `quickfw-cli` | `quickfw` | Cisco-style interactive CLI (talks to the API) |
| `quickfw-setup` | `quickfw-setup` | First-boot TUI wizard for appliance setup |

Additional directories:

- `front/` — Static web frontend (HTML, CSS, TypeScript). Served by `quickfw-api`.
- `rootfs/` — Root filesystem overlay for the ISO. Contains systemd units, sysctl tuning, base nftables config, and issue/profile scripts.
- `scripts/` — Bash helper scripts (`quickfw-console` emergency recovery, `quickfw-irq-tune` NIC tuning).
- `tests/` — Node.js integration tests using Playwright.
- `docs-site/` — Documentation website (VitePress).

---

## 4. Build Commands

### Build binaries locally

```bash
cargo build --release
```

Produced binaries:
- `target/release/quickfw-api`
- `target/release/quickfw`
- `target/release/quickfw-setup`

### Run unit tests

```bash
cargo test
```

### Build the bootable ISO

```bash
bash build.sh
```

This creates `output/quickfw.iso` using Docker and `live-build`. The ISO is a live Debian 12 (bookworm) image with QuickFW pre-installed. **This command requires Docker and can take 10–30 minutes.**

### Check formatting and linting

```bash
cargo fmt --check
cargo clippy
```

---

## 5. Runtime Architecture

When the appliance boots, the following systemd services are active:

| Service | Role |
|---------|------|
| `nftables.service` | Loads the base nftables ruleset (`/etc/nftables.conf`) |
| `quickfw-api.service` | Runs the HTTPS API + web UI on `0.0.0.0:443` and HTTP redirect on `0.0.0.0:3000` |
| `quickfw-cli.service` | Auto-login on tty1, running the Cisco-style `quickfw` CLI |
| `quickfw-console.service` | Emergency recovery console on tty2 (fallback bash script) |
| `quickfw-setup.service` | One-shot first-boot wizard (only if `/etc/quickfw/appliance.yaml` does not exist) |
| `dnsmasq.service` | DHCP/DNS for the LAN |

Key runtime paths:
- `/etc/quickfw/` — All appliance configuration (YAML files and `admin.password`)
- `/var/log/quickfw/` — Audit log directory
- `/opt/quickfw/front/` — Static web assets (populated at ISO build time)
- `/etc/frr/frr.conf` — FRR routing daemon configuration

---

## 6. Code Style & Conventions

- **Rust Edition 2021** — use modern idioms
- **Comments** — Top-of-file crate/module doc comments explain the purpose. Inline comments are used for security-critical or non-obvious logic
- **Error handling** — Prefer `Result` and `?`. For API handlers, map errors to `(StatusCode, Json<...>)` tuples
- **Security-first** — Every user-supplied field that reaches nftables or a system command **must** be validated. See `quickfw-api/src/validation.rs`
- **Config safety** — Before overwriting any config file, the code calls `backup_config()` to create a timestamped `.bak` in `/etc/quickfw/backups/`. Atomic writes (write to `.tmp`, `fsync`, `rename`) are used for sensitive updates
- **No panics on bad input** — API endpoints must return HTTP 400/500, never panic, on malformed client data

---

## 7. Testing Strategy

### Unit tests
Each crate contains `#[cfg(test)]` modules. Run them with `cargo test`.

### Integration tests
`tests/real-test.js` is a Node.js script that uses Playwright to:
1. Exercise the REST API (system info, interfaces, firewall rules, NAT, routes, settings, config export, auth, audit)
2. Log in via the browser and take screenshots of each SPA page

Prerequisites for integration tests:
- The `quickfw-api` binary must be running locally (usually on `https://127.0.0.1`)
- Node.js and `playwright` must be installed

### Frontend tests
The `front/` directory contains:
- Vitest for unit testing TypeScript code
- Playwright for E2E testing
- ESLint and Prettier for code quality

---

## 8. Security Considerations (Critical)

- **Input validation gatekeeper** — `quickfw-api/src/validation.rs` is the single source of truth for sanitizing interface names, IPs/CIDRs, ports, rule names, zones, and `forward_to` strings. Any new endpoint that accepts user data and feeds it to nftables or `Command` **must** use these validators.
- **nftables string sanitization** — `io/src/firewall.rs` has `sanitize_nft_string()` which strips quotes, newlines, control characters, and semicolons before interpolating into nft scripts.
- **Management safety chain** — The base ruleset and `io/src/nfqueue.rs` both define a high-priority `MGMT_SAFETY` chain that accepts SSH (22), HTTPS (443), HTTP (3000), and ICMP. This prevents accidental lockout.
- **Authentication** — Session-based auth with sliding 30-minute expiry, plus Basic auth fallback. Passwords are hashed with Argon2. Common passwords are banned.
- **Rate limiting & lockout** — Per-IP API rate limit (60 req/min). After 5 failed login attempts, the IP is locked out for 15 minutes.
- **TLS** — The API generates a self-signed ECDSA certificate on first start if `/etc/quickfw/tls.crt` and `tls.key` are missing.
- **Re-auth for destructive ops** — Endpoints like reboot, factory reset, and config restore require the current password to be re-supplied in the request body.
- **Security headers** — All API responses include CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and HSTS headers.

---

## 9. Key Files for Common Changes

| Task | File(s) |
|------|---------|
| Add/modify API endpoint | `quickfw-api/src/<module>.rs` and `quickfw-api/src/lib.rs` |
| Firewall rule engine | `io/src/firewall.rs` |
| NAT rule engine | `io/src/nat.rs` |
| NFQUEUE / packet I/O | `io/src/nfqueue.rs`, `io/src/lib.rs` |
| Interface logic | `ifmgr/src/lib.rs` |
| Routing protocols | `routing/src/ospf.rs`, `routing/src/bgp.rs`, `routing/src/rip.rs`, `routing/src/lib.rs` |
| Input validation | `quickfw-api/src/validation.rs` |
| Auth / sessions | `quickfw-api/src/auth.rs` |
| Audit logging | `quickfw-api/src/audit.rs` |
| Static web UI | `front/src/**/*.ts`, `front/index.html`, `front/styles.css` |
| Systemd units | `rootfs/etc/systemd/system/*.service` |
| ISO package list / boot branding | `Dockerfile` |
| Base nftables config | `rootfs/etc/nftables.conf` |
| Emergency recovery console | `scripts/quickfw-console` |

---

## 10. Default Credentials

| Interface | Username | Password |
|-----------|----------|----------|
| Web UI / API | `admin` | `quickfw` (forced change on first login is recommended) |
| Linux root | `root` | Set during first-boot setup wizard |

---

## 11. API Endpoints Overview

The REST API is organized into these categories:

### System & Interfaces
- `GET /api/system/info` — Hostname, version, uptime, CPU, memory, load
- `GET /api/system/traffic` — Connection counts, RX/TX stats
- `POST /api/system/reboot` — Reboot (requires password confirmation)
- `GET /api/interfaces` — List all interfaces with stats
- `PUT /api/interfaces/{name}` — Configure interface
- `GET /api/settings` — Get appliance settings
- `POST /api/settings` — Update appliance settings

### Firewall
- `GET /api/firewall` — Get firewall config (rules, policies, zones)
- `POST /api/firewall` — Apply firewall config (supports `?dry_run=true`)
- `GET /api/firewall/counters` — Rule hit counters
- `GET /api/firewall/groups` — Address/port groups
- `POST /api/firewall/groups` — Save groups

### NAT
- `GET /api/nat` — Get NAT config (masquerade, port-forward)
- `POST /api/nat` — Apply NAT config
- `DELETE /api/nat/masquerade/{index}` — Remove masquerade rule
- `DELETE /api/nat/port_forward/{index}` — Remove port-forward rule

### Routing
- `GET /api/routes` — Static routes
- `POST /api/routes` — Add route
- `DELETE /api/routes/{cidr}` — Remove route
- `GET /api/routing/ospf` — OSPF config/status
- `POST /api/routing/ospf` — Configure OSPF
- `GET /api/routing/bgp` — BGP config/status
- `POST /api/routing/bgp` — Configure BGP
- `GET /api/routing/rip` — RIP config/status
- `POST /api/routing/rip` — Configure RIP

### Tools & Monitoring
- `GET /api/conntrack` — Active connections
- `GET /api/tools/arp` — ARP table
- `GET /api/tools/dhcp-leases` — DHCP leases
- `GET /api/tools/dns-local` — Local DNS entries
- `POST /api/tools/ping` — Ping host
- `POST /api/tools/traceroute` — Traceroute

### Auth & Admin
- `POST /api/auth/login` — Session login
- `POST /api/auth/logout` — Session logout
- `POST /api/auth/password` — Change password
- `POST /api/auth/ws-token` — Get WebSocket auth token
- `GET /api/audit` — Audit log entries
- `GET /api/config/export` — Export full config
- `POST /api/config/import` — Import config (destructive)
- `POST /api/config/backup` — Create backup
- `POST /api/config/restore` — Restore from backup
- `POST /api/factory-reset` — Factory reset (requires password)

---

## 12. Configuration Files

All configuration is stored in YAML format under `/etc/quickfw/`:

| File | Purpose |
|------|---------|
| `appliance.yaml` | Network appliance configuration (WAN/LAN settings) |
| `firewall.yaml` | Firewall rules and policies |
| `firewall-groups.yaml` | Address and port groups |
| `nat.yaml` | NAT masquerade and port-forward rules |
| `routes.yaml` | Static routes |
| `ospf.yaml` | OSPF routing configuration |
| `bgp.yaml` | BGP routing configuration |
| `rip.yaml` | RIP routing configuration |
| `interfaces.yaml` | Interface role assignments |
| `settings.yaml` | Appliance settings (hostname, etc.) |
| `admin.password` | Admin password (Argon2 hash or plaintext for migration) |
| `tls.crt`, `tls.key` | Self-signed TLS certificate |

---

## 13. Quick Reference

```bash
# Build all binaries
cargo build --release

# Run all Rust unit tests
cargo test

# Build ISO (requires Docker)
bash build.sh

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy

# Run frontend dev server (in front/ directory)
cd front && npm run dev

# Build frontend for production
cd front && npm run build

# Run frontend tests
cd front && npm test

# Run E2E tests
cd front && npm run test:e2e
```

---

## 14. Important Notes for Developers

1. **Never** interpolate user input directly into nftables commands. Always use `sanitize_nft_string()` or the validation functions.

2. **Always** validate input before applying firewall/NAT changes. The validation layer in `quickfw-api/src/validation.rs` must reject any malicious input.

3. **Backup before change** — Use `crate::config_utils::backup_config()` before overwriting config files.

4. **Atomic writes** — For sensitive files, write to `.tmp`, fsync, then rename to avoid partial writes.

5. **Management safety** — The `MGMT_SAFETY` chain in nftables must always allow SSH (22), HTTPS (443), and HTTP (3000) to prevent lockout.

6. **First boot** — The setup wizard only runs if `/etc/quickfw/appliance.yaml` doesn't exist. To re-run, delete this file and restart.

7. **Emergency access** — If the CLI fails, tty2 provides the `quickfw-console` emergency recovery script.
