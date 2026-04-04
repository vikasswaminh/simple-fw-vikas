# QuickFW — Agent Guide

This document provides everything an AI coding agent needs to know about the QuickFW project.

---

## 1. Project Overview

**QuickFW** is a lightweight, high-performance L3/L4 stateful firewall appliance written in Rust. It is designed to run as a Debian-based live ISO and provides:

- A **Cisco IOS-style CLI** on the console (tty1/serial).
- A **web dashboard** served over HTTPS on port 443.
- A **REST API** for automation and for the CLI to consume.
- **Default-deny firewall** semantics (INPUT DROP, FORWARD DROP).
- **NAT** (masquerade + port forwarding) via nftables.
- **Interface management** with WAN/LAN/DMZ role assignments.
- **DHCP/DNS** server for the LAN via dnsmasq.
- **OSPF / BGP / RIP** routing protocol support via FRR.

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
| Frontend | Vanilla JS SPA (no build step) |

---

## 3. Workspace Structure

This is a Cargo workspace. The root `Cargo.toml` lists the following members:

| Crate | Binary / Library | Purpose |
|-------|------------------|---------|
| `io` | `lib` (package `io`, imported as `gfw-io`) | Packet I/O abstraction, NFQUEUE integration, nftables script generation for firewall & NAT |
| `ifmgr` | `lib` (package `ifmgr`, imported as `gfw-ifmgr`) | Network interface discovery, WAN/LAN configuration, dnsmasq config generation |
| `config` | `lib` | YAML configuration parsing for generic CLI configs |
| `quickfw-api` | `quickfw-api` | Axum REST API server and static web UI host |
| `quickfw-cli` | `quickfw` | Cisco-style interactive CLI (talks to the API) |
| `quickfw-setup` | `quickfw-setup` | First-boot TUI wizard for appliance setup |
| `routing` | `lib` | OSPF, BGP, RIP config models and FRR config generation |

Additional directories:

- `front/` — Static web frontend (HTML, CSS, vanilla JS). Served by `quickfw-api`.
- `rootfs/` — Root filesystem overlay for the ISO. Contains systemd units, sysctl tuning, base nftables config, and issue/profile scripts.
- `scripts/` — Bash helper scripts (`quickfw-console` emergency recovery, `quickfw-irq-tune` NIC tuning).
- `tests/` — Node.js integration tests using Playwright.
- `Dockerfile` — Multi-stage build that compiles Rust binaries and then builds a Debian live ISO.
- `build.sh` — Host-facing ISO builder script that drives Docker.

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
- `/etc/quickfw/` — All appliance configuration (YAML files and `admin.password`).
- `/var/log/quickfw/` — Audit log directory.
- `/opt/quickfw/front/` — Static web assets (populated at ISO build time).

---

## 6. Code Style & Conventions

- **Rust Edition 2021** — use modern idioms.
- **Comments** — Top-of-file crate/module doc comments explain the purpose. Inline comments are used for security-critical or non-obvious logic.
- **Error handling** — Prefer `Result` and `?`. For API handlers, map errors to `(StatusCode, Json<...>)` tuples.
- **Security-first** — Every user-supplied field that reaches nftables or a system command **must** be validated. See `quickfw-api/src/validation.rs`.
- **Config safety** — Before overwriting any config file, the code calls `backup_config()` to create a timestamped `.bak` in `/etc/quickfw/backups/`. Atomic writes (write to `.tmp`, `fsync`, `rename`) are used for sensitive updates.
- **No panics on bad input** — API endpoints must return HTTP 400/500, never panic, on malformed client data.

---

## 7. Testing Strategy

### Unit tests
Each crate contains `#[cfg(test)]` modules. Run them with `cargo test`.

### Integration tests
`tests/real-test.js` is a Node.js script that uses Playwright to:
1. Exercise the REST API (system info, interfaces, firewall rules, NAT, routes, settings, config export, auth, audit).
2. Log in via the browser and take screenshots of each SPA page.

Prerequisites for integration tests:
- The `quickfw-api` binary must be running locally (usually on `https://127.0.0.1`).
- Node.js and `playwright` must be installed.

---

## 8. Security Considerations (Critical)

- **Input validation gatekeeper** — `quickfw-api/src/validation.rs` is the single source of truth for sanitizing interface names, IPs/CIDRs, ports, rule names, zones, and `forward_to` strings. Any new endpoint that accepts user data and feeds it to nftables or `Command` **must** use these validators.
- **nftables string sanitization** — `io/src/firewall.rs` has `sanitize_nft_string()` which strips quotes, newlines, control characters, and semicolons before interpolating into nft scripts.
- **Management safety chain** — The base ruleset and `io/src/nfqueue.rs` both define a high-priority `MGMT_SAFETY` chain that accepts SSH (22), HTTPS (443), HTTP (3000), and ICMP. This prevents accidental lockout.
- **Authentication** — Session-based auth with sliding 30-minute expiry, plus Basic auth fallback. Passwords are hashed with Argon2. Common passwords are banned.
- **Rate limiting & lockout** — Per-IP API rate limit (60 req/min). After 5 failed login attempts, the IP is locked out for 15 minutes.
- **TLS** — The API generates a self-signed ECDSA certificate on first start if `/etc/quickfw/tls.crt` and `tls.key` are missing.
- **Re-auth for destructive ops** — Endpoints like reboot, factory reset, and config restore require the current password to be re-supplied in the request body.

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
| Static web UI | `front/*.js`, `front/index.html`, `front/styles.css` |
| Systemd units | `rootfs/etc/systemd/system/*.service` |
| ISO package list / boot branding | `Dockerfile` |
| Base nftables config | `rootfs/etc/nftables.conf` |

---

## 10. Default Credentials

| Interface | Username | Password |
|-----------|----------|----------|
| Web UI / API | `admin` | `quickfw` (forced change on first login is implemented) |
| Linux root | `root` | Set during first-boot setup wizard |

---

## 11. Quick Reference

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
```
