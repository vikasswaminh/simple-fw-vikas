# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

QuickFW is a Linux firewall appliance built in Rust. It produces a bootable Debian 12 ISO with a web dashboard, REST API, and Cisco-style CLI. The firewall uses nftables for packet filtering and NFQUEUE for userspace inspection.

## Build Commands

```bash
# Rust binaries (outputs to target/release/)
cargo build --release

# Run tests
cargo test

# Frontend (from front/ directory)
cd front
npm run build          # tsc && vite build
npm run dev            # dev server with API proxy to localhost
npm run typecheck      # tsc --noEmit
npm run lint           # eslint
npm run test           # vitest

# Bootable ISO (requires Docker, takes 10-30 min)
bash build.sh          # outputs output/quickfw.iso
```

## Workspace Architecture

Seven crates in a Cargo workspace:

```
quickfw-api  (binary)  ─── Axum REST API server, serves web UI over HTTPS :443
  ├── io               ─── nftables script generation, NFQUEUE packet I/O, NAT
  └── routing          ─── OSPF/BGP/RIP config models, FRR config generation

quickfw-cli  (binary)  ─── Interactive CLI, talks to API via reqwest HTTP client
quickfw-setup (binary) ─── First-boot TUI wizard
  └── ifmgr            ─── Interface discovery, WAN/LAN config, dnsmasq generation

config                 ─── YAML config parsing (CliConfig struct)
```

**quickfw-api** is the main runtime binary. Its modules map directly to API domains:
- `auth.rs` — Argon2 password hashing, session auth, rate limiting, lockout
- `firewall_api.rs` — Rule CRUD, nftables script generation and apply
- `nat_api.rs` — Masquerade/DNAT/static SNAT management
- `routing_api.rs` — OSPF/BGP config, FRR integration via vtysh
- `system.rs` — System info, interfaces, settings, config backup/restore
- `tools.rs` — Ping, traceroute, ARP, DHCP leases, WoL, NTP status
- `validation.rs` — **All input validation lives here** — interface names, IPs, CIDRs, ports, injection prevention

**io crate** (`io/src/`):
- `firewall.rs` — `FirewallConfig`/`FirewallRule` structs, `generate_firewall_nft_script()`, `apply_firewall()`
- `nat.rs` — `NatConfig` structs, `generate_nat_nft_script()`
- `nfqueue.rs` — NFQUEUE packet processing, MGMT_SAFETY chain (always allows SSH/443/3000/ICMP)

## Frontend

TypeScript SPA in `front/src/` using vanilla components (no React/Vue). Vite bundler.

- `pages/` — One file per page (dashboard.ts, firewall.ts, network.ts, etc.)
- `api/endpoints.ts` — All API client functions grouped by domain
- `schemas/` — Zod schemas for API response validation
- `components/modal.ts` — Reusable modal dialog (openModal/closeModal)
- `components/toast.ts` — Toast notifications (showToast)
- `components/component.ts` — Base Component class with setState/render lifecycle

Pages extend `Component<TState>` and use `setState()` to trigger re-renders. Navigation uses a custom router in `router/index.ts` with `data-navigate` attribute on links.

Path aliases: `@pages`, `@api`, `@schemas`, `@utils`, `@components`, `@router`, `@state` (configured in vite.config.ts and tsconfig.json). Note: `tsc --noEmit` reports module resolution errors for bare aliases like `@schemas` — these work through Vite but not bare tsc. This is a known pre-existing issue.

## Key Patterns

**Config persistence:** All configs are YAML files under `/etc/quickfw/`. The pattern is `load_*_config()` → modify → `save_*_config()` → `apply_*()` (which generates nftables/FRR scripts and applies them). Backups are timestamped copies made before writes.

**API auth:** Session cookie + Basic HTTP auth fallback. Rate limiting at 60 req/min per IP. Auth lockout after 5 failures (15 min). WebSocket tokens for real-time features (5 min expiry).

**Firewall safety:** The MGMT_SAFETY chain in nfqueue.rs ensures SSH, HTTPS, and API access survive any rule changes. Config apply uses atomic write (tmp → fsync → rename) with rollback on failure.

**CLI ↔ API:** quickfw-cli is a thin client — every command maps to an API call via reqwest. The CLI provides tab completion and colored output but has no local state.

## Runtime Paths (on the appliance)

- `/etc/quickfw/*.yaml` — Firewall, NAT, OSPF, BGP, routes, interfaces, appliance config
- `/etc/quickfw/admin.password` — Argon2 password hash
- `/etc/frr/frr.conf` — Generated FRR config (OSPF/BGP/static routes)
- `/etc/dnsmasq.d/quickfw.conf` — Generated DHCP/DNS config
- `/var/log/quickfw/audit.log` — Audit log (rotated at 10MB)
- `/opt/quickfw/front/` — Built web assets served by quickfw-api

## Default Credentials

| Interface | Username | Password |
|-----------|----------|----------|
| Web UI / API | `admin` | `quickfw` |
| Linux root | `root` | Set during setup wizard |
