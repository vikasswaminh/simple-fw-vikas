# QuickFW — Minimal Firewall Appliance

A lightweight, high-performance L3/L4 stateful firewall appliance with:

- **Cisco IOS-style CLI** on console (tty1/serial)
- **Web Dashboard** on HTTPS :443
- **REST API** for automation
- **Default-deny** firewall (INPUT DROP, FORWARD DROP)
- **NAT** (masquerade + port forwarding)
- **Interface management** (WAN/LAN/DMZ roles)
- **DHCP/DNS** server for LAN via dnsmasq

## Quick Start

```bash
# Build binaries
cargo build --release

# Binaries at:
#   target/release/quickfw-api   (API server + web UI)
#   target/release/quickfw       (Cisco-style CLI)
#   target/release/quickfw-setup (First-boot wizard)
```

## Build ISO

```bash
bash build.sh
# Output: output/quickfw.iso (~318MB)
```

## Default Credentials

| Account | Username | Password |
|---------|----------|----------|
| Web UI  | admin    | quickfw  |
| Root    | root     | Set during setup |

## Architecture

```
Console CLI ──┐
              ├──→ quickfw-api (Axum REST) ──→ nftables (kernel)
Web Browser ──┘
```

## License

MIT
