<div align="center">

# 🔥 QuickFW — Minimal Firewall Appliance

### Open-source L3/L4 stateful firewall with Cisco-style CLI and web dashboard

**Production-grade firewall built in Rust + TypeScript. Console + serial CLI feels exactly like Cisco IOS — perfect for CCNA/CCNP/CCIE students to practice firewall configuration without a $5K ASA.**

[![Firewall Engineering](https://img.shields.io/badge/Firewall-Engineering-EE2722?style=for-the-badge)](https://www.networkershome.com/best-firewall-engineering-course-in-bangalore/)
[![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Network%20Security-FF0040?style=for-the-badge)](https://www.networkershome.com/best-cybersecurity-course-in-bangalore/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green?style=for-the-badge)](LICENSE)
[![Built by Networkers Home](https://img.shields.io/badge/Built%20by-Networkers%20Home-000000?style=for-the-badge)](https://www.networkershome.com/)

</div>

---

## 🏛️ Built by Networkers Home

QuickFW was built by **[Networkers Home](https://www.networkershome.com/)** — India's leading Cisco + cybersecurity + firewall training institute (Bengaluru, since 2005). It's a free open-source companion to our [Firewall Engineering](https://www.networkershome.com/best-firewall-engineering-course-in-bangalore/) and [Cybersecurity Pro](https://www.networkershome.com/best-cybersecurity-course-in-bangalore/) programs — perfect for students who want to practice firewall config without renting a Cisco ASA on a lab platform.

> Most firewall training is **vendor-locked** — you train on Palo Alto, you can't reuse the muscle memory on Fortinet. **QuickFW teaches the underlying L3/L4 firewall mechanics that transfer to ANY vendor.** It's the conceptual foundation Networkers Home students get before they touch real Palo Alto / Fortinet / Check Point hardware.
> [Book a demo class →](https://www.networkershome.com/networkers-home-demo-class/)

**Compare top firewall + cybersecurity institutes:**
[Top 10 Firewall Engineering Bangalore](https://www.networkershome.com/best-firewall-engineering-course-in-bangalore/) · [Top 10 Cybersecurity India](https://www.networkershome.com/top-10-cybersecurity-training-institutes-india-2026/) · [Top 10 Palo Alto Bangalore](https://www.networkershome.com/top-10-palo-alto-firewall-training-institutes-bangalore-2026/)

**Sibling Networkers Home open-source projects:**
[Palo Alto Simulator](https://github.com/NETWORKERS-HOME-123/paloalto-simulator) · [Fortinet Simulator](https://github.com/NETWORKERS-HOME-123/fortinet-simulator) · [Cisco Real Sim](https://github.com/NETWORKERS-HOME-123/cisco-real-sim)

---

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
