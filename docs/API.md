# QuickFW REST API Reference

All endpoints are served by the `quickfw-api` binary on `https://<host>`
(port 443 by default). HTTP on port 3000 redirects to HTTPS.

## Authentication

### Session cookie (preferred)

Log in once, then ride the session cookie.

```
POST /api/auth/login          { "username": "admin", "password": "..." }
  -> 200 { "token": "...", "expires_in_seconds": 1800,
           "username": "admin", "role": "admin" }
  -> sets quickfw_session cookie (HttpOnly, Secure, SameSite=Strict)
  -> sets quickfw_csrf cookie    (Secure, SameSite=None, readable by JS)

POST /api/auth/logout
  -> 200; clears both cookies
```

### CSRF double-submit

Every mutating request (POST / PUT / DELETE) except the bootstrap
`/api/auth/*` must include the `quickfw_csrf` cookie value as the
`X-CSRF-Token` header. The web UI does this automatically; external
callers must read the cookie from the login response's `Set-Cookie`
and echo it back.

### Basic auth (for scripts)

Alternatively, send `Authorization: Basic base64(user:pass)` on every
request. CSRF is bypassed for the Basic auth code path since there's
no cookie to attack. Still rate-limited (60 req/min/IP).

## Roles

Endpoints are gated by role. `Admin > Operator > Readonly`.

- **Any authenticated user**: `GET /api/*`, `POST /api/auth/*`.
- **Operator+** (operator or admin): `POST/PUT/DELETE` on
  `/api/firewall`, `/api/nat`, `/api/routing/*`, `/api/interfaces*`,
  `/api/routes`, `/api/settings`, `/api/tools/dns-local`, `/api/syslog`,
  `/api/tools/arp/flush`.
- **Admin only**: `/api/system/reboot`, `/api/system/factory-reset`,
  `/api/config/restore`, `/api/config/import`, `/api/users/*`,
  `/api/logs`, `/api/system/firmware-upload`,
  `/api/system/upgrade-status`.

Insufficient role responses: `403 { "error": "forbidden", "message":
"Insufficient role" }`.

## Health

```
GET /api/health
  -> 200 {
    "api": true,
    "nftables": bool,
    "dnsmasq": bool,
    "frr": bool,
    "config": { "firewall": bool, "nat": bool, "settings": bool,
                "routes": bool, "roles": bool }
  }
```

No auth required. Good for load-balancer health checks.

## Firewall

```
GET  /api/firewall              -> FirewallConfig
POST /api/firewall              body: FirewallConfig
POST /api/firewall?dry_run=true body: FirewallConfig
  -> NftPreview { dry_run, nft_script, rule_count }
GET  /api/firewall/counters     -> { counters: [{ chain, comment, packets, bytes }] }
GET  /api/firewall/groups       -> FirewallGroups
POST /api/firewall/groups       body: FirewallGroups
```

`FirewallConfig`:

```jsonc
{
  "schema_version": "1.0",
  "rules": [ FirewallRule, ... ],
  "forward_policy": "drop" | "accept" | "reject",
  "input_policy":   "drop" | "accept" | "reject",
  "output_policy":  "drop" | "accept" | "reject",
  "zones": [ { "interface": "eth0", "zone": "wan", "role": "wan" }, ... ]
}
```

`FirewallRule`:

```jsonc
{
  "name": "allow-ssh",
  "enabled": true,
  "direction": "forward" | "input" | "output",
  "protocol": "tcp" | "udp" | "icmp" | "tcp+udp" | "any",
  "src_ip": "192.168.1.0/24" | "" | "any" | null,
  "dst_ip":  ...,
  "src_port": "22" | "80,443" | "1024-65535" | "" | "any" | null,
  "dst_port": ...,
  "action": "accept" | "drop" | "reject" | "log",
  "log": false,
  "comment": "optional string or null",
  "ipv6": false
}
```

## NAT

```
GET    /api/nat                       -> NatConfig
POST   /api/nat                       body: NatConfig
DELETE /api/nat/masquerade/:idx       1-based index
DELETE /api/nat/port_forward/:idx
DELETE /api/nat/snat/:idx
```

`NatConfig`:

```jsonc
{
  "schema_version": "1.0",
  "masquerade": [ { "out_interface": "eth0", "source_cidr": "192.168.1.0/24" } ],
  "port_forward": [ { "protocol": "tcp", "dest_port": 8080,
                      "forward_to": "192.168.1.100:80", "in_interface": "eth0" } ],
  "snat": [ { "source_cidr": "10.10.0.0/24", "to_address": "203.0.113.5",
              "out_interface": "eth0" } ]
}
```

## Routing

```
GET  /api/routing/ospf              -> OspfConfig
POST /api/routing/ospf              body: OspfConfig
GET  /api/routing/ospf/neighbors    -> { neighbors: [OspfNeighborStatus, ...] }
GET  /api/routing/bgp               -> BgpConfig
POST /api/routing/bgp               body: BgpConfig
GET  /api/routing/bgp/summary       -> { summary: "..." }
GET  /api/routing/table?protocol=X  -> { table: "..." }
GET  /api/routing/protocols         -> { protocols: ["ospf", "bgp", ...] }

GET  /api/routes                    -> StaticRoutesConfig
POST /api/routes                    body: StaticRoutesConfig
```

## Network / Interfaces

```
GET  /api/interfaces                -> { interfaces: [Interface, ...] }
GET  /api/interfaces/:name          -> Interface
POST /api/interfaces/config         body: InterfaceConfig
GET  /api/interfaces/roles          -> InterfaceRolesConfig
POST /api/interfaces/roles          body: InterfaceRolesConfig
```

`InterfaceConfig`:

```jsonc
{
  "name": "eth0",
  "mode": "dhcp" | "static" | "" ,    // empty = don't touch addressing
  "address": "192.168.1.1/24",
  "gateway": "192.168.1.254",
  "dns": ["1.1.1.1", "8.8.8.8"],
  "mtu": 1500,
  "enabled": true,                     // link up/down
  "description": "LAN trunk"
}
```

## Users (admin-only)

```
GET    /api/users                       -> [ { username, role } ]
POST   /api/users                       body: { username, password, role }
DELETE /api/users/:username
POST   /api/users/:username/role        body: { role: "admin"|"operator"|"readonly" }
POST   /api/users/:username/password    body: { password }
```

## Settings / System

```
GET  /api/system/info               -> SystemInfo
GET  /api/system/traffic            -> TrafficSnapshot
GET  /api/services                  -> { dns, dhcp, ntp, ssh, syslog: {unit,active} }
GET  /api/settings                  -> SystemSettings
POST /api/settings                  body: SystemSettings
POST /api/system/reboot             body: { confirm_password } ; admin-only
POST /api/system/factory-reset      body: { confirm_password } ; admin-only

GET  /api/conntrack                 -> [ ConntrackEntry, ... ]
GET  /api/syslog                    -> SyslogConfig
POST /api/syslog                    body: SyslogConfig
```

## Config backup / restore

```
GET  /api/config/export             -> full backup JSON (admin-only download)
GET  /api/config/backups            -> [{ name, size }]
POST /api/config/restore            body: { name, confirm_password } ; admin-only
POST /api/config/import             body: <backup JSON> ; admin-only
```

## Tools

```
GET  /api/tools/arp                 -> [ArpEntry]
POST /api/tools/arp/flush           clears the kernel ARP table
GET  /api/tools/dhcp-leases         -> [DhcpLease]
GET  /api/tools/dns-local           -> [{ hostname, ip }]
POST /api/tools/dns-local           body: [{ hostname, ip }]
POST /api/tools/ping                body: { host, count }
POST /api/tools/traceroute          body: { host, max_hops }
POST /api/tools/wol                 body: { mac, iface }
GET  /api/tools/ntp-status          -> { key: val, ... }
```

## Audit / Logs (admin-only)

```
GET /api/audit                      -> [ AuditEntry, ... ]
GET /api/logs?source=X&tail=N
    X: audit | system | firewall
    N: 1 <= N <= 2000, default 200
  -> { source, lines: [...], truncated: bool }
```

## Firmware upgrade (admin-only)

```
POST /api/system/firmware-upload
     Content-Type: application/octet-stream
     body: ISO bytes (max 1 GiB)
  -> 200 { accepted_bytes, iso_path, apply_exit, apply_stdout, apply_stderr }
  -> 400 on too-small body, bad signature, or no A/B layout
GET  /api/system/upgrade-status
  -> { available, exit, stdout, stderr }
```

## Rate limits

- 60 requests / minute / IP on any `/api/*` endpoint.
- 5 failed logins within a rolling window locks the IP out for 15 minutes.

## Error shape

All error responses are JSON:

```
{ "error": "short code", "message": "human-readable reason" }
```

Common codes: `unauthorized`, `forbidden`, `password_change_required`,
`validation_failed`.
