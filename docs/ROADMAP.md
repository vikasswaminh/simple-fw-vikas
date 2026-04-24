# QuickFW — Future Roadmap

What's landed (Phases A–M) is production-grade *code*. A few pieces of
**infrastructure and release-engineering** work sit outside the code
and are needed before an appliance can actually ship with Phase F/H/I
fully active. This document captures all known follow-ups so nothing
gets lost.

---

## 1. Required to productionize Phase F / H / I

These three phases depend on disk layout and release infrastructure
that can't be validated on a bare-metal test VM.

### 1.1 `build.sh` install-time partition layout

**Status:** not started.

The guest-side code (first-boot mount hook, A/B detection, upgrade CLI)
is complete and tested. The ISO's *install* path still needs to create
the labelled partition layout when the appliance is installed to disk:

```
GPT / MBR
├── ESP              (GRUB)
├── QUICKFW_A        (root slot A, ext4, ~2 GiB)
├── QUICKFW_B        (root slot B, ext4, ~2 GiB)
└── QUICKFW_PERSIST  (config + logs, ext4, ~1 GiB)
```

Work items:
- Extend `build.sh` / live-build to support an install mode (not just
  live). Default to live (toram) for the ISO download; install is
  triggered from the live environment by a user-run `quickfw-install`
  script.
- Write `quickfw-install`: `sgdisk` the target disk, `mkfs.ext4 -L
  QUICKFW_A/B/PERSIST`, dd the live rootfs onto A, seed PERSIST with
  `/etc/quickfw` defaults, install GRUB with two menu entries, mark A
  as the default.
- After install + first reboot, the Phase F mount hook and Phase H
  upgrade CLI are fully functional.

**Test plan:** PXE or QEMU-install a built ISO, verify `lsblk -f`
shows the three labels, verify `/etc/quickfw` survives a reboot,
verify `quickfw-upgrade status` reports "Active: A".

### 1.2 Production release signing key

**Status:** dev binaries only — every `verify` fails.

`quickfw-upgrade` bakes its trusted ed25519 public key from the
`QUICKFW_UPDATE_PUBKEY` env var at compile time. Shipping this unset
makes every `verify` fail by design, so no dev binary ever accepts an
unsigned ISO.

Work items for release infra:
- Generate an ed25519 keypair offline in a hardware token / HSM.
- Publish the public half in the repo's release notes + as a
  detached file on the releases page.
- CI pipeline: build release ISOs with `QUICKFW_UPDATE_PUBKEY=<b64>`
  baked into quickfw-upgrade. Sign each ISO with the private half,
  publish `<iso>.sig` alongside the ISO.
- Document the signing pipeline in a `RELEASING.md` once we have one.

### 1.3 End-to-end A/B upgrade test

**Status:** all unit tests green, end-to-end flow never exercised on
real hardware.

Requires 1.1 (partitions) + 1.2 (signed ISO). Then:

- Install ISO v1 to disk.
- Apply a v2 ISO via the web UI (or `quickfw-upgrade apply`).
- Reboot, confirm dashboard shows the new version.
- Intentionally break v2 (e.g., make `quickfw-api.service` fail on
  boot). Apply, reboot. Watchdog should roll back within 5 min.
- Try `quickfw-upgrade apply <unsigned.iso>` — must refuse.
- Try `quickfw-upgrade rollback` manually, confirm GRUB flip + reboot.

---

## 2. Nice-to-have improvements to what we shipped

### 2.1 Schema migrations

**Status:** framework complete, all chains empty (everything is at
`schema_version: "1.0"`).

When a future schema change is introduced — say, `FirewallRule` gains a
required `hit_count_start: u64` field — add an entry to the relevant
chain in [quickfw-api/src/migrations.rs](../quickfw-api/src/migrations.rs):

```rust
pub fn firewall_migrations() -> Vec<MigrationStep> {
    vec![MigrationStep {
        from: "1.0",
        to: "1.1",
        apply: |v| {
            // mutate v: &mut serde_yaml::Value in place
            Ok(())
        },
    }]
}
```

Bump `CURRENT_SCHEMA_VERSION` and the typed struct's `default_schema_version()`
in the same commit. Every appliance that loads a `"1.0"` file will
transparently migrate and rewrite it.

### 2.2 Pre-existing test fixtures

- `io::pcap::tests::test_register` needs `../assets/pcaps/ipv4frags.pcap`.
  That asset isn't in the repo; the test has been failing since long
  before Phase L. Fix: either commit a tiny hand-rolled fragments pcap
  or mark the test `#[ignore]` with a note.
- `tsc --noEmit` reports module-resolution errors on bare `@schemas`
  aliases (documented in CLAUDE.md). Vite resolves them fine, so the
  build works, but CI can't run typecheck cleanly. Fix: tell tsc
  about the paths via `tsconfig.json` `paths` (already configured but
  not picked up correctly under `moduleResolution: node`).

### 2.3 Operator-vs-admin gating on config writes

**Status:** currently only admin-only endpoints are gated. Config
writes on `/api/firewall`, `/api/nat`, `/api/routing/*`, `/api/interfaces`,
etc. accept any authenticated user.

Per the original plan, those should require Operator+. Tightening is a
one-line change per router (add `.layer(require_role(Operator))` to a
sub-router bundling the POST/PUT/DELETE routes). It was deferred in the
G-phase sprint because the readonly role doesn't yet have a well-defined
UX — a readonly user is currently just a logged-in user who can see the
same buttons as an admin, and the backend 403 is the only feedback. The
frontend should also hide mutating buttons for readonly users. Two
commits:

- Backend: add `require_role(Operator)` to mutating sub-routers in
  firewall_api, nat_api, routing_api, system.rs (settings + interfaces).
- Frontend: `store.state.currentRole` — populated from the login
  response — used to conditionally render action buttons.

### 2.4 Drag-and-drop rule reorder (Phase D2 polish)

The up/down arrow version shipped in Phase D. A drag-and-drop grip
handle is a UX upgrade, not a correctness one. HTML5 drag-and-drop,
no external library. ~1–2 hours.

### 2.5 Dashboard "ephemeral mode" warning

The Phase F mount hook writes `/run/quickfw/persist-state` containing
`persistent` or `ephemeral`. The dashboard should read it (via a new
GET `/api/system/info` field) and show a banner when the appliance is
running ephemerally — so the operator knows config will be lost on
reboot.

### 2.6 Migration refuse-to-load hook

The migration framework supports it, but the quickfw-api service
doesn't yet call it at startup. As currently written, an
incompatibly-new config file silently falls through to the per-loader
path, which may or may not reject it. Add a boot-time check that runs
`load_migrated::<T>()` for each domain file and fails loudly on
`MigrationError::Unsupported`.

---

## 3. Explicit non-goals (by design)

These were deliberately excluded from the production-ready plan and
should stay out of scope for this appliance model. Listed so future
contributors don't re-litigate the decision.

- Prometheus / Grafana / SNMP / remote SIEM push
- Email / Slack / webhook alerting
- Let's Encrypt / ACME / external CA integration
- Geo-IP feeds, threat intel feeds, IDS/IPS signatures, L7 / DPI
  application controls
- Any VPN (WireGuard, IPsec, OpenVPN), ZTNA / zero-trust
- Cloud-managed upgrade service / central fleet management
- Billing, multi-tenancy, SaaS control plane

All appliance state is local; all management is via the web UI / CLI
on the appliance itself. That boundary is what keeps the product
simple enough to reason about.
