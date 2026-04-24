# QuickFW — Upgrade Procedure

How the A/B upgrade flow works end-to-end, and how to drive it.

## Disk layout

A QuickFW appliance installed from the ISO (not live-booted) has three
labelled partitions:

| Label              | Purpose                                             |
|--------------------|-----------------------------------------------------|
| `QUICKFW_A`        | Root slot A                                         |
| `QUICKFW_B`        | Root slot B                                         |
| `QUICKFW_PERSIST`  | Config + logs (`/etc/quickfw`, `/var/log/quickfw`)  |

Exactly one of A/B is **active** (the one currently booted from); the
other is **standby** and is overwritten by the next upgrade. GRUB is
configured with both slots as entries; `grub-reboot` picks the one-time
default for the next boot.

## Signature model

Every released ISO ships with a detached signature file:

```
quickfw-2025.10.iso
quickfw-2025.10.iso.sig   # base64(ed25519(sha256(iso)))
```

The trusted ed25519 public key is baked into `quickfw-upgrade` at
compile time via the `QUICKFW_UPDATE_PUBKEY` build env var. Binaries
built without that env var fail every `verify` — the dev workflow
cannot accidentally ship an unsigned-ISO appliance to production.

Private key material **never** lives in this repo. It lives in release
infra only.

## Upgrade flow (web UI)

1. Download the new signed ISO.
2. Settings → Firmware → **Apply Upgrade**.
3. The browser streams the ISO body to
   `POST /api/system/firmware-upload` (1 GiB cap).
4. Backend saves it atomically to `/tmp/quickfw-upgrade.iso`, then runs
   `quickfw-upgrade apply --no-reboot`:
   - Verifies the signature. Abort if invalid.
   - Detects active + standby slots. Abort if not an A/B install.
   - `dd` the ISO bytes onto the standby block device.
   - `grub-reboot` to flip next-boot to the standby slot.
   - Writes `/persist/etc/quickfw/.upgrade-pending` with the target
     slot name.
5. The UI shows exit + stdout + stderr. Reboot from Settings → System
   when ready.
6. After reboot, the new slot runs for 5 minutes. At T+5:
   - `quickfw-upgrade-verify.service` fires `quickfw-upgrade mark-good`:
     - If `quickfw-api` is active, it clears the pending marker and
       the upgrade is sealed.
     - If `quickfw-api` is NOT active, it calls `rollback` (flip back
       + reboot). You end up back on the previous slot with a note in
       the journal.

## Upgrade flow (CLI)

```bash
# On the appliance
quickfw-upgrade status
# Active:  A (/dev/sda2)
# Standby: B (/dev/sda3)
# Pending: none

# Verify first — no disk changes
quickfw-upgrade verify /path/to/quickfw-new.iso

# Apply: verify + write + flip + pending marker + reboot
quickfw-upgrade apply /path/to/quickfw-new.iso
```

`apply` takes `--no-reboot` if you want to defer the reboot.

## Rollback

You have several options for rolling back a bad upgrade:

1. **Automatic (watchdog)** — if `quickfw-api` doesn't come up cleanly
   in the new slot, the watchdog flips back within 5 minutes.
2. **Before the watchdog fires** —
   `quickfw-upgrade rollback` from the console.
3. **On the next boot** — if you're in a situation where the new slot
   boots but is still broken, GRUB has both slots as menu entries; hold
   Shift during boot, select the other slot.

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `verify: signature does NOT verify` | Wrong key, tampered ISO | Redownload; confirm you have a production build of quickfw-upgrade |
| `verify: this binary was built without QUICKFW_UPDATE_PUBKEY` | Dev build | Rebuild or use the official appliance binary |
| `ERROR: /dev/disk/by-label/QUICKFW_A not found` | Live ISO, not installed | Install to disk first |
| `apply` succeeds, reboot fails | New slot's init / quickfw-api broken | Wait 5 min for watchdog, or boot the other slot via GRUB menu |
| `mark-good` reports unhealthy and rolls back | New binary crashes on boot | File a bug; rollback already ran |
