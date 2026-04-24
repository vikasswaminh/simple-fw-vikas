# QuickFW — Install Guide

## 1. Get the ISO

Download `quickfw.iso` + its signature `quickfw.iso.sig` from the releases
page. You can verify the signature with the bundled `quickfw-upgrade` binary
or the release's published ed25519 public key:

```bash
# Quick check: size + SHA-256
sha256sum -c quickfw.iso.sha256
# Full signature verification (requires the binary from inside an installed
# appliance, or a separately-shipped offline verifier)
quickfw-upgrade verify quickfw.iso
```

## 2. Write the ISO to a USB stick

Linux / macOS (replace `/dev/sdX` with the actual device — check with
`lsblk` first, and **be sure** you're picking the USB stick, not your
laptop's root disk):

```bash
sudo dd if=quickfw.iso of=/dev/sdX bs=4M status=progress conv=fsync
sudo sync
```

Windows: use [Rufus](https://rufus.ie/) in DD mode, not ISO mode.

## 3. Boot the appliance from USB

Plug the USB stick into the target hardware, power on, and enter the BIOS
/ UEFI boot menu (usually F2 / F10 / F12 / Del). Select the USB device.

The ISO supports two paths:

- **Live boot** — boots into RAM (`toram`) for a test drive. Config does
  not survive reboot in this mode. Good for a try-before-you-install.
- **Install to disk** — creates the A/B slot layout and a persistent
  config partition. This is the production path.

## 4. First-boot setup wizard

On first boot the appliance drops into `quickfw-setup` on the console:

1. **Detects network interfaces** and asks you to pick WAN and LAN.
2. **WAN addressing** — DHCP (easy) or Static (IP/CIDR + gateway + DNS).
3. **LAN addressing** — static CIDR. If you want the appliance to serve
   DHCP on the LAN side, supply a range here.
4. **Root password** — this is the Linux root password for console /
   SSH access.
5. **Admin password for the web UI** — must be ≥ 12 characters with
   upper + lowercase + a digit, and not contain a weak phrase like
   `admin`, `password`, `quickfw`. Prompted twice for confirmation.
6. **Enable SSH?** — default no. Turn on only if you need remote
   console access; otherwise manage via the web UI + `quickfw-cli`.

After the summary screen, confirm with `yes` and the appliance applies
the config, starts services, and prints the web UI URL.

## 5. Log in to the web UI

Open `https://<WAN-IP>` (or `<LAN-IP>` if you're on the LAN side) in a
browser. Accept the self-signed cert warning — the appliance generates a
cert at first boot.

Default credentials if you kept them:

- Username: `admin`
- Password: whatever you set in step 5 of the wizard

If you kept the default `quickfw` password, the dashboard forces you to
change it before you can access anything — a first-boot lockdown.

## 6. Next steps

- Set up firewall rules: **Firewall** tab → Add Rule
- Create additional users (operator, readonly): **Settings → Admin & Users**
- Back up your config: **Settings → Backup → Download Backup**
- Read the [Operator Runbook](OPERATOR_RUNBOOK.md) for day-2 operations.
