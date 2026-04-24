# QuickFW — Operator Runbook

Day-2 operations for a deployed QuickFW appliance. All tasks here
assume you can reach the web UI at `https://<appliance-ip>` and have
admin credentials.

---

## User management

QuickFW has three roles, ordered by privilege:

| Role | Can do |
|---|---|
| **Readonly** | View everything. Cannot change any config. |
| **Operator** | Edit firewall, NAT, routing, interfaces, settings. Cannot reboot, factory-reset, manage users, import/restore backups, or view system/firewall logs. |
| **Admin**    | Everything — full control. |

### Add a user

Settings → Admin & Users → **+ Add User**. Pick a role. The password
must be ≥ 8 characters.

### Change a user's role

In the Users table, use the role dropdown next to the user. Change
takes effect immediately — the target user's existing sessions keep
their old role until they log out.

**You cannot demote the last admin** — the API returns 400. Create
another admin first, then demote.

### Reset a user's password

Click the 🔑 icon next to the user, set a new password. Their existing
sessions are not invalidated — for that, have them log out, or wait for
session expiry (30 min idle).

### Change your own password

Settings → Admin & Users → **Change My Password**. All sessions are
invalidated on success — you're logged out of every other tab.

### Delete a user

Click the 🗑 icon. Cannot delete the last admin; cannot delete the user
you're currently logged in as.

---

## Backup and restore

### Download a backup

Settings → Backup → **Download Backup**. Saves a JSON file containing
firewall, NAT, routes, settings, and interface roles. Does not include
the TLS cert/key or the admin password hash.

### Import a backup

Settings → Backup → choose the JSON file → **Import**. Merges the
backup over the current config. Prompts for the admin password for
re-auth confirmation.

### Restore an older snapshot

Settings → Backup shows the list of server-side automatic backups (one
is made before every config-write). Click **Restore** → enter admin
password → appliance swaps config.

---

## Firmware upgrade

### Via the web UI

1. Settings → Firmware. Confirm which slot is active (A or B).
2. Pick your new signed `.iso` file. Click **Apply Upgrade**.
3. Enter your admin password when prompted.
4. The appliance verifies the ISO signature, writes it to the *standby*
   slot, and flips GRUB to boot into it.
5. Go to Settings → System → **Reboot**.
6. Appliance reboots into the new slot. If `quickfw-api` fails to come
   up within 5 minutes, a watchdog automatically rolls GRUB back to the
   previous slot and reboots.

Config (firewall, NAT, routing, users) survives the upgrade — it lives
on a separate `QUICKFW_PERSIST` partition.

### Via CLI (SSH console)

```bash
quickfw-upgrade verify  /path/to/quickfw-new.iso   # sanity-check before apply
quickfw-upgrade apply   /path/to/quickfw-new.iso   # verify + dd + flip + reboot
quickfw-upgrade status                              # which slot am I in?
quickfw-upgrade rollback                           # flip back to the other slot
```

See [UPGRADE.md](UPGRADE.md) for the full upgrade mechanics.

---

## Common failures

### "Appliance not initialized" on every page

First-boot lockdown. The admin still has the default `quickfw`
password. Log in with admin / quickfw, change it at the forced prompt,
and the lockdown lifts.

### Dashboard shows `dnsmasq: stopped` but clients are fine

Cosmetic — DHCP is provided by `dnsmasq.service` but the service lookup
is run under the API's restricted user. If clients are getting
addresses, ignore it. If they aren't, check journalctl:

```bash
journalctl -u dnsmasq -n 100
```

### Interface won't come up

1. Check physical link: **Network → Interfaces**. Status toggle on?
2. Verify addressing: click **Configure** on the row. Mode=static +
   valid CIDR + gateway?
3. Check `/var/log/quickfw/audit.log` for the last save attempt and
   the system journal for `quickfw-api` errors.

### Rule applied but traffic still dropped / allowed

nftables evaluates rules top-down. Use **Firewall → ↑/↓ arrows** to
reorder. Use **Preview nft** to see the actual generated script —
useful for confirming your rule is emitted where you expect.

### Persist partition full

`df -h /persist` on the console. The audit log rotates at 10 MB, but
if something else filled the partition (config backups, journal), clean
it up:

```bash
# Old config backups
ls -la /persist/etc/quickfw/*.backup.*
```

### Lost admin password

Physical console access required. Boot into recovery / single-user
mode, delete `/persist/etc/quickfw/users.yaml`, reboot. The appliance
re-enters first-boot mode with default admin/quickfw credentials, and
you can log in to the web UI to set a new password.

### Pending upgrade stuck, watchdog didn't fire

```bash
systemctl status quickfw-upgrade-verify
journalctl -u quickfw-upgrade-verify -n 50
```

Manually roll back:

```bash
quickfw-upgrade rollback
```

---

## Logs

Three sources, admin-only, available at **Audit** page:

- **Audit** — every POST/PUT/DELETE to the API with user, IP, response
  status. Exportable as CSV or JSON.
- **System** — `journalctl -u quickfw-api`. The API service's own
  stdout/stderr.
- **Firewall** — `journalctl -k --grep=QUICKFW`. Kernel-side LOG-rule
  output; nftables rules with `log prefix "QUICKFW ..."` show up here.

Raw tails are capped at 500 lines in the UI; use the CLI for deeper
digs:

```bash
journalctl -u quickfw-api --since "1 hour ago"
tail -n 500 /var/log/quickfw/audit.log
```
