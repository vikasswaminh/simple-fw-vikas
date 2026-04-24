//! QuickFW A/B upgrade CLI (Phase H).
//!
//! An installed QuickFW appliance has two root-filesystem slots labelled
//! QUICKFW_A and QUICKFW_B, plus a persistent partition labelled
//! QUICKFW_PERSIST that holds config + logs (see Phase F). Exactly one slot
//! is "active" (booted); the other is standby and gets overwritten by the
//! next `apply`.
//!
//! Subcommands:
//!   apply <iso>       Verify + install + flip + mark-pending + reboot.
//!   rollback          Flip GRUB back to the previously active slot and reboot.
//!   status            Print the current + standby slot, last upgrade state.
//!   verify <iso>      Verify the signed manifest without touching disk.
//!
//! Signature scheme:
//!   - Each released ISO ships with a separate `<iso>.sig` file — an ed25519
//!     signature over the SHA-256 hash of the ISO.
//!   - The public key is baked in at compile time via the QUICKFW_UPDATE_PUBKEY
//!     env var (base64). When the env var is absent during build, a
//!     `DEV_KEY_UNSAFE` sentinel is used and `verify` prints a prominent
//!     warning — useful for local dev, never used for production ISOs.
//!
//! Watchdog:
//!   A companion systemd unit (quickfw-upgrade-verify.service) runs this
//!   binary with `mark-good` 5 minutes post-boot. If `/persist/etc/quickfw/
//!   .upgrade-pending` exists and quickfw-api is active, the pending marker
//!   is deleted. If quickfw-api is inactive, we flip back to the other slot
//!   and reboot.

use clap::{Parser, Subcommand};
use std::path::Path;
use std::process::Command;

mod signature;
mod slots;

#[derive(Parser)]
#[command(name = "quickfw-upgrade", version, about = "QuickFW A/B upgrade manager")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify a signed ISO without touching disk — useful before apply.
    Verify { iso: String },
    /// Apply an ISO: verify, dd to inactive slot, flip GRUB, reboot.
    Apply {
        iso: String,
        /// Skip final reboot (for testing).
        #[arg(long)]
        no_reboot: bool,
    },
    /// Flip GRUB to the previously active slot and reboot.
    Rollback {
        #[arg(long)]
        no_reboot: bool,
    },
    /// Print current slot + pending upgrade state.
    Status,
    /// Watchdog: invoked 5 min after boot by systemd. Finalizes or rolls back
    /// a pending upgrade based on whether quickfw-api is active.
    MarkGood,
}

fn main() {
    let cli = Cli::parse();
    let exit = match cli.cmd {
        Cmd::Verify { iso } => cmd_verify(&iso),
        Cmd::Apply { iso, no_reboot } => cmd_apply(&iso, no_reboot),
        Cmd::Rollback { no_reboot } => cmd_rollback(no_reboot),
        Cmd::Status => cmd_status(),
        Cmd::MarkGood => cmd_mark_good(),
    };
    std::process::exit(exit);
}

fn cmd_verify(iso: &str) -> i32 {
    match signature::verify_iso(iso) {
        Ok(()) => {
            println!("OK: signature verified");
            0
        }
        Err(e) => {
            eprintln!("ERROR: verification failed: {}", e);
            2
        }
    }
}

fn cmd_apply(iso: &str, no_reboot: bool) -> i32 {
    // 1. Verify first — before touching any disk.
    if let Err(e) = signature::verify_iso(iso) {
        eprintln!("ERROR: verification failed: {}", e);
        return 2;
    }

    // 2. Determine active + standby slots. Refuse if we can't find both.
    let layout = match slots::detect() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ERROR: {} (is this an installed image with QUICKFW_A/QUICKFW_B partitions?)", e);
            return 3;
        }
    };
    println!("Active slot: {} ({})", layout.active.name, layout.active.device);
    println!("Writing ISO to standby: {} ({})", layout.standby.name, layout.standby.device);

    // 3. dd the ISO into the standby slot.
    if let Err(e) = dd_to(iso, &layout.standby.device) {
        eprintln!("ERROR: dd failed: {}", e);
        return 4;
    }
    println!("OK: ISO written to {}", layout.standby.device);

    // 4. Flip GRUB default to the standby slot using grub-reboot. This is
    //    a ONE-TIME boot override — if the new slot's quickfw-api fails
    //    the watchdog will flip back before the boot sticks.
    if let Err(e) = grub_reboot(&layout.standby.grub_entry) {
        eprintln!("ERROR: grub-reboot failed: {}", e);
        return 5;
    }

    // 5. Write the .upgrade-pending marker so the watchdog knows to verify.
    if let Err(e) = slots::write_pending_marker(&layout.standby.name) {
        eprintln!("WARN: could not write pending marker: {} (watchdog won't run)", e);
    }

    if no_reboot {
        println!("--no-reboot: skipping reboot. `systemctl reboot` to finish.");
        return 0;
    }

    println!("Rebooting into {} ...", layout.standby.name);
    let _ = Command::new("systemctl").arg("reboot").status();
    0
}

fn cmd_rollback(no_reboot: bool) -> i32 {
    let layout = match slots::detect() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return 3;
        }
    };
    // Rolling back == booting the CURRENT standby (which is the previous
    // active). That's just another grub-reboot flip.
    if let Err(e) = grub_reboot(&layout.standby.grub_entry) {
        eprintln!("ERROR: grub-reboot failed: {}", e);
        return 5;
    }
    // Clear pending marker so we don't bounce in a loop.
    let _ = slots::clear_pending_marker();
    if no_reboot {
        println!("--no-reboot: flip written, reboot manually to take effect.");
        return 0;
    }
    println!("Rolling back to {} ...", layout.standby.name);
    let _ = Command::new("systemctl").arg("reboot").status();
    0
}

fn cmd_status() -> i32 {
    match slots::detect() {
        Ok(l) => {
            println!("Active:  {} ({})", l.active.name, l.active.device);
            println!("Standby: {} ({})", l.standby.name, l.standby.device);
            match slots::read_pending_marker() {
                Some(target) => println!("Pending: upgrade to slot {}", target),
                None => println!("Pending: none"),
            }
            0
        }
        Err(e) => {
            eprintln!("(no A/B layout: {})", e);
            1
        }
    }
}

fn cmd_mark_good() -> i32 {
    let pending = match slots::read_pending_marker() {
        Some(p) => p,
        None => {
            // Nothing pending — nothing to do.
            return 0;
        }
    };
    // Check quickfw-api is active. If yes, clear the pending marker. If
    // not, rollback.
    let active = Command::new("systemctl")
        .args(["is-active", "quickfw-api"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if active {
        println!("upgrade to {} looks good; clearing pending marker", pending);
        let _ = slots::clear_pending_marker();
        0
    } else {
        println!("upgrade to {} unhealthy (quickfw-api not active); rolling back", pending);
        cmd_rollback(false)
    }
}

fn dd_to(iso: &str, device: &str) -> Result<(), String> {
    if !Path::new(iso).exists() {
        return Err(format!("ISO not found: {}", iso));
    }
    let out = Command::new("dd")
        .args([
            &format!("if={}", iso),
            &format!("of={}", device),
            "bs=4M",
            "status=progress",
            "conv=fsync",
        ])
        .status()
        .map_err(|e| format!("spawn dd: {}", e))?;
    if out.success() {
        Ok(())
    } else {
        Err(format!("dd exited with {}", out))
    }
}

fn grub_reboot(entry: &str) -> Result<(), String> {
    let out = Command::new("grub-reboot")
        .arg(entry)
        .status()
        .map_err(|e| format!("spawn grub-reboot: {}", e))?;
    if out.success() {
        Ok(())
    } else {
        Err(format!("grub-reboot exited with {}", out))
    }
}
