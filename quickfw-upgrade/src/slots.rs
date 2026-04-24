//! A/B slot detection and pending-upgrade marker.
//!
//! The installed image layout is:
//!   /dev/disk/by-label/QUICKFW_A        — root slot A
//!   /dev/disk/by-label/QUICKFW_B        — root slot B
//!   /dev/disk/by-label/QUICKFW_PERSIST  — persistent config + logs
//!
//! Which slot is CURRENTLY BOOTED is determined by reading /proc/mounts:
//! the root mount resolves back to one of the two labelled devices via
//! /dev/disk/by-label symlinks.
//!
//! The pending-upgrade marker lives at
//! /persist/etc/quickfw/.upgrade-pending and contains the name of the slot
//! we flipped TO. The watchdog uses it to decide whether to confirm or
//! roll back after the boot. /persist is mounted by the Phase F
//! persistence hook.

use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct Slot {
    pub name: &'static str,
    pub device: String,
    pub grub_entry: &'static str,
}

#[derive(Debug)]
pub struct Layout {
    pub active: Slot,
    pub standby: Slot,
}

const PENDING_MARKER: &str = "/persist/etc/quickfw/.upgrade-pending";
const LABEL_A: &str = "QUICKFW_A";
const LABEL_B: &str = "QUICKFW_B";

/// Detect which slot is active and which is standby. Refuses if either
/// labelled device is absent — a QuickFW live ISO doesn't have this layout
/// and should never get here.
pub fn detect() -> Result<Layout, String> {
    let dev_a = format!("/dev/disk/by-label/{}", LABEL_A);
    let dev_b = format!("/dev/disk/by-label/{}", LABEL_B);

    if !Path::new(&dev_a).exists() {
        return Err(format!("{} not found", dev_a));
    }
    if !Path::new(&dev_b).exists() {
        return Err(format!("{} not found", dev_b));
    }

    // Resolve both symlinks to their canonical paths so we can compare
    // with /proc/mounts entries.
    let canon_a = fs::canonicalize(&dev_a).map_err(|e| format!("canonicalize {}: {}", dev_a, e))?;
    let canon_b = fs::canonicalize(&dev_b).map_err(|e| format!("canonicalize {}: {}", dev_b, e))?;

    let mounts = fs::read_to_string("/proc/mounts").map_err(|e| format!("read /proc/mounts: {}", e))?;
    let root_dev = mounts
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let dev = parts.next()?;
            let mount = parts.next()?;
            if mount == "/" {
                Some(dev.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| "no / mount in /proc/mounts".to_string())?;

    let root_canon = fs::canonicalize(&root_dev).unwrap_or_else(|_| root_dev.clone().into());

    let a_slot = Slot {
        name: "A",
        device: canon_a.to_string_lossy().into_owned(),
        grub_entry: "quickfw-a",
    };
    let b_slot = Slot {
        name: "B",
        device: canon_b.to_string_lossy().into_owned(),
        grub_entry: "quickfw-b",
    };

    let (active, standby) = if root_canon == canon_a {
        (a_slot, b_slot)
    } else if root_canon == canon_b {
        (b_slot, a_slot)
    } else {
        return Err(format!(
            "root device {} doesn't match QUICKFW_A or QUICKFW_B",
            root_canon.display()
        ));
    };
    Ok(Layout { active, standby })
}

pub fn write_pending_marker(target_slot: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(PENDING_MARKER).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    fs::write(PENDING_MARKER, target_slot).map_err(|e| format!("write {}: {}", PENDING_MARKER, e))
}

pub fn read_pending_marker() -> Option<String> {
    fs::read_to_string(PENDING_MARKER).ok().map(|s| s.trim().to_string())
}

pub fn clear_pending_marker() -> Result<(), String> {
    match fs::remove_file(PENDING_MARKER) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {}", PENDING_MARKER, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_marker_round_trip_in_temp() {
        // Can't test with the real /persist path (doesn't exist in CI /
        // on the bare-metal test VM). Just exercise the name parsing.
        assert_eq!(read_pending_marker(), None); // file not present
    }

    #[test]
    fn detect_returns_err_without_labels() {
        // CI / test hosts don't have QUICKFW_A/B labels — detect must
        // return a helpful error, not panic.
        let e = detect().unwrap_err();
        assert!(e.contains("QUICKFW_A") || e.contains("QUICKFW_B") || e.contains("/dev"));
    }
}
