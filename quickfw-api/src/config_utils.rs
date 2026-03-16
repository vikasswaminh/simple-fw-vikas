//! Config file backup and atomic write utilities.

use std::io::Write;
use tracing::info;

/// Backup a config file before overwriting it.
/// Copies to /etc/quickfw/backups/{filename}.{timestamp}.bak.
/// Keeps last 20 backups per file.
pub fn backup_config(path: &str) -> std::io::Result<()> {
    if !std::path::Path::new(path).exists() {
        return Ok(());
    }
    let backup_dir = "/etc/quickfw/backups";
    std::fs::create_dir_all(backup_dir)?;
    let filename = std::path::Path::new(path)
        .file_name()
        .unwrap()
        .to_string_lossy();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let backup_path = format!("{}/{}.{}.bak", backup_dir, filename, timestamp);
    std::fs::copy(path, &backup_path)?;
    info!("Config backup: {} -> {}", path, backup_path);
    prune_backups(backup_dir, &filename, 20);
    Ok(())
}

/// Atomic write: write to .tmp, fsync, rename.
pub fn atomic_write(path: &str, content: &str) -> std::io::Result<()> {
    let tmp_path = format!("{}.tmp", path);
    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// List backup files for all config files.
pub fn list_backups() -> Vec<BackupInfo> {
    let backup_dir = "/etc/quickfw/backups";
    let mut backups = Vec::new();
    if let Ok(entries) = std::fs::read_dir(backup_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".bak") {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                backups.push(BackupInfo { name, size });
            }
        }
    }
    backups.sort_by(|a, b| b.name.cmp(&a.name)); // newest first
    backups
}

#[derive(serde::Serialize)]
pub struct BackupInfo {
    pub name: String,
    pub size: u64,
}

/// Generic YAML config loader. Returns Default if file missing or parse fails.
pub fn load_yaml<T: serde::de::DeserializeOwned + Default>(path: &str) -> T {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_yaml::from_str(&s).ok())
        .unwrap_or_default()
}

/// Generic YAML config saver with error mapping for Axum handlers.
pub fn save_yaml<T: serde::Serialize>(
    path: &str,
    config: &T,
) -> Result<(), (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    let yaml = serde_yaml::to_string(config).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": format!("Serialize: {}", e)})),
        )
    })?;
    std::fs::write(path, &yaml).map_err(|e| {
        tracing::error!("Write {}: {}", path, e);
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": format!("Write: {}", e)})),
        )
    })?;
    Ok(())
}

fn prune_backups(backup_dir: &str, prefix: &str, keep: usize) {
    if let Ok(entries) = std::fs::read_dir(backup_dir) {
        let mut matching: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with(prefix) && name.ends_with(".bak") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        matching.sort();
        matching.reverse(); // newest first
        for old in matching.iter().skip(keep) {
            let path = format!("{}/{}", backup_dir, old);
            let _ = std::fs::remove_file(&path);
        }
    }
}
