//! Global state for the API server.
//!
//! Provides a process-level lock around all config file I/O to prevent
//! concurrent writes from corrupting YAML files.

use tokio::sync::Mutex;

static CONFIG_LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();

/// Returns the global config I/O mutex.
/// All handlers that read or write YAML config files must acquire this lock.
pub fn config_lock() -> &'static Mutex<()> {
    CONFIG_LOCK.get_or_init(|| Mutex::new(()))
}
