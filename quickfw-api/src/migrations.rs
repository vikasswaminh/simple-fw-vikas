//! Config schema migration framework.
//!
//! Every appliance YAML now carries a `schema_version: "X.Y"` string. The
//! migration framework wraps the load path:
//!
//! 1. Parse the YAML as a generic `serde_yaml::Value`.
//! 2. Extract `schema_version` (default `"1.0"`).
//! 3. If the stored version is **higher** than `CURRENT`, refuse to load —
//!    that's a downgrade scenario and blindly parsing could drop fields.
//! 4. If the version is **older**, run the per-domain migration chain to
//!    bring the value up to `CURRENT` before typed deserialization.
//! 5. Deserialize into the typed struct.
//!
//! The 1.0 → 1.0 path is a no-op; the migration chain is an empty Vec for
//! each domain today. When a future schema change requires a migration, add
//! a closure to the appropriate chain (e.g., `firewall_migrations()`) that
//! mutates the `Value` in place and the next binary will transparently
//! upgrade any appliance's config on first load.
//!
//! The migrated Value is *also* re-serialized back to disk after load, so
//! the next boot doesn't re-run the migration.

use serde::de::DeserializeOwned;

/// Current schema version for every domain. Bump when a breaking change is
/// introduced and add a corresponding entry to the domain's migration chain.
pub const CURRENT_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug)]
pub enum MigrationError {
    Read(std::io::Error),
    Parse(serde_yaml::Error),
    Typed(serde_yaml::Error),
    /// Config was written by a newer binary than us — refuse to load rather
    /// than silently drop unknown fields.
    Unsupported { stored: String, current: String },
    /// A migration step failed to transform the value.
    Migrate { from: String, to: String, reason: String },
    Write(std::io::Error),
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "read failed: {}", e),
            Self::Parse(e) => write!(f, "yaml parse failed: {}", e),
            Self::Typed(e) => write!(f, "typed deserialization failed: {}", e),
            Self::Unsupported { stored, current } => write!(
                f,
                "config schema_version {} is newer than binary supports ({}) — refusing to load",
                stored, current
            ),
            Self::Migrate { from, to, reason } => {
                write!(f, "migration {} -> {} failed: {}", from, to, reason)
            }
            Self::Write(e) => write!(f, "write-back after migration failed: {}", e),
        }
    }
}

impl std::error::Error for MigrationError {}

/// One step in a migration chain: given a Value at version `from`, produce
/// a Value at version `to`. Mutates in place.
pub struct MigrationStep {
    pub from: &'static str,
    pub to: &'static str,
    pub apply: fn(&mut serde_yaml::Value) -> Result<(), String>,
}

/// Compare two dotted schema versions numerically (e.g. "1.0" vs "1.10").
/// Returns Ordering of `a` vs `b`.
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(v: &str) -> Vec<u64> {
        v.split('.').filter_map(|p| p.parse().ok()).collect()
    }
    parts(a).cmp(&parts(b))
}

/// Extract schema_version from a Value, defaulting to "1.0" if absent.
/// "1.0" is the pre-migration baseline — configs written before the
/// framework existed didn't have the field.
fn extract_version(v: &serde_yaml::Value) -> String {
    v.get("schema_version")
        .and_then(|x| x.as_str())
        .unwrap_or("1.0")
        .to_string()
}

/// Run a migration chain over `value` to bring it up to `CURRENT_SCHEMA_VERSION`.
fn run_chain(
    value: &mut serde_yaml::Value,
    steps: &[MigrationStep],
) -> Result<(), MigrationError> {
    let mut current = extract_version(value);
    loop {
        match version_cmp(&current, CURRENT_SCHEMA_VERSION) {
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Greater => {
                return Err(MigrationError::Unsupported {
                    stored: current,
                    current: CURRENT_SCHEMA_VERSION.to_string(),
                });
            }
            std::cmp::Ordering::Less => {
                let step = steps
                    .iter()
                    .find(|s| s.from == current)
                    .ok_or_else(|| MigrationError::Migrate {
                        from: current.clone(),
                        to: CURRENT_SCHEMA_VERSION.to_string(),
                        reason: format!("no migration registered from {}", current),
                    })?;
                (step.apply)(value).map_err(|reason| MigrationError::Migrate {
                    from: step.from.to_string(),
                    to: step.to.to_string(),
                    reason,
                })?;
                // Bump the version field so the next iteration sees it.
                if let serde_yaml::Value::Mapping(m) = value {
                    m.insert(
                        serde_yaml::Value::String("schema_version".to_string()),
                        serde_yaml::Value::String(step.to.to_string()),
                    );
                }
                current = step.to.to_string();
            }
        }
    }
}

/// Load a YAML file, run the migration chain, then deserialize into T.
/// If migration rewrote fields, the file is also re-saved so the next boot
/// starts at the new baseline.
pub fn load_migrated<T: DeserializeOwned>(
    path: &str,
    steps: &[MigrationStep],
) -> Result<T, MigrationError> {
    let raw = std::fs::read_to_string(path).map_err(MigrationError::Read)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&raw).map_err(MigrationError::Parse)?;

    let before = extract_version(&value);
    run_chain(&mut value, steps)?;
    let after = extract_version(&value);

    // Typed deserialization — this is where unknown fields get dropped;
    // by now the migration chain has normalized the shape.
    let typed: T = serde_yaml::from_value(value.clone()).map_err(MigrationError::Typed)?;

    // Write back if the migration changed anything.
    if before != after {
        let new_yaml =
            serde_yaml::to_string(&value).map_err(MigrationError::Parse)?;
        std::fs::write(path, new_yaml).map_err(MigrationError::Write)?;
    }

    Ok(typed)
}

// ---------------------------------------------------------------------------
// Per-domain migration chains. Today every chain is empty (we're at 1.0),
// but this is where future schema migrations will live.
// ---------------------------------------------------------------------------

/// Firewall config migrations.
pub fn firewall_migrations() -> Vec<MigrationStep> {
    Vec::new()
}

/// NAT config migrations.
pub fn nat_migrations() -> Vec<MigrationStep> {
    Vec::new()
}

/// OSPF config migrations.
pub fn ospf_migrations() -> Vec<MigrationStep> {
    Vec::new()
}

/// BGP config migrations.
pub fn bgp_migrations() -> Vec<MigrationStep> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestCfg {
        #[serde(default = "default_v")]
        schema_version: String,
        name: String,
        #[serde(default)]
        count: u32,
    }
    fn default_v() -> String {
        "1.0".to_string()
    }

    #[test]
    fn version_cmp_orders_correctly() {
        use std::cmp::Ordering::*;
        assert_eq!(version_cmp("1.0", "1.0"), Equal);
        assert_eq!(version_cmp("1.0", "1.1"), Less);
        assert_eq!(version_cmp("1.10", "1.2"), Greater);
        assert_eq!(version_cmp("2.0", "1.99"), Greater);
    }

    #[test]
    fn load_migrated_with_matching_version_succeeds() {
        let dir = tempdir();
        let path = format!("{}/test.yaml", dir);
        std::fs::write(&path, "schema_version: \"1.0\"\nname: hello\ncount: 42\n").unwrap();

        let cfg: TestCfg = load_migrated(&path, &[]).unwrap();
        assert_eq!(cfg.schema_version, "1.0");
        assert_eq!(cfg.name, "hello");
        assert_eq!(cfg.count, 42);

        cleanup(&dir);
    }

    #[test]
    fn load_migrated_with_missing_version_defaults_to_1_0() {
        // A config written before the framework existed has no schema_version.
        // We treat that as "1.0" — the pre-framework baseline.
        let dir = tempdir();
        let path = format!("{}/test.yaml", dir);
        std::fs::write(&path, "name: legacy\n").unwrap();

        let cfg: TestCfg = load_migrated(&path, &[]).unwrap();
        assert_eq!(cfg.schema_version, "1.0");
        assert_eq!(cfg.name, "legacy");
        cleanup(&dir);
    }

    #[test]
    fn load_migrated_refuses_future_version() {
        let dir = tempdir();
        let path = format!("{}/test.yaml", dir);
        std::fs::write(&path, "schema_version: \"99.0\"\nname: future\n").unwrap();

        let err = load_migrated::<TestCfg>(&path, &[]).unwrap_err();
        assert!(matches!(err, MigrationError::Unsupported { .. }));
        cleanup(&dir);
    }

    #[test]
    fn migration_chain_applies_and_writes_back() {
        // Pretend the schema went from 0.9 → 1.0, and the migration renames
        // `old_name` to `name`.
        let dir = tempdir();
        let path = format!("{}/test.yaml", dir);
        std::fs::write(&path, "schema_version: \"0.9\"\nold_name: renamed\ncount: 7\n").unwrap();

        let steps = vec![MigrationStep {
            from: "0.9",
            to: "1.0",
            apply: |v: &mut serde_yaml::Value| {
                let m = v.as_mapping_mut().ok_or("not a mapping")?;
                if let Some(old) = m.remove("old_name") {
                    m.insert(serde_yaml::Value::String("name".to_string()), old);
                }
                Ok(())
            },
        }];

        let cfg: TestCfg = load_migrated(&path, &steps).unwrap();
        assert_eq!(cfg.name, "renamed");
        assert_eq!(cfg.count, 7);

        // The file should have been rewritten at the new version.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("schema_version: '1.0'") || on_disk.contains("schema_version: \"1.0\""));
        assert!(!on_disk.contains("old_name"));
        cleanup(&dir);
    }

    #[test]
    fn migration_missing_step_errors_clearly() {
        let dir = tempdir();
        let path = format!("{}/test.yaml", dir);
        std::fs::write(&path, "schema_version: \"0.5\"\nname: old\n").unwrap();

        // No step from 0.5 → 1.0 registered.
        let err = load_migrated::<TestCfg>(&path, &[]).unwrap_err();
        match err {
            MigrationError::Migrate { from, reason, .. } => {
                assert_eq!(from, "0.5");
                assert!(reason.contains("no migration registered"));
            }
            other => panic!("expected Migrate, got {:?}", other),
        }
        cleanup(&dir);
    }

    // --- tiny tempdir helper so we don't pull in the `tempfile` crate ---
    fn tempdir() -> String {
        let n: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let p = format!("/tmp/quickfw-mig-test-{}", n);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn cleanup(dir: &str) {
        let _ = std::fs::remove_dir_all(dir);
    }
}
