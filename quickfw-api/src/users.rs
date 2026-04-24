//! Multi-user RBAC store (Phase G).
//!
//! Users live in `/etc/quickfw/users.yaml`. Three roles:
//!   - `Admin`    — full control, only one who can manage users or reboot
//!   - `Operator` — edits firewall/NAT/routing/settings but no destructive
//!                  system ops and no user management
//!   - `Readonly` — GET-only
//!
//! On first load, if users.yaml is absent but the legacy
//! `/etc/quickfw/admin.password` file exists, we migrate the single admin
//! hash into users.yaml with role=Admin and delete the legacy file. This
//! keeps upgraded appliances working without manual intervention.
//!
//! Password hashing uses the same argon2 parameters as the pre-existing
//! admin.password path (see auth.rs), so hashes are interchangeable.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const USERS_PATH: &str = "/etc/quickfw/users.yaml";
pub const LEGACY_ADMIN_PASSWORD_PATH: &str = "/etc/quickfw/admin.password";

/// Three-tier role. Ordered by privilege: Admin > Operator > Readonly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Readonly,
    Operator,
    Admin,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Readonly => "readonly",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "readonly" => Some(Role::Readonly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersFile {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub users: Vec<User>,
}

impl Default for UsersFile {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            users: Vec::new(),
        }
    }
}

fn default_schema_version() -> String {
    "1.0".to_string()
}

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

/// Load users.yaml, performing the legacy-admin migration on first run.
///
/// If users.yaml already exists, returns its contents.
/// If it doesn't exist but admin.password does, migrates into a new file
/// with a single `admin` user at role=Admin, then deletes the legacy file.
/// If neither exists, returns an empty UsersFile — callers treat this as
/// "first-boot state" and the login layer will refuse until admin is set.
pub fn load_users() -> UsersFile {
    if Path::new(USERS_PATH).exists() {
        match std::fs::read_to_string(USERS_PATH) {
            Ok(s) => serde_yaml::from_str(&s).unwrap_or_default(),
            Err(_) => UsersFile::default(),
        }
    } else if Path::new(LEGACY_ADMIN_PASSWORD_PATH).exists() {
        let file = migrate_from_legacy();
        let _ = save_users(&file);
        // Delete the legacy file so we never migrate twice. If delete fails
        // the next boot will see users.yaml exists and skip migration.
        let _ = std::fs::remove_file(LEGACY_ADMIN_PASSWORD_PATH);
        file
    } else {
        UsersFile::default()
    }
}

fn migrate_from_legacy() -> UsersFile {
    let hash = std::fs::read_to_string(LEGACY_ADMIN_PASSWORD_PATH)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    UsersFile {
        schema_version: default_schema_version(),
        users: vec![User {
            username: "admin".to_string(),
            password_hash: hash,
            role: Role::Admin,
        }],
    }
}

pub fn save_users(file: &UsersFile) -> Result<(), String> {
    let _ = std::fs::create_dir_all("/etc/quickfw");
    let yaml =
        serde_yaml::to_string(file).map_err(|e| format!("serialize users: {}", e))?;
    // Atomic write: tmp → rename. 0600 permissions — the file holds hashes.
    let tmp = format!("{}.tmp", USERS_PATH);
    std::fs::write(&tmp, yaml).map_err(|e| format!("write tmp: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, USERS_PATH).map_err(|e| format!("rename: {}", e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Password helpers — argon2id, matching auth.rs
// ---------------------------------------------------------------------------

pub fn hash_password(pass: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pass.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("argon2: {}", e))
}

pub fn verify_password(stored_hash: &str, candidate: &str) -> bool {
    if stored_hash.is_empty() {
        return false;
    }
    if let Ok(parsed) = PasswordHash::new(stored_hash) {
        return Argon2::default()
            .verify_password(candidate.as_bytes(), &parsed)
            .is_ok();
    }
    // Legacy plaintext path — for the one-shot migration case where
    // admin.password never got hashed. Constant-time compare.
    use subtle::ConstantTimeEq;
    let a = stored_hash.as_bytes();
    let b = candidate.as_bytes();
    let len = std::cmp::min(a.len(), b.len());
    let ok: bool = a[..len].ct_eq(&b[..len]).into();
    ok && a.len() == b.len()
}

// ---------------------------------------------------------------------------
// High-level CRUD operations. All save on success.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum UserOpError {
    NotFound,
    AlreadyExists,
    LastAdmin,
    InvalidRole,
    WeakPassword,
    Hash(String),
    Io(String),
}

impl std::fmt::Display for UserOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "user not found"),
            Self::AlreadyExists => write!(f, "user already exists"),
            Self::LastAdmin => {
                write!(f, "cannot remove or demote the last admin")
            }
            Self::InvalidRole => write!(f, "invalid role"),
            Self::WeakPassword => {
                write!(f, "password must be at least 8 characters")
            }
            Self::Hash(e) => write!(f, "hash error: {}", e),
            Self::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

pub fn find_user<'a>(file: &'a UsersFile, username: &str) -> Option<&'a User> {
    file.users.iter().find(|u| u.username == username)
}

pub fn admin_count(file: &UsersFile) -> usize {
    file.users.iter().filter(|u| u.role == Role::Admin).count()
}

pub fn create_user(
    file: &mut UsersFile,
    username: &str,
    password: &str,
    role: Role,
) -> Result<(), UserOpError> {
    if password.len() < 8 {
        return Err(UserOpError::WeakPassword);
    }
    if file.users.iter().any(|u| u.username == username) {
        return Err(UserOpError::AlreadyExists);
    }
    let hash = hash_password(password).map_err(UserOpError::Hash)?;
    file.users.push(User {
        username: username.to_string(),
        password_hash: hash,
        role,
    });
    save_users(file).map_err(UserOpError::Io)?;
    Ok(())
}

pub fn delete_user(file: &mut UsersFile, username: &str) -> Result<(), UserOpError> {
    let idx = file
        .users
        .iter()
        .position(|u| u.username == username)
        .ok_or(UserOpError::NotFound)?;
    if file.users[idx].role == Role::Admin && admin_count(file) <= 1 {
        return Err(UserOpError::LastAdmin);
    }
    file.users.remove(idx);
    save_users(file).map_err(UserOpError::Io)?;
    Ok(())
}

pub fn set_role(
    file: &mut UsersFile,
    username: &str,
    new_role: Role,
) -> Result<(), UserOpError> {
    let idx = file
        .users
        .iter()
        .position(|u| u.username == username)
        .ok_or(UserOpError::NotFound)?;
    if file.users[idx].role == Role::Admin
        && new_role != Role::Admin
        && admin_count(file) <= 1
    {
        return Err(UserOpError::LastAdmin);
    }
    file.users[idx].role = new_role;
    save_users(file).map_err(UserOpError::Io)?;
    Ok(())
}

pub fn set_password(
    file: &mut UsersFile,
    username: &str,
    new_password: &str,
) -> Result<(), UserOpError> {
    if new_password.len() < 8 {
        return Err(UserOpError::WeakPassword);
    }
    let idx = file
        .users
        .iter()
        .position(|u| u.username == username)
        .ok_or(UserOpError::NotFound)?;
    let hash = hash_password(new_password).map_err(UserOpError::Hash)?;
    file.users[idx].password_hash = hash;
    save_users(file).map_err(UserOpError::Io)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — cover everything that doesn't touch the real /etc/quickfw path.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_file() -> UsersFile {
        let mut f = UsersFile::default();
        let hash = hash_password("initial1!").unwrap();
        f.users.push(User {
            username: "admin".to_string(),
            password_hash: hash,
            role: Role::Admin,
        });
        f
    }

    #[test]
    fn role_parse_roundtrip() {
        for r in [Role::Admin, Role::Operator, Role::Readonly] {
            assert_eq!(Role::parse(r.as_str()), Some(r));
        }
        assert_eq!(Role::parse("Admin"), Some(Role::Admin));
        assert_eq!(Role::parse("bogus"), None);
    }

    #[test]
    fn role_ordering_matches_privilege() {
        assert!(Role::Admin > Role::Operator);
        assert!(Role::Operator > Role::Readonly);
    }

    #[test]
    fn password_hash_verifies() {
        let hash = hash_password("correct-horse-battery-staple").unwrap();
        assert!(verify_password(&hash, "correct-horse-battery-staple"));
        assert!(!verify_password(&hash, "wrong-password"));
    }

    #[test]
    fn verify_empty_hash_is_false() {
        assert!(!verify_password("", "anything"));
    }

    #[test]
    fn cannot_delete_last_admin() {
        // save_users will fail in the test environment (no perms on /etc),
        // so we bypass save by calling delete on a file with the migrations
        // ... actually delete_user calls save_users which would IO-error.
        // Test the pre-check branch by asserting the LastAdmin error surfaces
        // BEFORE any save attempt.
        let mut f = mk_file();
        assert_eq!(admin_count(&f), 1);
        let err = delete_user(&mut f, "admin").unwrap_err();
        assert_eq!(err, UserOpError::LastAdmin);
        assert_eq!(f.users.len(), 1, "delete must not have happened");
    }

    #[test]
    fn cannot_demote_last_admin() {
        let mut f = mk_file();
        let err = set_role(&mut f, "admin", Role::Operator).unwrap_err();
        assert_eq!(err, UserOpError::LastAdmin);
    }

    #[test]
    fn weak_password_rejected_on_create() {
        let mut f = mk_file();
        let err = create_user(&mut f, "bob", "short", Role::Operator).unwrap_err();
        assert_eq!(err, UserOpError::WeakPassword);
    }

    #[test]
    fn weak_password_rejected_on_set_password() {
        let mut f = mk_file();
        let err = set_password(&mut f, "admin", "short").unwrap_err();
        assert_eq!(err, UserOpError::WeakPassword);
    }

    #[test]
    fn find_user_works() {
        let f = mk_file();
        assert!(find_user(&f, "admin").is_some());
        assert!(find_user(&f, "nobody").is_none());
    }

    #[test]
    fn role_serde_uses_lowercase() {
        let yaml = serde_yaml::to_string(&Role::Admin).unwrap();
        assert_eq!(yaml.trim(), "admin");
        let r: Role = serde_yaml::from_str("admin").unwrap();
        assert_eq!(r, Role::Admin);
    }
}
