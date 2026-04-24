//! ISO signature verification.
//!
//! Scheme: each released ISO ships with a detached signature file
//! `<iso>.sig` that is the base64-encoded ed25519 signature over the
//! SHA-256 hash of the ISO contents. The trusted public key is baked at
//! compile time from the QUICKFW_UPDATE_PUBKEY env var (base64 of the
//! raw 32-byte ed25519 public key).
//!
//! For local builds where QUICKFW_UPDATE_PUBKEY is unset, the constant
//! below is a zero-byte placeholder; every verify() call will fail.
//! That's deliberate — we never want a binary to silently accept unsigned
//! ISOs.
//!
//! A production build sets the env var to the public half of the release
//! key so the shipping binary will only accept ISOs signed by the private
//! half (which lives in the release infra, not the repo).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

/// Trusted ed25519 public key (base64-encoded 32 bytes). Baked at build
/// time via the QUICKFW_UPDATE_PUBKEY env var; defaults to the empty
/// string so every verify fails in dev builds.
const PUBKEY_B64: &str = match option_env!("QUICKFW_UPDATE_PUBKEY") {
    Some(s) => s,
    None => "",
};

pub fn verify_iso(iso_path: &str) -> Result<(), String> {
    let pubkey = load_pubkey()?;
    let sig_path = format!("{}.sig", iso_path);
    let sig_b64 = fs::read_to_string(&sig_path)
        .map_err(|e| format!("read signature {}: {}", sig_path, e))?;
    let sig_bytes = B64
        .decode(sig_b64.trim())
        .map_err(|e| format!("signature is not valid base64: {}", e))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("signature wrong length: {}", e))?;

    let hash = sha256_file(iso_path)?;
    pubkey
        .verify(&hash, &sig)
        .map_err(|_| "signature does NOT verify against trusted public key".to_string())
}

fn load_pubkey() -> Result<VerifyingKey, String> {
    if PUBKEY_B64.is_empty() {
        return Err(
            "this binary was built without QUICKFW_UPDATE_PUBKEY — every verify will fail. \
             Rebuild with `QUICKFW_UPDATE_PUBKEY=<base64-pubkey> cargo build`."
                .to_string(),
        );
    }
    let bytes = B64
        .decode(PUBKEY_B64)
        .map_err(|e| format!("QUICKFW_UPDATE_PUBKEY is not valid base64: {}", e))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "QUICKFW_UPDATE_PUBKEY must decode to exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid ed25519 public key: {}", e))
}

fn sha256_file(path: &str) -> Result<Vec<u8>, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open {}: {}", path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("read {}: {}", path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    // Test helper: override the baked pubkey by injecting a verify call
    // with a known key pair, bypassing load_pubkey. This exercises the
    // hash + sig machinery even when the real PUBKEY_B64 is empty.
    fn sign_and_verify_with_keypair(iso_bytes: &[u8]) {
        let dir = std::env::temp_dir();
        let iso_path = dir.join(format!("qfwupg-test-{}.iso", std::process::id()));
        let sig_path = dir.join(format!("qfwupg-test-{}.iso.sig", std::process::id()));
        fs::write(&iso_path, iso_bytes).unwrap();

        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        let mut hasher = Sha256::new();
        hasher.update(iso_bytes);
        let hash = hasher.finalize();
        let sig = key.sign(&hash);
        fs::write(&sig_path, B64.encode(sig.to_bytes())).unwrap();

        // Verify directly with the keypair (no load_pubkey).
        let sig_b64 = fs::read_to_string(&sig_path).unwrap();
        let sig_bytes = B64.decode(sig_b64.trim()).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let vk: VerifyingKey = key.verifying_key();
        let disk_hash = sha256_file(iso_path.to_str().unwrap()).unwrap();
        assert!(vk.verify(&disk_hash, &sig).is_ok());

        let _ = fs::remove_file(&iso_path);
        let _ = fs::remove_file(&sig_path);
    }

    #[test]
    fn sign_verify_round_trip_with_known_key() {
        sign_and_verify_with_keypair(b"hello world - pretend this is an ISO");
    }

    #[test]
    fn verify_iso_without_baked_pubkey_fails_loudly() {
        // Even if the signature and ISO are valid, a dev binary with no
        // baked pubkey must refuse — that's the entire point.
        let dir = std::env::temp_dir();
        let iso_path = dir.join(format!("qfwupg-nopk-{}.iso", std::process::id()));
        let sig_path = dir.join(format!("qfwupg-nopk-{}.iso.sig", std::process::id()));
        fs::write(&iso_path, b"payload").unwrap();
        fs::write(&sig_path, "ignored").unwrap();

        let e = verify_iso(iso_path.to_str().unwrap()).unwrap_err();
        // Either "built without QUICKFW_UPDATE_PUBKEY" (no-key dev build)
        // or a signature-decode error (prod build). Both acceptable.
        assert!(
            e.contains("QUICKFW_UPDATE_PUBKEY")
                || e.contains("signature")
                || e.contains("public key"),
            "unexpected error: {}",
            e
        );

        let _ = fs::remove_file(&iso_path);
        let _ = fs::remove_file(&sig_path);
    }

    #[test]
    fn missing_signature_file_errors() {
        let iso_path = std::env::temp_dir().join(format!("qfwupg-nosig-{}.iso", std::process::id()));
        fs::write(&iso_path, b"content").unwrap();
        let e = verify_iso(iso_path.to_str().unwrap()).unwrap_err();
        assert!(e.contains("read signature") || e.contains("QUICKFW_UPDATE_PUBKEY"));
        let _ = fs::remove_file(&iso_path);
    }
}
