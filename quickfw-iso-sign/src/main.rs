//! QuickFW release ISO signer.
//!
//! Two subcommands, both meant to run on a release/build host (not on the
//! appliance):
//!
//!   keygen         — generate a fresh ed25519 keypair, print pubkey
//!                    (stdout, base64) and write privkey to a file (0600).
//!   sign <iso>     — produce <iso>.sig — the base64 ed25519 signature over
//!                    SHA-256(iso). Reads the privkey from --key <path> or
//!                    QUICKFW_SIGN_PRIVKEY env var.
//!
//! Pair this with `quickfw-upgrade verify`, which uses the same scheme:
//! the public key is baked into quickfw-upgrade at compile time via
//! QUICKFW_UPDATE_PUBKEY (which is exactly what `keygen` prints).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

#[derive(Parser)]
#[command(name = "quickfw-iso-sign", version, about = "Offline ed25519 signer for QuickFW ISOs")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a fresh ed25519 keypair. Prints the public key (base64) on
    /// stdout. Writes the private key to --out (0600). Run this ONCE,
    /// offline, and store the private key somewhere safe.
    Keygen {
        /// Path to write the private key file (32 bytes, base64). 0600 mode.
        #[arg(long, default_value = "quickfw-release.key")]
        out: String,
    },
    /// Sign an ISO. Produces <iso>.sig.
    Sign {
        iso: String,
        /// Path to the private key file. Falls back to QUICKFW_SIGN_PRIVKEY
        /// env var (also base64-encoded private key).
        #[arg(long)]
        key: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let exit = match cli.cmd {
        Cmd::Keygen { out } => keygen(&out),
        Cmd::Sign { iso, key } => sign(&iso, key.as_deref()),
    };
    std::process::exit(exit);
}

fn keygen(out_path: &str) -> i32 {
    use rand_core::OsRng;
    let mut csprng = OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let verifying: VerifyingKey = signing.verifying_key();

    let priv_b64 = B64.encode(signing.to_bytes());
    let pub_b64 = B64.encode(verifying.to_bytes());

    if let Err(e) = fs::write(out_path, &priv_b64) {
        eprintln!("ERROR: write {}: {}", out_path, e);
        return 2;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(out_path, fs::Permissions::from_mode(0o600));
    }

    println!("Wrote private key to {} (0600)", out_path);
    println!();
    println!("Public key (use as QUICKFW_UPDATE_PUBKEY when building quickfw-upgrade):");
    println!("{}", pub_b64);
    println!();
    println!("Private key (also written to {} — DO NOT commit this):", out_path);
    println!("{}", priv_b64);
    0
}

fn sign(iso_path: &str, key_arg: Option<&str>) -> i32 {
    let priv_b64 = match resolve_privkey(key_arg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return 2;
        }
    };
    let priv_bytes = match B64.decode(priv_b64.trim()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: private key is not valid base64: {}", e);
            return 2;
        }
    };
    let priv_arr: [u8; 32] = match priv_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("ERROR: private key must decode to exactly 32 bytes");
            return 2;
        }
    };
    let signing = SigningKey::from_bytes(&priv_arr);

    let hash = match sha256_file(iso_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("ERROR: hash {}: {}", iso_path, e);
            return 3;
        }
    };
    let sig = signing.sign(&hash);
    let sig_b64 = B64.encode(sig.to_bytes());
    let sig_path = format!("{}.sig", iso_path);
    if let Err(e) = fs::write(&sig_path, &sig_b64) {
        eprintln!("ERROR: write {}: {}", sig_path, e);
        return 4;
    }
    println!("Wrote signature to {}", sig_path);
    println!("ISO   sha256: {}", hex(&hash));
    println!("Pubkey base64: {}", B64.encode(signing.verifying_key().to_bytes()));
    0
}

fn resolve_privkey(key_arg: Option<&str>) -> Result<String, String> {
    if let Some(p) = key_arg {
        return fs::read_to_string(p).map_err(|e| format!("read --key {}: {}", p, e));
    }
    if let Ok(env) = std::env::var("QUICKFW_SIGN_PRIVKEY") {
        return Ok(env);
    }
    Err("no --key supplied and QUICKFW_SIGN_PRIVKEY not set".to_string())
}

fn sha256_file(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
