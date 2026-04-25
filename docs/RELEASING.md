# QuickFW — Release Pipeline

How to cut a signed release ISO that operators can apply via
`quickfw-upgrade apply` or the Firmware tab in the web UI.

This is operator/maintainer-facing documentation. End-users never need
to read it.

---

## One-time setup: generate the release signing key

Do this **once**, on an offline / air-gapped machine ideally, and never
again.

```bash
cargo run --release -p quickfw-iso-sign -- keygen --out /secure/quickfw-release.key
```

Output looks like:

```
Wrote private key to /secure/quickfw-release.key (0600)

Public key (use as QUICKFW_UPDATE_PUBKEY when building quickfw-upgrade):
A0Bcdef0123456789abcdefghijklmnopqrstuvwxyz0123456789=

Private key (also written to /secure/quickfw-release.key — DO NOT commit this):
zyxw98765...
```

Two things to do with the output:

1. **Public key** — paste it into the repo's CI secrets or build-config
   under the name `QUICKFW_UPDATE_PUBKEY`. It's safe to commit; it's
   only the *public* half. Operators can use it later to verify ISOs
   they downloaded.
2. **Private key** — store the file in your release vault (HSM, 1Password
   secrets, encrypted git-crypt repo — whatever your org uses). The
   binary form ALSO contains the private key, so if you can't keep the
   key file, save the base64 string itself somewhere safe.

**The private key never goes in this repo. Never commit `*.key`.**

A `.gitignore` line for `*.key` is already in place; double-check before
your first release.

---

## Per-release: build + sign

The flow is: build a signed `quickfw-upgrade` binary, build the ISO that
ships with that binary, sign the ISO.

```bash
# 1. Set the env var so quickfw-upgrade bakes the matching public key.
export QUICKFW_UPDATE_PUBKEY="$(cat /secure/quickfw-release.pub)"
#    (or paste the base64 directly)

# 2. Build everything in release mode. quickfw-upgrade picks up the env
#    var via option_env! at compile time.
cargo build --release --workspace

# 3. Build the ISO. The build script copies target/release/quickfw-upgrade
#    into the ISO's rootfs.
bash build.sh
#    → output/quickfw-<version>.iso

# 4. Sign the ISO. The signer reads the private key from --key or from
#    the QUICKFW_SIGN_PRIVKEY env var. Either way, this happens on the
#    release host (CI runner with secret access, or your laptop).
cargo run --release -p quickfw-iso-sign -- sign output/quickfw-<version>.iso \
    --key /secure/quickfw-release.key
#    → output/quickfw-<version>.iso.sig
```

The `.sig` file is a single base64-encoded ed25519 signature over the
ISO's SHA-256. Tiny. Ship it next to the ISO on your release page.

---

## Verifying you didn't mismatch keys

Before you publish, sanity-check on a fresh shell:

```bash
target/release/quickfw-upgrade verify output/quickfw-<version>.iso
# → OK: signature verified
```

If you see `signature does NOT verify against trusted public key`, the
binary was built with a different `QUICKFW_UPDATE_PUBKEY` than the one
you used to sign. Either rebuild with the right env var or re-sign with
the right key.

If you see `this binary was built without QUICKFW_UPDATE_PUBKEY`, you
forgot to export the env var before `cargo build`. Re-export and rebuild.

---

## CI workflow (GitHub Actions)

Drop the file [.github/workflows/release.yml](../.github/workflows/release.yml)
into the repo. It does steps 2–4 automatically when you push a tag like
`v1.2.3`. Two repository secrets are required:

- `QUICKFW_UPDATE_PUBKEY` — public half (base64), safe to view
- `QUICKFW_SIGN_PRIVKEY` — private half (base64), guard like a token

The workflow:
1. Restores the cargo cache
2. Exports `QUICKFW_UPDATE_PUBKEY` and runs `cargo build --release`
3. Runs `bash build.sh`
4. Exports `QUICKFW_SIGN_PRIVKEY` and runs the signer
5. Uploads `quickfw-*.iso` + `quickfw-*.iso.sig` as the GitHub release
   artifacts

---

## Key rotation

Every appliance bakes the public key at install time, so rotating the
release key requires:

1. Generate a new keypair (`keygen` again).
2. Push a new release that contains a `quickfw-upgrade` built with the
   NEW public key, signed by the OLD private key. Operators apply this
   via the existing trust-chain — current binaries verify with the old
   key, the new binary then trusts only the new key.
3. After everyone's upgraded, you may discard the old private key.

This is mechanically the same as a normal release; the ISO just happens
to contain a binary with a new baked pubkey. There is no separate
"rotate" command.

---

## What if I lose the private key?

You can no longer sign new releases with that key. You can:

1. Generate a new keypair.
2. Push a one-off "transition" release that's signed with the OLD key
   (you have to keep the old key alive long enough for this — if you've
   truly lost it, you cannot do this and operators must reinstall).
3. The transition release contains a `quickfw-upgrade` built with the
   NEW pubkey. After applying it, operators trust only the new key.

If you've lost the old key with no backup, every existing appliance is
stuck on its current version until reinstalled from a fresh ISO. So:
**back up the private key**.
