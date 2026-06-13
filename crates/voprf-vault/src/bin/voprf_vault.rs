//! Standalone VOPRF Vault O (feature `http-server`): holds the OPRF key k in
//! its OWN process and serves attested Gate b evaluations. This is the
//! key-custody split made real — the enrollment-tee talks to it over HTTP
//! (VAULT_URL) and never sees k.
//!
//! SIM mode: the sealing seed comes from VAULT_SEED (or a fixed demo
//! default). The REAL path obtains the seed from TDX sealed storage / the
//! dstack KMS `get_key` so k only ever exists inside the CVM — that is the
//! ONE component permitted a durable TEE-held secret (CLAUDE.md / dstack
//! key-custody rule). k is never logged: `Debug` prints the public key only.

use std::sync::Arc;

use attestation::sim::SimVerifier;
use voprf_vault::http::VaultServer;
use voprf_vault::VoprfVault;

fn main() {
    let seed = std::env::var("VAULT_SEED").unwrap_or_else(|_| "sim-sealed-seed-demo".into());
    let vault = Arc::new(
        VoprfVault::from_seed(seed.as_bytes(), b"pramaana-vault-v1", SimVerifier::default())
            .expect("vault key derivation"),
    );
    // Public key only — k stays inside `vault`.
    let pk_hex: String = vault.public_key().iter().map(|b| format!("{b:02x}")).collect();

    let addr = std::env::var("VAULT_ADDR").unwrap_or_else(|_| "127.0.0.1:9944".into());
    let (local, server_thread) = VaultServer::spawn(vault, &addr).expect("spawn vault server");
    println!("voprf-vault listening on http://{local} (SIM mode) — committed pk = {pk_hex}");
    server_thread.join().expect("server thread");
}
