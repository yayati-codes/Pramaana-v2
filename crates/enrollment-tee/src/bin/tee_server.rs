//! SIM-ONLY standalone enrollment backend for the SDK/demo (feature
//! `sim-fixture`): one process = Gate 0/b/k/Z-complete T plus an in-process
//! sim vault O (unless VAULT_URL points at an external one) and a demo
//! UIDAI keypair signing the /fixture QR.
//!
//! Env: TEE_ADDR (default 127.0.0.1:9966), VAULT_URL (optional),
//! SIMULATION (must be unset/"1"/"true" — §6).

use std::sync::Arc;

use aadhaar_qr::testgen::{self, TestQrSpec};
use attestation::sim::SimVerifier;
use enrollment_tee::http::{FixtureState, TeeServer, TeeService};
use enrollment_tee::registry::InMemoryRegistry;
use enrollment_tee::{AttestationMode, EnrollmentTee, HttpVaultClient};
use liveness::SimMatcher;
use voprf_vault::http::VaultServer;
use voprf_vault::VoprfVault;

fn main() {
    let mode = AttestationMode::from_env().expect("tee-server is sim-only (unset SIMULATION)");

    let vault_url = std::env::var("VAULT_URL").unwrap_or_else(|_| {
        let vault = Arc::new(
            VoprfVault::from_seed(
                b"sim-sealed-seed-demo",
                b"pramaana-vault-v1",
                SimVerifier::default(),
            )
            .expect("vault key derivation"),
        );
        let (addr, _vault_thread) =
            VaultServer::spawn(vault, "127.0.0.1:0").expect("spawn sim vault");
        eprintln!("tee-server: in-process sim vault on http://{addr}");
        format!("http://{addr}")
    });

    // Demo credential issuer: a fresh keypair stands in for UIDAI. T
    // verifies against the pubkey; /fixture signs with the private half.
    let (signing_key, uidai_pubkey) = testgen::generate_keypair();

    let tee = EnrollmentTee::new(
        mode,
        uidai_pubkey,
        HttpVaultClient::connect(&vault_url).expect("connect to vault"),
        InMemoryRegistry::default(),
        SimMatcher::default(),
    );
    let service = Arc::new(TeeService::with_fixture(
        tee,
        FixtureState {
            spec: TestQrSpec::default(),
            signing_key,
        },
    ));

    let addr = std::env::var("TEE_ADDR").unwrap_or_else(|_| "127.0.0.1:9966".into());
    let (local, server_thread) = TeeServer::spawn(service, &addr).expect("spawn tee server");
    println!("tee-server listening on http://{local} (SIM mode, /fixture enabled)");
    server_thread.join().expect("server thread");
}
