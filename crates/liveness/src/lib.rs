//! Liveness + face match (ARCHITECTURE.md §5).
//!
//! Decode the JP2 photo from the Secure QR, accept a live face capture, and
//! match the two INSIDE the enclave (§2 step 5). The photo is for liveness
//! only — it must never feed key derivation (§4).
