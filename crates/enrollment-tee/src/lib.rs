//! Enrollment TEE T (ARCHITECTURE.md §5): orchestrates §2 steps 1, 4–13.
//!
//! Gate 0 (RA-TLS quote to C) → receive QR + liveness artifacts → verify
//! UIDAI signature + face match in-enclave → stable id → blind → Gate b →
//! VOPRF eval → Gate k + unblind → PALC → dedup query → Gate Z → register Φ
//! commitment → ERASE all PII (QR bytes, live face, intermediates).
