//! VOPRF Vault O (ARCHITECTURE.md §5): holds the sealed key k in its own TDX
//! CVM and serves attested evaluations (Gate b/k, server side).
//!
//! Gate b: verify T's quote, bound to the blinded input, before evaluating
//! (blocks replay-based grinding). Evaluations return a DLEQ proof. k never
//! leaves the CVM; its secrecy carries issuer-unlinkability (THREAT_MODEL.md b).
