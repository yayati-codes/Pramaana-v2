//! TDX attestation (ARCHITECTURE.md §5, §6): quote generation via
//! configfs-tsm, verification via dcap-rs, plus a simulation mode.
//!
//! SIM mode (deterministic mock quotes) is the default; the real path is
//! behind the cargo feature "tdx". Attestation gates ACTIONS (Gates 0/b/k/Z),
//! not computation on public data — see THREAT_MODEL.md (c)/(d).
