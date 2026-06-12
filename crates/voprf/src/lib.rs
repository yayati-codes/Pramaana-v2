//! VOPRF client side (ARCHITECTURE.md §5): blind/unblind + DLEQ verification
//! over ristretto255.
//!
//! Load-bearing for privacy: the issuer (UIDAI) knows the full QR contents, so
//! the issuer-unknown key k held by the vault is the ONLY thing preventing
//! issuer de-anonymization. The DLEQ proof stops the vault from using a
//! per-user key (a linking attack). See THREAT_MODEL.md (b).
