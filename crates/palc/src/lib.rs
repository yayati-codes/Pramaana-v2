//! PALC — Post-quantum Anonymous Lattice Commitment (ARCHITECTURE.md §2 step 10, §5).
//!
//! seed = HKDF-SHA3-512(salt=0^512, IKM = oprf_output ‖ H(stable_id),
//!                      info="pramaana-v1", L=64)
//! (pk_IdR, sk_IdR) = Kyber1024.KeyGen(seed)   // deterministic
//! C_commit = pk_IdR ‖ Kyber1024.Enc(pk_IdR, H(seed))
//! Φ = H(C_commit)
//!
//! Every hash is domain-separated; all PII-derived intermediates are zeroized
//! once Φ and sk_IdR exist (§4). sk_IdR is recomputable, never stored.
