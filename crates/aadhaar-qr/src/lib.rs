//! Aadhaar Secure QR handling (ARCHITECTURE.md §5).
//!
//! Parse the Secure QR, verify the UIDAI RSA-2048/SHA-256 signature, extract
//! demographic fields + the JPEG2000 photo, and compute the STABLE
//! timestamp-stripped digest (§2 step 6, §4): the 17 timestamp bytes in the
//! reference region are zeroed before hashing so re-scans are deterministic.
//!
//! Enrollment is signature-verified, never OCR.
