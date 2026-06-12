# Decisions

Architecture/implementation decision log. One entry per decision:
`## YYYY-MM-DD — Title`, then Context / Decision / Consequences.

## 2026-06-12 — aadhaar-qr: stable digest scope, decompression, field layout

**Context.** The Secure QR's trailing 256-byte RSA signature covers the issuance
timestamp, and UIDAI re-issues QRs with fresh timestamps for the same person.

**Decision.**
1. `stable_digest` = SHA-256 over the *signed message* (decompressed payload
   MINUS the trailing 256 signature bytes) with the 17 timestamp bytes of the
   referenceId zeroed. Including the signature would make digests differ across
   re-issues, since the signature covers the timestamp.
2. Decompression is tolerant: zlib → gzip → raw DEFLATE. Real UIDAI QRs are
   gzip-wrapped; the spec is commonly described as zlib; the test generator
   emits zlib.
3. Field layout constant: 16 text fields each terminated by 0xFF (version,
   referenceId = last-4 + 17-digit timestamp, name, DOB, gender, 11 address
   fields), then the JPEG2000 photo, then the signature. 0xFF cannot occur in
   UTF-8 text, so only the photo region may contain it; splitting stops after
   the 16th delimiter.

**Consequences.** Re-scan and re-issue determinism holds (§4); signature
verification runs before any field is interpreted; a real-QR fixture should be
added later to pin the layout against UIDAI ground truth.
