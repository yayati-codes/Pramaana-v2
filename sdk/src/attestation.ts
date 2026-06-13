/**
 * Client-side (C) verification of T's SIM attestation quotes — the TS mirror
 * of crates/attestation (§2 step 1, §6). Gate 0 rule: if the quote fails the
 * appraisal policy or the report_data binding, C sends NOTHING.
 *
 * Cross-language consistency with the Rust implementation is pinned by a
 * test vector generated from the Rust crate (see test/attestation.test.ts)
 * and exercised live by the e2e suite against a running tee-server.
 */

import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";

const MAGIC = new TextEncoder().encode("PRAMSIM1");
const BIND_DOMAIN = new TextEncoder().encode("pramaana-report-data-v1");

export const MEASUREMENT_LEN = 48;
export const REPORT_DATA_LEN = 64;
const QUOTE_LEN = MAGIC.length + MEASUREMENT_LEN + REPORT_DATA_LEN;

/** The sim "hardware" measurement (stand-in for the reviewed enclave MRTD). */
export const SIM_MEASUREMENT: Uint8Array = new Uint8Array(MEASUREMENT_LEN).fill(0x5a);

export class AttestationError extends Error {
  constructor(message: string) {
    super(`attestation rejected: ${message}`);
    this.name = "AttestationError";
  }
}

export interface VerifiedQuote {
  measurement: Uint8Array;
  /** The report_data field as stored in the quote (sha256-wrapped form). */
  storedReportData: Uint8Array;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u64le(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}

/** report_data = SHA-512(domain ‖ u64_le(|nonce|) ‖ nonce ‖ value). */
export function bindReportData(nonce: Uint8Array, value: Uint8Array): Uint8Array {
  return sha512(concat(BIND_DOMAIN, u64le(nonce.length), nonce, value));
}

/** The quote FIELD stores sha256(report_data) ‖ 0^32, never the raw bytes. */
export function quotedReportData(reportData: Uint8Array): Uint8Array {
  const stored = new Uint8Array(REPORT_DATA_LEN);
  stored.set(sha256(reportData), 0);
  return stored;
}

/** Appraisal: structure + measurement allowlist ("reviewed code"). */
export function verifySimQuote(
  quote: Uint8Array,
  allowedMeasurements: Uint8Array[] = [SIM_MEASUREMENT],
): VerifiedQuote {
  if (quote.length !== QUOTE_LEN) {
    throw new AttestationError(`sim quote must be ${QUOTE_LEN} bytes`);
  }
  if (!equalBytes(quote.subarray(0, MAGIC.length), MAGIC)) {
    throw new AttestationError("bad sim magic");
  }
  const measurement = quote.subarray(MAGIC.length, MAGIC.length + MEASUREMENT_LEN);
  if (!allowedMeasurements.some((m) => equalBytes(m, measurement))) {
    throw new AttestationError("measurement is not in the appraisal allowlist");
  }
  return {
    measurement: Uint8Array.from(measurement),
    storedReportData: Uint8Array.from(quote.subarray(MAGIC.length + MEASUREMENT_LEN)),
  };
}

/** The shared gate check: does the quote bind the expected (nonce, value)? */
export function verifyReportDataBinding(
  verified: VerifiedQuote,
  nonce: Uint8Array,
  value: Uint8Array,
): void {
  const expected = quotedReportData(bindReportData(nonce, value));
  if (!equalBytes(verified.storedReportData, expected)) {
    throw new AttestationError("report_data does not bind the expected (nonce, value)");
  }
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  // Quotes are public data; constant time is not load-bearing here.
  return a.length === b.length && a.every((v, i) => v === b[i]);
}
