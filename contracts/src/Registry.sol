// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {GateZVerifier} from "./GateZVerifier.sol";

/// @title Registry (R) — ARCHITECTURE.md §1/§2 steps 11–12
/// @notice Records Φ commitments and enforces per-person novelty via dedup
///         tags. Registration is gated on a Gate Z proof: C_commit must come
///         from reviewed code on approved hardware.
contract Registry {
    GateZVerifier public immutable gateZ;

    /// dedup tag → already enrolled (Sybil block: never mint a second identity)
    mapping(bytes32 => bool) public dedupSeen;
    /// Φ (= H(C_commit)) → registered
    mapping(bytes32 => bool) public phiRegistered;

    event Registered(bytes32 indexed phi, bytes32 indexed dedupTag);

    error AlreadyEnrolled(bytes32 dedupTag);
    error InvalidGateZProof();

    constructor(GateZVerifier _gateZ) {
        gateZ = _gateZ;
    }

    /// @notice §2 step 11 — T queries novelty before continuing enrollment.
    function isSeen(bytes32 dedupTag) external view returns (bool) {
        return dedupSeen[dedupTag];
    }

    /// @notice §2 step 12 — verify Gate Z, then record the Φ commitment.
    /// TODO: replace with the real Groth16 verifier call once circuits/ lands.
    function register(bytes32 phi, bytes32 dedupTag, bytes calldata gateZProof) external {
        if (dedupSeen[dedupTag]) revert AlreadyEnrolled(dedupTag);
        if (!gateZ.verify(phi, gateZProof)) revert InvalidGateZProof();
        dedupSeen[dedupTag] = true;
        phiRegistered[phi] = true;
        emit Registered(phi, dedupTag);
    }
}
