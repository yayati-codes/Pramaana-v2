// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IGateZVerifier} from "./IGateZVerifier.sol";

/// @title Registry (R) — ARCHITECTURE.md §1/§2 steps 11–12
/// @notice Records Φ commitments and enforces uniqueness on two axes:
///         Φ novelty (no commitment registered twice) and the per-person
///         dedup tag (Sybil block: one person → one identity). Registration
///         is gated on a Gate Z proof that C_commit came from reviewed code
///         on approved hardware.
contract Registry {
    IGateZVerifier public immutable gateZ;

    /// dedup tag → already enrolled (Sybil block: never mint a second identity)
    mapping(bytes32 => bool) public dedupSeen;
    /// Φ (= H(C_commit)) → registered
    mapping(bytes32 => bool) public phiRegistered;
    /// Number of registered identities.
    uint256 public identityCount;

    event Registered(bytes32 indexed phi, bytes32 indexed dedupTag);

    error DuplicatePhi(bytes32 phi);
    error AlreadyEnrolled(bytes32 dedupTag);
    error InvalidGateZProof();

    constructor(IGateZVerifier _gateZ) {
        gateZ = _gateZ;
    }

    /// @notice §2 step 11 — T queries novelty before continuing enrollment.
    function isSeen(bytes32 dedupTag) external view returns (bool) {
        return dedupSeen[dedupTag];
    }

    /// @notice §2 step 12 — verify Gate Z, then record the Φ commitment.
    /// @dev Checks run cheapest-first: Φ novelty, then dedup, then the proof.
    function register(bytes32 phi, bytes32 dedupTag, bytes calldata gateZProof) external {
        if (phiRegistered[phi]) revert DuplicatePhi(phi);
        if (dedupSeen[dedupTag]) revert AlreadyEnrolled(dedupTag);
        if (!gateZ.verify(phi, gateZProof)) revert InvalidGateZProof();

        dedupSeen[dedupTag] = true;
        phiRegistered[phi] = true;
        identityCount += 1;
        emit Registered(phi, dedupTag);
    }
}
