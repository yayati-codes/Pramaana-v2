// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IGateZVerifier} from "./IGateZVerifier.sol";

/// @title GateZVerifier (SIM) — ARCHITECTURE.md §2 step 12, §6
/// @notice SIM-mode Gate Z verifier: accepts a deterministic mock attestation
///         instead of a real proof, so the registry flow runs end-to-end on
///         any chain. Production deploys a different `IGateZVerifier`
///         implementation (a DCAP-in-ZK / Groth16 verifier) in its place.
///
/// @dev The on-chain sim proof is `keccak256("pramaana-sim-attestation", phi)`.
///      This is a separate, self-contained EVM mock; the Rust enrollment-tee
///      uses a different sim Gate Z format (an attestation-crate quote). Both
///      are sim stand-ins for their layer — see docs/DECISIONS.md.
contract GateZVerifier is IGateZVerifier {
    /// @notice The sim proof bytes a caller must present for `phi`.
    function expectedProof(bytes32 phi) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("pramaana-sim-attestation", phi));
    }

    /// @inheritdoc IGateZVerifier
    function verify(bytes32 phi, bytes calldata proof) external pure returns (bool) {
        if (proof.length != 32) return false;
        // casting to 'bytes32' is safe: length is exactly 32 (checked above)
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes32(proof) == expectedProof(phi);
    }
}
