// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title GateZVerifier — ARCHITECTURE.md §2 step 12, §6
/// @notice Verifies the Gate Z ZK proof that a Φ commitment was produced by
///         reviewed code on approved hardware. Per §6 it has a SIM mode that
///         checks the deterministic mock attestation instead of a real proof.
contract GateZVerifier {
    bool public immutable simMode;

    constructor(bool _simMode) {
        simMode = _simMode;
    }

    /// @notice Stub. SIM mode: accept the mock attestation tag emitted by the
    ///         attestation crate's simulator. Real mode: not implemented until
    ///         circuits/gatez.circom is more than a placeholder.
    /// TODO: real Groth16 verification of the Gate Z circuit.
    function verify(bytes32 phi, bytes calldata proof) external view returns (bool) {
        if (simMode) {
            // Mock attestation: proof must be the sim tag for this phi.
            if (proof.length != 32) return false;
            // casting to 'bytes32' is safe: length is exactly 32 (checked above)
            // forge-lint: disable-next-line(unsafe-typecast)
            return bytes32(proof) == keccak256(abi.encodePacked("pramaana-sim-attestation", phi));
        }
        return false;
    }
}
