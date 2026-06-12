// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IGateZVerifier — ARCHITECTURE.md §2 step 12
/// @notice The Gate Z verification seam. The Registry depends only on this
///         interface, so the SIM verifier ([`GateZVerifier`]) can be swapped
///         for a real DCAP-in-ZK / Groth16 verifier at deployment without
///         touching the Registry.
interface IGateZVerifier {
    /// @return true iff `proof` attests that the C_commit behind `phi` was
    ///         produced by reviewed code on approved hardware.
    function verify(bytes32 phi, bytes calldata proof) external view returns (bool);
}
