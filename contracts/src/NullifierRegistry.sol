// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title NullifierRegistry — ARCHITECTURE.md §3
/// @notice Records per-service nullifiers (nullifier_s = H(secret, serviceId)).
///         Reuse within a service is detectable (same nullifier) → one
///         identity per service; cross-service values are unlinkable.
contract NullifierRegistry {
    /// serviceId → nullifier → spent
    mapping(uint256 => mapping(bytes32 => bool)) public spent;

    event NullifierSpent(uint256 indexed serviceId, bytes32 indexed nullifier);

    error NullifierAlreadySpent(uint256 serviceId, bytes32 nullifier);

    /// @notice Stub. TODO: require a valid Semaphore membership proof against
    ///         the Registry group before recording.
    function spend(uint256 serviceId, bytes32 nullifier) external {
        if (spent[serviceId][nullifier]) revert NullifierAlreadySpent(serviceId, nullifier);
        spent[serviceId][nullifier] = true;
        emit NullifierSpent(serviceId, nullifier);
    }
}
