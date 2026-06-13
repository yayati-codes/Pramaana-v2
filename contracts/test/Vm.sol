// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// Minimal cheatcode surface so the test suite needs no forge-std and the
// build stays git-submodule-free (bootstrap decision, docs/DECISIONS.md).
address constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));

interface Vm {
    /// Expect the next external call to revert with EXACTLY `revertData`
    /// (build it with abi.encodeWithSelector for errors that carry args).
    /// Precompute any helper values first: a staticcall between expectRevert
    /// and the target call would consume the expectation.
    function expectRevert(bytes calldata revertData) external;

    /// Expect the next event emitted in this test to match the next call's
    /// event exactly (all topics and data).
    function expectEmit() external;
}
