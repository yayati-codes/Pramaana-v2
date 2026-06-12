// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// Minimal Foundry cheatcode surface. We deliberately avoid a forge-std
/// dependency so `forge build` / `make build` need no git submodules (see
/// docs/DECISIONS.md); this declares only what the tests use.
interface Vm {
    /// Expect the next call to revert with exactly this revert data
    /// (selector + ABI-encoded args).
    function expectRevert(bytes calldata revertData) external;
}

// The canonical Foundry cheatcode address.
address constant VM_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
