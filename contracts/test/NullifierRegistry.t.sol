// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Vm, VM_ADDRESS} from "./Vm.sol";
import {NullifierRegistry} from "../src/NullifierRegistry.sol";

contract NullifierRegistryTest {
    Vm constant vm = Vm(VM_ADDRESS);

    NullifierRegistry nullifiers;

    uint256 constant SERVICE_A = 1;
    uint256 constant SERVICE_B = 2;
    bytes32 constant NULLIFIER = keccak256("nullifier");

    // Mirror of NullifierRegistry.NullifierSpent for expectEmit.
    event NullifierSpent(uint256 indexed serviceId, bytes32 indexed nullifier);

    function setUp() public {
        nullifiers = new NullifierRegistry();
    }

    function test_first_spend_succeeds() public {
        vm.expectEmit();
        emit NullifierSpent(SERVICE_A, NULLIFIER);
        nullifiers.spend(SERVICE_A, NULLIFIER);

        require(nullifiers.spent(SERVICE_A, NULLIFIER), "nullifier must be spent");
    }

    function test_double_spend_reverts() public {
        nullifiers.spend(SERVICE_A, NULLIFIER);
        vm.expectRevert(
            abi.encodeWithSelector(
                NullifierRegistry.NullifierAlreadySpent.selector, SERVICE_A, NULLIFIER
            )
        );
        nullifiers.spend(SERVICE_A, NULLIFIER);
    }

    function test_services_are_independent() public {
        nullifiers.spend(SERVICE_A, NULLIFIER);
        // The SAME nullifier under a different service is a different identity
        // slot (cross-service unlinkability §3) → must succeed.
        nullifiers.spend(SERVICE_B, NULLIFIER);

        require(nullifiers.spent(SERVICE_A, NULLIFIER), "service A spent");
        require(nullifiers.spent(SERVICE_B, NULLIFIER), "service B spent");
    }
}
