// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Vm, VM_ADDRESS} from "./Vm.sol";
import {Registry} from "../src/Registry.sol";
import {GateZVerifier} from "../src/GateZVerifier.sol";

contract RegistryTest {
    Vm constant vm = Vm(VM_ADDRESS);

    Registry registry;
    GateZVerifier gateZ;

    bytes32 constant PHI = keccak256("phi-1");
    bytes32 constant DEDUP = keccak256("dedup-1");

    // Mirror of Registry.Registered for expectEmit.
    event Registered(bytes32 indexed phi, bytes32 indexed dedupTag);

    function setUp() public {
        gateZ = new GateZVerifier();
        registry = new Registry(gateZ);
    }

    function proofFor(bytes32 phi) internal view returns (bytes memory) {
        return abi.encodePacked(gateZ.expectedProof(phi));
    }

    function test_register_succeeds_with_valid_proof() public {
        bytes memory proof = proofFor(PHI);

        vm.expectEmit();
        emit Registered(PHI, DEDUP);
        registry.register(PHI, DEDUP, proof);

        require(registry.phiRegistered(PHI), "phi must be registered");
        require(registry.isSeen(DEDUP), "dedup tag must be seen");
        require(registry.identityCount() == 1, "identity count must be 1");
    }

    function test_duplicate_phi_reverts() public {
        registry.register(PHI, DEDUP, proofFor(PHI));

        // Same Φ again under a FRESH dedup tag → the novelty check fires
        // first. Precompute the proof so no staticcall sits between
        // expectRevert and the register call it targets.
        bytes32 otherDedup = keccak256("dedup-2");
        bytes memory proof = proofFor(PHI);
        vm.expectRevert(abi.encodeWithSelector(Registry.DuplicatePhi.selector, PHI));
        registry.register(PHI, otherDedup, proof);

        require(registry.identityCount() == 1, "no second mint");
    }

    function test_invalid_gatez_proof_reverts() public {
        // Wrong bytes (right length).
        bytes memory wrong = abi.encodePacked(keccak256("not-the-proof"));
        vm.expectRevert(abi.encodeWithSelector(Registry.InvalidGateZProof.selector));
        registry.register(PHI, DEDUP, wrong);

        // Wrong length.
        vm.expectRevert(abi.encodeWithSelector(Registry.InvalidGateZProof.selector));
        registry.register(PHI, DEDUP, hex"deadbeef");

        require(registry.identityCount() == 0, "nothing recorded on bad proof");
    }

    function test_reused_dedup_tag_reverts() public {
        registry.register(PHI, DEDUP, proofFor(PHI));

        // A DIFFERENT person's Φ reusing the same dedup tag → Sybil block,
        // a distinct path from Φ novelty.
        bytes32 otherPhi = keccak256("phi-2");
        bytes memory proof = proofFor(otherPhi);
        vm.expectRevert(abi.encodeWithSelector(Registry.AlreadyEnrolled.selector, DEDUP));
        registry.register(otherPhi, DEDUP, proof);

        require(!registry.phiRegistered(otherPhi), "second phi not recorded");
        require(registry.identityCount() == 1, "no second mint");
    }

    function test_independent_identities_register() public {
        registry.register(PHI, DEDUP, proofFor(PHI));
        bytes32 phi2 = keccak256("phi-2");
        bytes32 dedup2 = keccak256("dedup-2");
        registry.register(phi2, dedup2, proofFor(phi2));

        require(registry.identityCount() == 2, "two distinct identities");
    }

    /// Any (Φ, dedup) pair registers with its valid sim proof.
    function testFuzz_register_any_identity(bytes32 phi, bytes32 dedupTag) public {
        registry.register(phi, dedupTag, proofFor(phi));

        require(registry.phiRegistered(phi), "phi must be registered");
        require(registry.isSeen(dedupTag), "dedup tag must be seen");
    }

    /// Anything that is not THE expected proof for Φ is rejected.
    function testFuzz_wrong_proof_rejected(bytes32 phi, bytes calldata proof) public {
        bytes memory expected = proofFor(phi);
        if (keccak256(proof) == keccak256(expected)) return; // fuzzer found the needle

        vm.expectRevert(abi.encodeWithSelector(Registry.InvalidGateZProof.selector));
        registry.register(phi, DEDUP, proof);

        require(registry.identityCount() == 0, "nothing recorded on bad proof");
    }
}
