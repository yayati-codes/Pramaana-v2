// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {GateZVerifier} from "../src/GateZVerifier.sol";

contract GateZVerifierTest {
    GateZVerifier gateZ;

    bytes32 constant PHI = keccak256("phi");

    function setUp() public {
        gateZ = new GateZVerifier();
    }

    function test_accepts_expected_proof() public view {
        bytes memory proof = abi.encodePacked(gateZ.expectedProof(PHI));
        require(gateZ.verify(PHI, proof), "expected proof must verify");
    }

    function test_rejects_tampered_proof() public view {
        bytes32 tag = gateZ.expectedProof(PHI);
        bytes memory tampered = abi.encodePacked(tag ^ bytes32(uint256(1)));
        require(!gateZ.verify(PHI, tampered), "tampered proof must fail");
    }

    function test_rejects_wrong_length() public view {
        require(!gateZ.verify(PHI, hex""), "empty proof must fail");
        require(!gateZ.verify(PHI, hex"deadbeef"), "short proof must fail");
    }

    function test_rejects_proof_for_other_phi() public view {
        // A proof valid for a different Φ must not verify here.
        bytes memory otherProof = abi.encodePacked(gateZ.expectedProof(keccak256("other")));
        require(!gateZ.verify(PHI, otherProof), "cross-phi proof must fail");
    }
}
