pragma circom 2.0.0;

/*
 * Gate Z — PLACEHOLDER (ARCHITECTURE.md §2 step 12, §5).
 *
 * Eventually: prove that C_commit was produced by reviewed code on approved
 * hardware (binding the attestation measurement into the proof) without
 * revealing enrollment inputs. For now this is a trivially satisfiable stub
 * so the toolchain (circom 2.x + snarkjs) is wired end to end.
 */
template GateZ() {
    // Public: the Φ commitment hash being registered.
    signal input phi;
    // Private: stand-in for the attestation measurement witness.
    signal input measurement;

    signal output ok;

    // Dummy quadratic constraint to keep the R1CS non-empty.
    ok <== phi * measurement;
}

component main {public [phi]} = GateZ();
