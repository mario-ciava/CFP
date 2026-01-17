pragma circom 2.0.0;

// Minimal bridge circuit: proves knowledge of two private field elements (a, b)
// whose circomlib Poseidon hash equals the public output `out`.
//
// Its purpose in CFP is to pin the Python Poseidon implementation
// (cfp/crypto/poseidon.py) to the in-circuit Poseidon: a Groth16 proof over this
// circuit verifies only if `out` matches what Python computed for the same
// (a, b). See tests/integration/test_zk_proof.py.

include "circomlib/circuits/poseidon.circom";

template PoseidonCheck() {
    signal input a;      // private
    signal input b;      // private
    signal output out;   // public

    component h = Poseidon(2);
    h.inputs[0] <== a;
    h.inputs[1] <== b;
    out <== h.out;
}

component main = PoseidonCheck();
