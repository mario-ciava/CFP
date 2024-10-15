pragma circom 2.1.0;

/*
 * Simple State Transition Circuit for CFP Prototype
 *
 * This is a minimal demonstration circuit that proves:
 * "I know values that hash to the declared batch_hash"
 *
 * In a real implementation, this would verify:
 * - Merkle proofs of UTXO existence
 * - Nullifier validity
 * - Balance conservation
 * - Signature validity
 *
 * For the prototype, we keep it simple to demonstrate
 * the ZK integration pipeline.
 */

include "circomlib/circuits/poseidon.circom";

template SimpleTransition() {
    // Public inputs (visible to verifier)
    signal input old_state_root;
    signal input new_state_root;
    signal input batch_hash;
    
    // Private inputs (known only to prover)
    signal input secret_preimage;
    
    // Constraint: prove we know a value that hashes correctly
    // Using Poseidon hash for efficiency in ZK circuits
    component hasher = Poseidon(3);
    hasher.inputs[0] <== old_state_root;
    hasher.inputs[1] <== new_state_root;
    hasher.inputs[2] <== secret_preimage;
    
    // The hash of (old_root, new_root, preimage) should equal batch_hash
    batch_hash === hasher.out;
}

component main {public [old_state_root, new_state_root, batch_hash]} = SimpleTransition();
