pragma circom 2.1.0;

/*
 * UTXO Transition Circuit - Proves valid state transition
 * 
 * This circuit proves that:
 * 1. Input UTXOs exist in the state (Merkle inclusion)
 * 2. Nullifiers are correctly computed (prevent double-spend)
 * 3. Output commitments are correctly formed
 * 4. Balance is conserved (inputs = outputs + fee)
 * 
 * Public Inputs:
 * - old_state_root: Merkle root before transition
 * - new_state_root: Merkle root after transition
 * - nullifiers[N]: Nullifiers for spent inputs
 * - output_commitments[M]: Commitments for new outputs
 * - fee: Transaction fee
 * 
 * Private Inputs:
 * - input_values[N]: Values of input UTXOs
 * - input_salts[N]: Salts used in input commitments
 * - input_paths[N]: Merkle paths for inputs
 * - input_indices[N]: Merkle indices for inputs
 * - nullifier_keys[N]: Keys for nullifier computation
 * - output_values[M]: Values of output UTXOs
 * - output_salts[M]: Salts for output commitments
 * - output_pk_hashes[M]: Recipient public key hashes
 */

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Domain separators
// Template for N inputs and M outputs
template UTXOTransition(N, M, TREE_DEPTH) {
    // Domain separators
    var DOMAIN_NULLIFIER = 3;
    var DOMAIN_UTXO_COMMITMENT = 4;
    
    // =========================================================================
    // Public Inputs
    // =========================================================================
    signal input old_state_root;
    signal input new_state_root;
    signal input nullifiers[N];
    signal input output_commitments[M];
    signal input fee;
    
    // =========================================================================
    // Private Inputs - Inputs
    // =========================================================================
    signal input input_values[N];
    signal input input_salts[N];
    signal input input_pk_hashes[N];
    signal input input_paths[N][TREE_DEPTH];
    signal input input_indices[N];
    signal input nullifier_keys[N];
    
    // =========================================================================
    // Private Inputs - Outputs
    // =========================================================================
    signal input output_values[M];
    signal input output_salts[M];
    signal input output_pk_hashes[M];
    
    // =========================================================================
    // Components
    // =========================================================================
    
    // Input commitment computation
    component input_commitment[N];
    
    // Nullifier computation
    component nullifier_hash[N];
    
    // Merkle verification for inputs
    component merkle_verify[N];
    
    // Output commitment computation
    component output_commitment[M];
    
    // =========================================================================
    // Step 1: Verify input UTXOs and compute nullifiers
    // =========================================================================
    
    for (var i = 0; i < N; i++) {
        // Compute input commitment: Poseidon(domain, value, pk_hash, salt)
        input_commitment[i] = Poseidon(4);
        input_commitment[i].inputs[0] <== DOMAIN_UTXO_COMMITMENT;
        input_commitment[i].inputs[1] <== input_values[i];
        input_commitment[i].inputs[2] <== input_pk_hashes[i];
        input_commitment[i].inputs[3] <== input_salts[i];
        
        // Verify Merkle inclusion in old state
        merkle_verify[i] = MerkleProofVerifyUTXO(TREE_DEPTH);
        merkle_verify[i].leaf <== input_commitment[i].out;
        merkle_verify[i].root <== old_state_root;
        merkle_verify[i].index <== input_indices[i];
        for (var j = 0; j < TREE_DEPTH; j++) {
            merkle_verify[i].proof[j] <== input_paths[i][j];
        }
        merkle_verify[i].valid === 1;
        
        // Compute nullifier: Poseidon(domain, nk, index)
        nullifier_hash[i] = Poseidon(3);
        nullifier_hash[i].inputs[0] <== DOMAIN_NULLIFIER;
        nullifier_hash[i].inputs[1] <== nullifier_keys[i];
        nullifier_hash[i].inputs[2] <== input_indices[i];
        
        // Constraint: computed nullifier must match public input
        nullifier_hash[i].out === nullifiers[i];
    }
    
    // =========================================================================
    // Step 2: Verify output commitments
    // =========================================================================
    
    for (var i = 0; i < M; i++) {
        // Compute output commitment
        output_commitment[i] = Poseidon(4);
        output_commitment[i].inputs[0] <== DOMAIN_UTXO_COMMITMENT;
        output_commitment[i].inputs[1] <== output_values[i];
        output_commitment[i].inputs[2] <== output_pk_hashes[i];
        output_commitment[i].inputs[3] <== output_salts[i];
        
        // Constraint: computed commitment must match public input
        output_commitment[i].out === output_commitments[i];
    }
    
    // =========================================================================
    // Step 3: Verify balance conservation
    // =========================================================================
    
    // Sum inputs
    signal input_sum[N + 1];
    input_sum[0] <== 0;
    for (var i = 0; i < N; i++) {
        input_sum[i + 1] <== input_sum[i] + input_values[i];
    }
    
    // Sum outputs
    signal output_sum[M + 1];
    output_sum[0] <== 0;
    for (var i = 0; i < M; i++) {
        output_sum[i + 1] <== output_sum[i] + output_values[i];
    }
    
    // Constraint: inputs = outputs + fee
    input_sum[N] === output_sum[M] + fee;
    
    // =========================================================================
    // Step 4: Verify new state root (simplified)
    // =========================================================================
    
    // Note: Full new_state_root verification would require:
    // 1. Removing nullified UTXOs from tree
    // 2. Inserting new output commitments
    // 3. Recomputing root
    //
    // This is complex and typically handled by the prover providing
    // the new tree state as witness. For this prototype, we trust
    // the new_state_root is correctly computed by the execution layer.
    //
    // A production circuit would include incremental Merkle tree updates.
    
    // Placeholder: ensure new_state_root is different from old (state changed)
    component stateChanged = IsEqual();
    stateChanged.in[0] <== old_state_root;
    stateChanged.in[1] <== new_state_root;
    // Allow same root only if no real transition (edge case)
    // stateChanged.out === 0; // Commented: might be same if empty tx
}

// =========================================================================
// Merkle Proof Verification Template
// =========================================================================

template MerkleProofVerifyUTXO(LEVELS) {
    signal input leaf;
    signal input root;
    signal input index;
    signal input proof[LEVELS];
    
    signal output valid;
    
    // Convert index to bits
    component indexBits = Num2Bits(LEVELS);
    indexBits.in <== index;
    
    // Hash up the tree
    component hashers[LEVELS];
    signal levelHashes[LEVELS + 1];
    levelHashes[0] <== leaf;
    
    // Signals for path reconstruction
    signal left[LEVELS];
    signal right[LEVELS];

    for (var i = 0; i < LEVELS; i++) {
        hashers[i] = Poseidon(2);
        
        left[i] <== indexBits.out[i] * (proof[i] - levelHashes[i]) + levelHashes[i];
        right[i] <== indexBits.out[i] * (levelHashes[i] - proof[i]) + proof[i];
        
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        
        levelHashes[i + 1] <== hashers[i].out;
    }
    
    // Check if computed root matches
    component eq = IsEqual();
    eq.in[0] <== levelHashes[LEVELS];
    eq.in[1] <== root;
    valid <== eq.out;
}

// =========================================================================
// Main Component Instantiation
// =========================================================================

// Default: 2 inputs, 2 outputs, tree depth 16
component main {public [old_state_root, new_state_root, nullifiers, output_commitments, fee]} = UTXOTransition(2, 2, 16);
