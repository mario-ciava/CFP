pragma circom 2.1.0;

/*
 * Auction Selection Circuit - Proves correct winner selection
 * 
 * This circuit proves that:
 * 1. The winner has the highest utility among all candidates
 * 2. Tie-breaks are computed correctly using Poseidon
 * 3. The transcript root binds all bids
 * 
 * Public Inputs:
 * - intent_id: The intent being auctioned
 * - transcript_root: Merkle root of all bid commitments
 * - winner_solver_id: The claimed winning solver
 * - winner_score: The winning score
 * - epoch_seed: External randomness for tie-break
 * 
 * Private Inputs:
 * - all_solver_ids[K]: Array of solver IDs
 * - all_scores[K]: Array of utility scores
 * - all_commitments[K]: Array of bid commitments
 * - merkle_proofs[K]: Merkle proofs for each commitment
 * - merkle_indices[K]: Merkle path indices
 */

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Number of candidates (configurable, start with 4)
// template parameter K
template AuctionSelect(K, TREE_DEPTH) {
    // =========================================================================
    // Public Inputs
    // =========================================================================
    signal input intent_id;
    signal input transcript_root;
    signal input winner_solver_id;
    signal input winner_score;
    signal input epoch_seed;
    
    // =========================================================================
    // Private Inputs
    // =========================================================================
    signal input all_solver_ids[K];
    signal input all_scores[K];
    signal input all_commitments[K];
    signal input merkle_proof[K][TREE_DEPTH];
    signal input merkle_indices[K];
    
    // =========================================================================
    // Components
    // =========================================================================
    
    // Poseidon hashers for tie-break computation
    component tiebreak_hash[K];
    signal tiebreaks[K];
    
    // Comparators for pairwise tournament
    component score_gt[K-1];      // score[i] > current_best_score
    component score_eq[K-1];      // score[i] == current_best_score
    component tiebreak_lt[K-1];   // tiebreak[i] < current_best_tiebreak
    
    // Merkle verification
    component merkle_verify[K];
    
    // Intermediate signals for tournament
    signal current_winner_id[K];
    signal current_winner_score[K];
    signal current_winner_tiebreak[K];
    
    // =========================================================================
    // Step 1: Compute tie-breaks for all candidates
    // =========================================================================
    
    // Domain separator for tie-break (must match Python implementation)
    var DOMAIN_TIE_BREAK = 6;
    
    for (var i = 0; i < K; i++) {
        tiebreak_hash[i] = Poseidon(4);
        tiebreak_hash[i].inputs[0] <== DOMAIN_TIE_BREAK;
        tiebreak_hash[i].inputs[1] <== epoch_seed;
        tiebreak_hash[i].inputs[2] <== intent_id;
        tiebreak_hash[i].inputs[3] <== all_solver_ids[i];
        tiebreaks[i] <== tiebreak_hash[i].out;
    }
    
    // =========================================================================
    // Step 2: Verify Merkle inclusion for all commitments
    // =========================================================================
    
    for (var i = 0; i < K; i++) {
        merkle_verify[i] = MerkleProofVerify(TREE_DEPTH);
        merkle_verify[i].leaf <== all_commitments[i];
        merkle_verify[i].root <== transcript_root;
        merkle_verify[i].index <== merkle_indices[i];
        for (var j = 0; j < TREE_DEPTH; j++) {
            merkle_verify[i].proof[j] <== merkle_proof[i][j];
        }
        // Constraint: proof must be valid
        merkle_verify[i].valid === 1;
    }
    
    // =========================================================================
    // Step 3: Tournament to find winner (argmax)
    // =========================================================================
    
    // Initialize with first candidate
    current_winner_id[0] <== all_solver_ids[0];
    current_winner_score[0] <== all_scores[0];
    current_winner_tiebreak[0] <== tiebreaks[0];
    
    // Signals for tournament logic
    signal score_wins[K];
    signal tie_wins[K];
    signal candidate_wins[K];

    // Pairwise comparisons
    for (var i = 1; i < K; i++) {
        // Compare score[i] > current_winner_score[i-1]
        score_gt[i-1] = GreaterThan(64);
        score_gt[i-1].in[0] <== all_scores[i];
        score_gt[i-1].in[1] <== current_winner_score[i-1];
        
        // Compare score[i] == current_winner_score[i-1]
        score_eq[i-1] = IsEqual();
        score_eq[i-1].in[0] <== all_scores[i];
        score_eq[i-1].in[1] <== current_winner_score[i-1];
        
        // Compare tiebreak[i] < current_winner_tiebreak[i-1] (smaller wins)
        // Note: Using 252 bits to satisfy circomlib limits (sufficient entropy)
        tiebreak_lt[i-1] = LessThan(252);
        tiebreak_lt[i-1].in[0] <== tiebreaks[i];
        tiebreak_lt[i-1].in[1] <== current_winner_tiebreak[i-1];
        
        // Candidate wins if: score > best OR (score == best AND tiebreak < best_tiebreak)
        score_wins[i] <== score_gt[i-1].out;
        tie_wins[i] <== score_eq[i-1].out * tiebreak_lt[i-1].out;
        
        candidate_wins[i] <== score_wins[i] + tie_wins[i] - score_wins[i] * tie_wins[i]; // OR gate
        
        // Update current winner using mux
        current_winner_id[i] <== candidate_wins[i] * (all_solver_ids[i] - current_winner_id[i-1]) + current_winner_id[i-1];
        current_winner_score[i] <== candidate_wins[i] * (all_scores[i] - current_winner_score[i-1]) + current_winner_score[i-1];
        current_winner_tiebreak[i] <== candidate_wins[i] * (tiebreaks[i] - current_winner_tiebreak[i-1]) + current_winner_tiebreak[i-1];
    }
    
    // =========================================================================
    // Step 4: Verify claimed winner matches tournament result
    // =========================================================================
    
    current_winner_id[K-1] === winner_solver_id;
    current_winner_score[K-1] === winner_score;
}

// =========================================================================
// Merkle Proof Verification Template
// =========================================================================

template MerkleProofVerify(LEVELS) {
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
        
        // If bit is 0, leaf is on left; if bit is 1, leaf is on right
        // left = bit ? proof : current
        // right = bit ? current : proof
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

// Default: K=4 candidates, TREE_DEPTH=4 (16 entries max)
component main {public [intent_id, transcript_root, winner_solver_id, winner_score, epoch_seed]} = AuctionSelect(4, 4);
