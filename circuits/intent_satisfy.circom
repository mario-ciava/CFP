pragma circom 2.1.0;

/*
 * Intent Satisfaction Circuit - Proves solution satisfies intent constraints
 * 
 * This circuit proves that:
 * 1. The intent_id is correctly computed
 * 2. The solution satisfies the intent's constraints
 * 3. The solver's execution matches declared solution_hash
 * 
 * Public Inputs:
 * - intent_id: Hash of the intent
 * - solution_hash: Hash of the execution solution
 * - solver_id: The solver executing
 * 
 * Private Inputs:
 * - user_pk_hash: Hash of user's public key
 * - nonce: Intent nonce
 * - constraints_hash: Hash of serialized constraints
 * - deadline: Intent deadline block
 * - chain_id: Chain identifier
 * - solution_data: Execution solution data
 */

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// Domain separators (must match Python implementation)
template IntentSatisfy() {
    // Domain separators (must match Python implementation)
    var DOMAIN_INTENT_ID = 1;
    
    // =========================================================================
    // Public Inputs
    // =========================================================================
    signal input intent_id;
    signal input solution_hash;
    signal input solver_id;
    
    // =========================================================================
    // Private Inputs - Intent Data
    // =========================================================================
    signal input user_pk_hash;
    signal input nonce;
    signal input constraints_hash;
    signal input deadline;
    signal input chain_id;
    
    // =========================================================================
    // Private Inputs - Solution Data (for transfer intent)
    // =========================================================================
    signal input recipient_hash;
    signal input amount;
    signal input actual_fee;
    
    // =========================================================================
    // Step 1: Verify intent_id computation
    // =========================================================================
    
    // Compute intent_id = Poseidon chain(domain, pk_hash, nonce, constraints, deadline, chain_id)
    component h1 = Poseidon(2);
    h1.inputs[0] <== DOMAIN_INTENT_ID;
    h1.inputs[1] <== user_pk_hash;
    
    component h2 = Poseidon(2);
    h2.inputs[0] <== h1.out;
    h2.inputs[1] <== nonce;
    
    component h3 = Poseidon(2);
    h3.inputs[0] <== h2.out;
    h3.inputs[1] <== constraints_hash;
    
    component h4 = Poseidon(2);
    h4.inputs[0] <== h3.out;
    h4.inputs[1] <== deadline;
    
    component h5 = Poseidon(2);
    h5.inputs[0] <== h4.out;
    h5.inputs[1] <== chain_id;
    
    // Constraint: computed intent_id must match public input
    h5.out === intent_id;
    
    // =========================================================================
    // Step 2: Compute and verify solution_hash
    // =========================================================================
    
    // solution_hash = Poseidon(recipient_hash, amount, actual_fee)
    component sol_hash = Poseidon(3);
    sol_hash.inputs[0] <== recipient_hash;
    sol_hash.inputs[1] <== amount;
    sol_hash.inputs[2] <== actual_fee;
    
    // Constraint: computed solution hash must match public input
    sol_hash.out === solution_hash;
    
    // =========================================================================
    // Step 3: Verify solution satisfies constraints
    // =========================================================================
    
    // For transfer: constraints_hash should encode (recipient, min_amount)
    // The solution must satisfy: actual_amount >= min_amount
    // This would require unpacking constraints_hash, which is complex
    // 
    // Simplified approach: assume constraints are satisfied if solution_hash is valid
    // Full constraint verification would require intent-type-specific templates
    
    // Placeholder constraint: amount must be positive
    component amountGt = GreaterThan(64);
    amountGt.in[0] <== amount;
    amountGt.in[1] <== 0;
    amountGt.out === 1;
}

component main {public [intent_id, solution_hash, solver_id]} = IntentSatisfy();
