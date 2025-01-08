"""
Scoring - Deterministic utility computation and winner selection for CFP.

This module implements the scoring system for solver competition:
- Utility function: measures solution quality for an intent
- Tie-break: deterministic, ungrindable tie resolution
- Winner selection: argmax over (utility, -tie_break)

All computations use fixed-point integer arithmetic for:
- Determinism (no floating point rounding issues)
- ZK-friendliness (can be replicated in arithmetic circuits)

See spec/scoring.md for the formal specification.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Tuple, Protocol, runtime_checkable

from cfp.crypto import hash_tie_break
from cfp.utils.logger import get_logger

logger = get_logger("scoring")


# =============================================================================
# Constants
# =============================================================================

# Scale factor for fixed-point arithmetic (2^32)
# Used to ensure primary metric dominates secondary in comparisons
SCALE_FACTOR = 2**32

# Maximum utility value (2^64 - 1)
# All utilities saturate at this value to prevent overflow
MAX_UTILITY = 2**64 - 1

# Minimum utility (cannot go below 0)
MIN_UTILITY = 0


# =============================================================================
# Intent Type (duplicated here to avoid circular imports)
# =============================================================================

class IntentType(IntEnum):
    """Types of intents supported."""
    TRANSFER = 0
    SWAP = 1
    CUSTOM = 2


# =============================================================================
# Protocols for Type Checking
# =============================================================================

@runtime_checkable
class IntentLike(Protocol):
    """Protocol for intent-like objects."""
    intent_id: bytes
    intent_type: IntentType
    max_fee: int


@runtime_checkable
class SolutionLike(Protocol):
    """Protocol for solution-like objects."""
    solver_id: int
    fee_offered: int


@dataclass
class SwapSolution:
    """Solution for a swap intent."""
    solver_id: int
    fee_offered: int
    input_amount: int
    output_amount: int


# =============================================================================
# Safe Arithmetic
# =============================================================================

def safe_add(a: int, b: int) -> int:
    """
    Add two integers with saturation at MAX_UTILITY.
    
    Prevents overflow in utility computation.
    """
    result = a + b
    if result > MAX_UTILITY:
        return MAX_UTILITY
    if result < MIN_UTILITY:
        return MIN_UTILITY
    return result


def safe_sub(a: int, b: int) -> int:
    """
    Subtract with floor at MIN_UTILITY (0).
    """
    result = a - b
    if result < MIN_UTILITY:
        return MIN_UTILITY
    if result > MAX_UTILITY:
        return MAX_UTILITY
    return result


def safe_mul(a: int, b: int, scale: int = 1) -> int:
    """
    Multiply and scale down with saturation.
    
    result = (a * b) // scale
    """
    result = (a * b) // scale
    if result > MAX_UTILITY:
        return MAX_UTILITY
    return result


# =============================================================================
# Utility Computation
# =============================================================================

def compute_utility_transfer(intent: IntentLike, solution: SolutionLike) -> int:
    """
    Compute utility for a transfer intent.
    
    For transfers, utility = fee offered by solver.
    Higher fee = better for protocol = higher utility.
    
    Args:
        intent: The user's transfer intent
        solution: Solver's proposed solution
        
    Returns:
        Utility score (non-negative integer)
    """
    # Validate fee doesn't exceed max
    fee = min(solution.fee_offered, intent.max_fee)
    return max(0, fee)


def compute_utility_swap(intent: IntentLike, solution: SwapSolution) -> int:
    """
    Compute utility for a swap intent.
    
    For swaps, utility = output_amount * SCALE - input_amount
    
    This ensures:
    - Higher output is always better (scaled up)
    - Lower input is better as tiebreaker (not scaled)
    - Output dominates input in comparison
    
    Args:
        intent: The user's swap intent
        solution: Solver's proposed swap solution
        
    Returns:
        Utility score (non-negative integer)
    """
    # Output score (scaled to dominate)
    output_score = safe_mul(solution.output_amount, SCALE_FACTOR)
    
    # Input penalty (not scaled, acts as tiebreaker)
    input_penalty = solution.input_amount
    
    # Combined utility
    return safe_sub(output_score, input_penalty)


def compute_utility(intent: IntentLike, solution: SolutionLike) -> int:
    """
    Compute utility for any intent type.
    
    Dispatches to type-specific utility function.
    
    Args:
        intent: The user's intent
        solution: Solver's proposed solution
        
    Returns:
        Utility score (non-negative integer)
    """
    if intent.intent_type == IntentType.TRANSFER:
        return compute_utility_transfer(intent, solution)
    elif intent.intent_type == IntentType.SWAP:
        if isinstance(solution, SwapSolution):
            return compute_utility_swap(intent, solution)
        else:
            # Fallback for non-swap solutions
            return compute_utility_transfer(intent, solution)
    else:
        # Custom and unknown types: use fee as utility
        return compute_utility_transfer(intent, solution)


# =============================================================================
# Tie-Break Computation
# =============================================================================

def compute_tie_break(epoch_seed: int, intent_id: int, solver_id: int) -> int:
    """
    Compute deterministic, ungrindable tie-break value.
    
    Uses Poseidon hash with domain separation.
    Smaller value wins in case of equal utility.
    
    Properties:
    - Deterministic: same inputs always produce same output
    - Ungrindable: solver cannot predict or manipulate result
    - Fair: based on external epoch_seed, not solver-controlled
    
    Args:
        epoch_seed: External randomness (e.g., previous block hash as int)
        intent_id: Intent identifier (as int)
        solver_id: Solver identifier (as int)
        
    Returns:
        Tie-break value (smaller wins)
    """
    return hash_tie_break(epoch_seed, intent_id, solver_id)


def compute_tie_break_from_bytes(
    epoch_seed: bytes,
    intent_id: bytes, 
    solver_id: bytes
) -> int:
    """
    Compute tie-break from byte representations.
    
    Convenience wrapper that converts bytes to int.
    """
    seed_int = int.from_bytes(epoch_seed[:32].ljust(32, b'\x00'), 'big')
    intent_int = int.from_bytes(intent_id[:32].ljust(32, b'\x00'), 'big')
    solver_int = int.from_bytes(solver_id[:32].ljust(32, b'\x00'), 'big')
    
    # Reduce to field size
    from cfp.crypto import FIELD_PRIME
    seed_int = seed_int % FIELD_PRIME
    intent_int = intent_int % FIELD_PRIME
    solver_int = solver_int % FIELD_PRIME
    
    return compute_tie_break(seed_int, intent_int, solver_int)


# =============================================================================
# Solution Comparison
# =============================================================================

def compare_solutions(
    sol_a: SolutionLike,
    sol_b: SolutionLike,
    intent: IntentLike,
    epoch_seed: int,
    intent_id: int,
) -> int:
    """
    Compare two solutions for an intent.
    
    Uses lexicographic ordering: (utility, -tie_break)
    
    Args:
        sol_a: First solution
        sol_b: Second solution
        intent: The intent being solved
        epoch_seed: External randomness for tie-break
        intent_id: Intent ID as integer
        
    Returns:
        -1 if sol_a < sol_b (sol_b wins)
         0 if sol_a == sol_b (identical)
        +1 if sol_a > sol_b (sol_a wins)
    """
    # Primary comparison: utility
    util_a = compute_utility(intent, sol_a)
    util_b = compute_utility(intent, sol_b)
    
    if util_a > util_b:
        return 1
    if util_a < util_b:
        return -1
    
    # Secondary comparison: tie-break (smaller wins)
    tie_a = compute_tie_break(epoch_seed, intent_id, sol_a.solver_id)
    tie_b = compute_tie_break(epoch_seed, intent_id, sol_b.solver_id)
    
    if tie_a < tie_b:
        return 1  # sol_a wins (smaller tie-break)
    if tie_a > tie_b:
        return -1
    
    # Identical (same solver_id, which shouldn't happen in valid auction)
    return 0


# =============================================================================
# Winner Selection
# =============================================================================

def select_winner(
    intent: IntentLike,
    solutions: List[SolutionLike],
    epoch_seed: int,
    intent_id: Optional[int] = None,
) -> Tuple[Optional[SolutionLike], int]:
    """
    Select the winning solution for an intent.
    
    Uses argmax over (utility, -tie_break) total ordering.
    
    Args:
        intent: The user's intent
        solutions: List of solver solutions
        epoch_seed: External randomness for tie-break
        intent_id: Intent ID as integer (computed from bytes if not provided)
        
    Returns:
        Tuple of (winning_solution, winner_index)
        Returns (None, -1) if no solutions provided
    """
    if not solutions:
        logger.debug("No solutions to select winner from")
        return None, -1
    
    # Convert intent_id if needed
    if intent_id is None:
        if hasattr(intent, 'intent_id') and isinstance(intent.intent_id, bytes):
            from cfp.crypto import FIELD_PRIME
            intent_id = int.from_bytes(intent.intent_id[:32].ljust(32, b'\x00'), 'big') % FIELD_PRIME
        else:
            intent_id = 0
    
    # Tournament: find argmax
    winner = solutions[0]
    winner_idx = 0
    
    for i, candidate in enumerate(solutions[1:], start=1):
        comparison = compare_solutions(candidate, winner, intent, epoch_seed, intent_id)
        if comparison > 0:
            winner = candidate
            winner_idx = i
    
    logger.debug(f"Selected winner at index {winner_idx} with utility {compute_utility(intent, winner)}")
    return winner, winner_idx


def verify_winner(
    intent: IntentLike,
    claimed_winner: SolutionLike,
    all_solutions: List[SolutionLike],
    epoch_seed: int,
    intent_id: int,
) -> bool:
    """
    Verify that claimed_winner is indeed the argmax.
    
    Used for validation and ZK proof verification.
    
    Args:
        intent: The user's intent
        claimed_winner: The solution claimed to be the winner
        all_solutions: All eligible solutions
        epoch_seed: External randomness
        intent_id: Intent ID as integer
        
    Returns:
        True if claimed_winner is the correct winner
    """
    actual_winner, _ = select_winner(intent, all_solutions, epoch_seed, intent_id)
    
    if actual_winner is None:
        return False
    
    # Check solver_id match
    return actual_winner.solver_id == claimed_winner.solver_id


# =============================================================================
# Utility Helpers
# =============================================================================

def rank_solutions(
    intent: IntentLike,
    solutions: List[SolutionLike],
    epoch_seed: int,
    intent_id: int,
) -> List[Tuple[SolutionLike, int, int, int]]:
    """
    Rank all solutions from best to worst.
    
    Returns list of (solution, rank, utility, tie_break) tuples.
    """
    # Compute utility and tie-break for each
    scored = []
    for sol in solutions:
        utility = compute_utility(intent, sol)
        tie = compute_tie_break(epoch_seed, intent_id, sol.solver_id)
        scored.append((sol, utility, tie))
    
    # Sort by (utility desc, tie_break asc)
    scored.sort(key=lambda x: (-x[1], x[2]))
    
    # Add rank
    return [(sol, i, util, tie) for i, (sol, util, tie) in enumerate(scored)]
