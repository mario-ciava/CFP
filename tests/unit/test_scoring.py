"""
Tests for scoring and winner selection.

These tests verify:
1. Utility computation for different intent types
2. Tie-break determinism
3. Winner selection correctness
4. Safe arithmetic
"""

import pytest
from dataclasses import dataclass
from typing import Optional

from cfp.core.auction.scoring import (
    compute_utility,
    compute_utility_transfer,
    compute_utility_swap,
    compute_tie_break,
    compare_solutions,
    select_winner,
    verify_winner,
    rank_solutions,
    safe_add,
    safe_sub,
    safe_mul,
    IntentType,
    SwapSolution,
    SCALE_FACTOR,
    MAX_UTILITY,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@dataclass
class MockIntent:
    """Mock intent for testing."""
    intent_id: bytes = b"\x00" * 32
    intent_type: IntentType = IntentType.TRANSFER
    max_fee: int = 1000


@dataclass
class MockSolution:
    """Mock solution for testing."""
    solver_id: int
    fee_offered: int


class TestSafeArithmetic:
    """Tests for overflow-safe arithmetic."""
    
    def test_safe_add_normal(self):
        """Normal addition works."""
        assert safe_add(100, 200) == 300
    
    def test_safe_add_overflow(self):
        """Overflow saturates at MAX_UTILITY."""
        result = safe_add(MAX_UTILITY, 1)
        assert result == MAX_UTILITY
    
    def test_safe_sub_normal(self):
        """Normal subtraction works."""
        assert safe_sub(200, 100) == 100
    
    def test_safe_sub_underflow(self):
        """Underflow floors at 0."""
        result = safe_sub(100, 200)
        assert result == 0
    
    def test_safe_mul_normal(self):
        """Normal multiplication works."""
        assert safe_mul(100, 200) == 20000
    
    def test_safe_mul_with_scale(self):
        """Multiplication with scale down."""
        result = safe_mul(100, 200, 10)
        assert result == 2000


class TestUtilityComputation:
    """Tests for utility computation."""
    
    def test_transfer_utility(self):
        """Transfer utility equals fee offered."""
        intent = MockIntent(intent_type=IntentType.TRANSFER, max_fee=1000)
        solution = MockSolution(solver_id=1, fee_offered=500)
        
        utility = compute_utility_transfer(intent, solution)
        assert utility == 500
    
    def test_transfer_utility_capped_at_max_fee(self):
        """Transfer utility capped at max_fee."""
        intent = MockIntent(intent_type=IntentType.TRANSFER, max_fee=100)
        solution = MockSolution(solver_id=1, fee_offered=500)
        
        utility = compute_utility_transfer(intent, solution)
        assert utility == 100
    
    def test_swap_utility_basic(self):
        """Swap utility computed correctly."""
        intent = MockIntent(intent_type=IntentType.SWAP)
        solution = SwapSolution(
            solver_id=1,
            fee_offered=100,
            input_amount=1000,
            output_amount=900
        )
        
        utility = compute_utility_swap(intent, solution)
        # utility = output * SCALE - input
        expected = 900 * SCALE_FACTOR - 1000
        assert utility == expected
    
    def test_swap_utility_higher_output_wins(self):
        """Higher output gives higher utility."""
        intent = MockIntent(intent_type=IntentType.SWAP)
        
        sol_a = SwapSolution(solver_id=1, fee_offered=0, input_amount=1000, output_amount=900)
        sol_b = SwapSolution(solver_id=2, fee_offered=0, input_amount=1000, output_amount=950)
        
        util_a = compute_utility_swap(intent, sol_a)
        util_b = compute_utility_swap(intent, sol_b)
        
        assert util_b > util_a
    
    def test_swap_utility_lower_input_wins_on_tie(self):
        """Lower input gives higher utility when output equal."""
        intent = MockIntent(intent_type=IntentType.SWAP)
        
        sol_a = SwapSolution(solver_id=1, fee_offered=0, input_amount=1000, output_amount=900)
        sol_b = SwapSolution(solver_id=2, fee_offered=0, input_amount=900, output_amount=900)
        
        util_a = compute_utility_swap(intent, sol_a)
        util_b = compute_utility_swap(intent, sol_b)
        
        assert util_b > util_a
    
    def test_compute_utility_dispatch(self):
        """compute_utility dispatches to correct function."""
        intent = MockIntent(intent_type=IntentType.TRANSFER)
        solution = MockSolution(solver_id=1, fee_offered=500)
        
        utility = compute_utility(intent, solution)
        assert utility == 500


class TestTieBreak:
    """Tests for tie-break computation."""
    
    def test_tie_break_deterministic(self):
        """Same inputs produce same tie-break."""
        tie1 = compute_tie_break(100, 200, 300)
        tie2 = compute_tie_break(100, 200, 300)
        assert tie1 == tie2
    
    def test_tie_break_different_seeds(self):
        """Different epoch seeds produce different tie-breaks."""
        tie1 = compute_tie_break(100, 200, 300)
        tie2 = compute_tie_break(101, 200, 300)
        assert tie1 != tie2
    
    def test_tie_break_different_intents(self):
        """Different intents produce different tie-breaks."""
        tie1 = compute_tie_break(100, 200, 300)
        tie2 = compute_tie_break(100, 201, 300)
        assert tie1 != tie2
    
    def test_tie_break_different_solvers(self):
        """Different solvers produce different tie-breaks."""
        tie1 = compute_tie_break(100, 200, 300)
        tie2 = compute_tie_break(100, 200, 301)
        assert tie1 != tie2


class TestSolutionComparison:
    """Tests for solution comparison."""
    
    def test_higher_utility_wins(self):
        """Solution with higher utility wins."""
        intent = MockIntent()
        sol_a = MockSolution(solver_id=1, fee_offered=500)
        sol_b = MockSolution(solver_id=2, fee_offered=600)
        
        result = compare_solutions(sol_a, sol_b, intent, epoch_seed=0, intent_id=0)
        assert result == -1  # sol_b wins
        
        result = compare_solutions(sol_b, sol_a, intent, epoch_seed=0, intent_id=0)
        assert result == 1  # sol_b still wins
    
    def test_equal_utility_tie_break_decides(self):
        """Equal utility uses tie-break (smaller wins)."""
        intent = MockIntent()
        sol_a = MockSolution(solver_id=1, fee_offered=500)
        sol_b = MockSolution(solver_id=2, fee_offered=500)
        
        # Get tie-breaks
        tie_a = compute_tie_break(0, 0, 1)
        tie_b = compute_tie_break(0, 0, 2)
        
        result = compare_solutions(sol_a, sol_b, intent, epoch_seed=0, intent_id=0)
        
        # Smaller tie-break wins
        if tie_a < tie_b:
            assert result == 1  # sol_a wins
        else:
            assert result == -1  # sol_b wins


class TestWinnerSelection:
    """Tests for winner selection."""
    
    def test_select_winner_single_solution(self):
        """Single solution wins by default."""
        intent = MockIntent()
        solutions = [MockSolution(solver_id=1, fee_offered=500)]
        
        winner, idx = select_winner(intent, solutions, epoch_seed=0)
        
        assert winner is not None
        assert idx == 0
        assert winner.solver_id == 1
    
    def test_select_winner_empty_list(self):
        """Empty list returns None."""
        intent = MockIntent()
        
        winner, idx = select_winner(intent, [], epoch_seed=0)
        
        assert winner is None
        assert idx == -1
    
    def test_select_winner_best_utility(self):
        """Winner has highest utility."""
        intent = MockIntent()
        solutions = [
            MockSolution(solver_id=1, fee_offered=100),
            MockSolution(solver_id=2, fee_offered=300),
            MockSolution(solver_id=3, fee_offered=200),
        ]
        
        winner, idx = select_winner(intent, solutions, epoch_seed=0, intent_id=0)
        
        assert winner is not None
        assert winner.fee_offered == 300
        assert winner.solver_id == 2
    
    def test_select_winner_deterministic(self):
        """Same inputs always produce same winner."""
        intent = MockIntent()
        solutions = [
            MockSolution(solver_id=1, fee_offered=100),
            MockSolution(solver_id=2, fee_offered=100),
            MockSolution(solver_id=3, fee_offered=100),
        ]
        
        # Run multiple times
        winners = []
        for _ in range(10):
            winner, _ = select_winner(intent, solutions, epoch_seed=12345, intent_id=67890)
            winners.append(winner.solver_id if winner else None)
        
        # All should be the same
        assert len(set(winners)) == 1
    
    def test_select_winner_different_epoch_can_change_winner(self):
        """Different epoch seed can change winner (when utilities tied)."""
        intent = MockIntent()
        solutions = [
            MockSolution(solver_id=1, fee_offered=100),
            MockSolution(solver_id=2, fee_offered=100),
        ]
        
        winner1, _ = select_winner(intent, solutions, epoch_seed=1, intent_id=0)
        winner2, _ = select_winner(intent, solutions, epoch_seed=2, intent_id=0)
        
        # Winners might be different due to tie-break
        # (not guaranteed, but statistically likely over many tries)
        # Just check both are valid
        assert winner1 is not None
        assert winner2 is not None


class TestVerifyWinner:
    """Tests for winner verification."""
    
    def test_verify_correct_winner(self):
        """Correct winner is verified."""
        intent = MockIntent()
        solutions = [
            MockSolution(solver_id=1, fee_offered=100),
            MockSolution(solver_id=2, fee_offered=300),
        ]
        
        winner, _ = select_winner(intent, solutions, epoch_seed=0, intent_id=0)
        
        is_valid = verify_winner(intent, winner, solutions, epoch_seed=0, intent_id=0)
        assert is_valid
    
    def test_verify_wrong_winner(self):
        """Wrong winner is rejected."""
        intent = MockIntent()
        solutions = [
            MockSolution(solver_id=1, fee_offered=100),
            MockSolution(solver_id=2, fee_offered=300),
        ]
        
        wrong_winner = solutions[0]  # Lower fee, not the winner
        
        is_valid = verify_winner(intent, wrong_winner, solutions, epoch_seed=0, intent_id=0)
        assert not is_valid


class TestRankSolutions:
    """Tests for solution ranking."""
    
    def test_rank_by_utility(self):
        """Solutions ranked by utility."""
        intent = MockIntent()
        solutions = [
            MockSolution(solver_id=1, fee_offered=100),
            MockSolution(solver_id=2, fee_offered=300),
            MockSolution(solver_id=3, fee_offered=200),
        ]
        
        ranked = rank_solutions(intent, solutions, epoch_seed=0, intent_id=0)
        
        # First should have highest utility
        assert ranked[0][0].fee_offered == 300
        assert ranked[1][0].fee_offered == 200
        assert ranked[2][0].fee_offered == 100
    
    def test_rank_includes_utility_and_tiebreak(self):
        """Ranking includes utility and tie-break values."""
        intent = MockIntent()
        solutions = [MockSolution(solver_id=1, fee_offered=100)]
        
        ranked = rank_solutions(intent, solutions, epoch_seed=0, intent_id=0)
        
        sol, rank, utility, tie = ranked[0]
        assert rank == 0
        assert utility == 100
        assert isinstance(tie, int)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
