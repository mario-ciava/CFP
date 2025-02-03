"""
Tests for Commit-Reveal Auction.

Tests cover:
1. Auction lifecycle
2. Commit phase
3. Reveal phase
4. Winner selection
5. Commitment verification
"""

import pytest
import secrets
from dataclasses import dataclass
from typing import Optional

from cfp.core.auction import (
    CommitRevealAuction,
    SolverCommit,
    SolverReveal,
    AuctionState,
    create_commitment,
    create_solver_commit,
)
from cfp.core.intent import IntentType


# =============================================================================
# Fixtures
# =============================================================================


@dataclass
class MockIntent:
    """Mock intent for testing."""
    intent_id: bytes
    intent_type: IntentType = IntentType.TRANSFER
    max_fee: int = 1000


@pytest.fixture
def mock_intent():
    return MockIntent(intent_id=b"\x01" * 32)


@pytest.fixture
def auction(mock_intent):
    auction = CommitRevealAuction(
        intent_id=mock_intent.intent_id,
        intent=mock_intent,
        commit_window=10,
        reveal_window=5,
    )
    auction.start(current_block=100)
    return auction


# =============================================================================
# Commitment Tests
# =============================================================================


class TestCommitment:
    """Tests for commitment creation and verification."""
    
    def test_create_commitment_deterministic(self):
        """Same inputs produce same commitment."""
        intent_id = b"\x01" * 32
        
        c1 = create_commitment(intent_id, solver_id=1, score=100, solution_hash=999, salt=42)
        c2 = create_commitment(intent_id, solver_id=1, score=100, solution_hash=999, salt=42)
        
        assert c1 == c2
    
    def test_create_commitment_different_salt(self):
        """Different salt produces different commitment."""
        intent_id = b"\x01" * 32
        
        c1 = create_commitment(intent_id, solver_id=1, score=100, solution_hash=999, salt=42)
        c2 = create_commitment(intent_id, solver_id=1, score=100, solution_hash=999, salt=43)
        
        assert c1 != c2
    
    def test_create_solver_commit_pair(self):
        """Should create matching commit-reveal pair."""
        intent_id = b"\x01" * 32
        
        commit, reveal = create_solver_commit(
            intent_id=intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        # Verify reveal matches commit
        assert reveal.compute_commitment() == commit.commitment


# =============================================================================
# Auction Lifecycle Tests
# =============================================================================


class TestAuctionLifecycle:
    """Tests for auction state transitions."""
    
    def test_auction_starts_in_commit_phase(self, auction):
        """Auction should start in commit phase."""
        assert auction.state == AuctionState.COMMIT_PHASE
    
    def test_auction_transitions_to_reveal_phase(self, mock_intent):
        """Auction should transition to reveal phase after commit window."""
        auction = CommitRevealAuction(
            intent_id=mock_intent.intent_id,
            intent=mock_intent,
            commit_window=10,
            reveal_window=5,
        )
        auction.start(current_block=100)
        
        # Still in commit phase
        auction.update_state(current_block=105)
        assert auction.state == AuctionState.COMMIT_PHASE
        
        # Transition to reveal phase
        auction.update_state(current_block=110)
        assert auction.state == AuctionState.REVEAL_PHASE
    
    def test_auction_finalizes_with_reveals(self, auction):
        """Auction should finalize when there are valid reveals."""
        # Submit commit
        commit, reveal = create_solver_commit(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        auction.submit_commit(commit, current_block=105)
        
        # Move to reveal phase
        auction.update_state(current_block=110)
        
        # Submit reveal
        auction.submit_reveal(reveal, current_block=112)
        
        # Finalize
        winner, err = auction.finalize(current_block=120, epoch_seed=12345)
        
        assert auction.state == AuctionState.FINALIZED
        assert winner == 1  # solver_id
    
    def test_auction_cancelled_without_reveals(self, auction):
        """Auction should cancel when no valid reveals."""
        # Submit commit but no reveal
        commit, _ = create_solver_commit(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        auction.submit_commit(commit, current_block=105)
        
        # Move past reveal phase (reveal ends at 115 for default window)
        auction.update_state(current_block=116)  # Past reveal_end_block
        
        assert auction.state == AuctionState.CANCELLED


# =============================================================================
# Commit Phase Tests
# =============================================================================


class TestCommitPhase:
    """Tests for commit phase."""
    
    def test_submit_commit_success(self, auction):
        """Should accept valid commit."""
        commit, _ = create_solver_commit(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        success, err = auction.submit_commit(commit, current_block=105)
        
        assert success
        assert auction.get_commit_count() == 1
    
    def test_submit_commit_wrong_intent(self, auction):
        """Should reject commit for different intent."""
        commit, _ = create_solver_commit(
            intent_id=b"\x02" * 32,  # Different intent
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        success, err = auction.submit_commit(commit, current_block=105)
        
        assert not success
        assert "mismatch" in err.lower()
    
    def test_submit_commit_duplicate(self, auction):
        """Should reject duplicate commit from same solver."""
        commit, _ = create_solver_commit(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        auction.submit_commit(commit, current_block=105)
        success, err = auction.submit_commit(commit, current_block=106)
        
        assert not success
        assert "already committed" in err.lower()
    
    def test_submit_commit_after_phase_ends(self, auction):
        """Should reject commit after commit phase ends."""
        commit, _ = create_solver_commit(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        # Move past commit phase
        auction.update_state(current_block=115)
        
        success, err = auction.submit_commit(commit, current_block=115)
        
        assert not success


# =============================================================================
# Reveal Phase Tests
# =============================================================================


class TestRevealPhase:
    """Tests for reveal phase."""
    
    def test_submit_reveal_success(self, auction):
        """Should accept valid reveal that matches commit."""
        commit, reveal = create_solver_commit(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        auction.submit_commit(commit, current_block=105)
        auction.update_state(current_block=110)  # Enter reveal phase
        
        success, err = auction.submit_reveal(reveal, current_block=112)
        
        assert success
        assert auction.get_reveal_count() == 1
    
    def test_submit_reveal_without_commit(self, auction):
        """Should reject reveal without matching commit."""
        # Don't submit commit
        
        reveal = SolverReveal(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        auction.update_state(current_block=110)  # Enter reveal phase
        
        success, err = auction.submit_reveal(reveal, current_block=112)
        
        assert not success
        assert "No commitment" in err
    
    def test_submit_reveal_mismatch(self, auction):
        """Should reject reveal that doesn't match commitment."""
        commit, reveal = create_solver_commit(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        auction.submit_commit(commit, current_block=105)
        auction.update_state(current_block=110)
        
        # Modify reveal to not match
        reveal.score = 200  # Different score
        
        success, err = auction.submit_reveal(reveal, current_block=112)
        
        assert not success
        assert "does not match" in err.lower()
    
    def test_submit_reveal_during_commit_phase(self, auction):
        """Should reject reveal during commit phase."""
        commit, reveal = create_solver_commit(
            intent_id=auction.intent_id,
            solver_id=1,
            score=100,
            solution_hash=999,
            salt=42
        )
        
        auction.submit_commit(commit, current_block=105)
        
        # Try to reveal during commit phase
        success, err = auction.submit_reveal(reveal, current_block=106)
        
        assert not success
        assert "Not in reveal phase" in err


# =============================================================================
# Winner Selection Tests
# =============================================================================


class TestWinnerSelection:
    """Tests for winner selection."""
    
    def test_select_highest_score_winner(self, auction):
        """Should select solver with highest score."""
        # Solver 1: score 100
        c1, r1 = create_solver_commit(auction.intent_id, 1, 100, 999, 42)
        # Solver 2: score 200
        c2, r2 = create_solver_commit(auction.intent_id, 2, 200, 999, 42)
        
        auction.submit_commit(c1, 105)
        auction.submit_commit(c2, 106)
        
        auction.update_state(110)  # Reveal phase
        
        auction.submit_reveal(r1, 112)
        auction.submit_reveal(r2, 113)
        
        winner, err = auction.finalize(120, epoch_seed=12345)
        
        assert winner == 2  # Higher score
        assert auction.winner_score == 200
    
    def test_winner_deterministic(self, mock_intent):
        """Same auction should produce same winner."""
        winners = []
        
        for _ in range(3):
            auction = CommitRevealAuction(
                intent_id=mock_intent.intent_id,
                intent=mock_intent,
                commit_window=10,
                reveal_window=5,
            )
            auction.start(100)
            
            # Two solvers with equal scores
            c1, r1 = create_solver_commit(auction.intent_id, 1, 100, 999, 42)
            c2, r2 = create_solver_commit(auction.intent_id, 2, 100, 999, 43)
            
            auction.submit_commit(c1, 105)
            auction.submit_commit(c2, 106)
            auction.update_state(110)
            auction.submit_reveal(r1, 112)
            auction.submit_reveal(r2, 113)
            
            winner, _ = auction.finalize(120, epoch_seed=99999)
            winners.append(winner)
        
        # All winners should be the same
        assert len(set(winners)) == 1


class TestUnrevealedSolvers:
    """Tests for tracking unrevealed solvers."""
    
    def test_get_unrevealed_solvers(self, auction):
        """Should track solvers who committed but didn't reveal."""
        # Two commits
        c1, r1 = create_solver_commit(auction.intent_id, 1, 100, 999, 42)
        c2, _ = create_solver_commit(auction.intent_id, 2, 200, 999, 43)
        
        auction.submit_commit(c1, 105)
        auction.submit_commit(c2, 106)
        
        auction.update_state(110)  # Reveal phase
        
        # Only solver 1 reveals
        auction.submit_reveal(r1, 112)
        
        unrevealed = auction.get_unrevealed_solvers()
        
        assert 2 in unrevealed
        assert 1 not in unrevealed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
