"""
Integration tests for the Verifiable Auction system.

Tests the complete flow from intent submission to proof generation.
"""

import pytest
import secrets
from cfp.crypto import generate_keypair, poseidon_bytes
from cfp.core.intent import IntentType, create_intent
from cfp.core.intent.verifiable_auction import (
    VerifiableAuctionManager,
    VerifiableAuctionConfig,
)
from cfp.core.auction import create_commitment, AuctionState
from cfp.core.state import address_from_public_key


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def manager():
    """Create a configured auction manager."""
    config = VerifiableAuctionConfig(
        min_solver_stake=100,
        min_bid_bond=10,
        commit_window=5,
        reveal_window=3,
        execution_window=5,
    )
    return VerifiableAuctionManager(config=config)


@pytest.fixture
def user_keypair():
    return generate_keypair()


@pytest.fixture
def solver_keypairs():
    """Create 3 solver keypairs."""
    return [generate_keypair() for _ in range(3)]


# =============================================================================
# Full Flow Tests
# =============================================================================


class TestFullAuctionFlow:
    """End-to-end auction flow tests."""
    
    def test_complete_auction_flow(self, manager, user_keypair, solver_keypairs):
        """Test complete flow: register -> submit -> commit -> reveal -> execute."""
        # 1. Register solvers
        solver_ids = []
        for kp in solver_keypairs:
            solver_id, err = manager.register_solver(kp.public_key, initial_stake=500)
            assert solver_id is not None, f"Registration failed: {err}"
            solver_ids.append(solver_id)
        
        # 2. Create and submit intent
        user_addr = address_from_public_key(user_keypair.public_key)
        intent = create_intent(
            user_address=user_addr,
            intent_type=IntentType.TRANSFER,
            conditions={"recipient": "0x" + "ab" * 20, "amount": 100},
            max_fee=50,
            deadline_block=1000,
            private_key=user_keypair.private_key,
        )
        
        success, err = manager.submit_intent(intent)
        assert success, f"Intent submission failed: {err}"
        
        # 3. Submit commits from all solvers
        # Note: scores must be <= max_fee for utility to differentiate them
        salts = [secrets.randbelow(2**128) for _ in range(3)]
        scores = [30, 45, 35]  # Solver 1 has highest score (within max_fee=50)
        
        for i, (solver_id, score, salt) in enumerate(zip(solver_ids, scores, salts)):
            commitment = create_commitment(
                intent_id=intent.intent_id,
                solver_id=solver_id,
                score=score,
                solution_hash=12345,
                salt=salt,
            )
            success, err = manager.submit_commit(intent.intent_id, solver_id, commitment)
            assert success, f"Commit failed for solver {i}: {err}"
        
        # 4. Advance to reveal phase
        manager.on_new_block(manager.current_block + 5)
        
        auction = manager.get_auction(intent.intent_id)
        assert auction.state == AuctionState.REVEAL_PHASE
        
        # 5. Submit reveals
        for i, (solver_id, score, salt) in enumerate(zip(solver_ids, scores, salts)):
            success, err = manager.submit_reveal(
                intent_id=intent.intent_id,
                solver_id=solver_id,
                score=score,
                solution_hash=12345,
                salt=salt,
            )
            assert success, f"Reveal failed for solver {i}: {err}"
        
        # 6. Advance to finalization
        manager.on_new_block(manager.current_block + 4)
        
        auction = manager.get_auction(intent.intent_id)
        assert auction.state == AuctionState.FINALIZED
        assert auction.winner_solver_id == solver_ids[1]  # Highest score (45)
        
        # 7. Verify proof was generated
        proof = manager.get_proof(intent.intent_id)
        assert proof is not None
    
    def test_auction_with_tie_break(self, manager, user_keypair, solver_keypairs):
        """Test that tie-break works correctly."""
        # Register solvers
        solver_ids = []
        for kp in solver_keypairs[:2]:
            sid, _ = manager.register_solver(kp.public_key, 500)
            solver_ids.append(sid)
        
        # Submit intent
        intent = create_intent(
            user_address=address_from_public_key(user_keypair.public_key),
            intent_type=IntentType.TRANSFER,
            conditions={"recipient": "0x" + "cd" * 20, "amount": 50},
            max_fee=30,
            deadline_block=500,
            private_key=user_keypair.private_key,
        )
        manager.submit_intent(intent)
        
        # Both solvers submit same score
        salt1, salt2 = 111, 222
        score = 100
        
        for solver_id, salt in zip(solver_ids, [salt1, salt2]):
            commitment = create_commitment(intent.intent_id, solver_id, score, 999, salt)
            manager.submit_commit(intent.intent_id, solver_id, commitment)
        
        # Reveal phase
        manager.on_new_block(manager.current_block + 5)
        
        for solver_id, salt in zip(solver_ids, [salt1, salt2]):
            manager.submit_reveal(intent.intent_id, solver_id, score, 999, salt)
        
        # Finalize
        manager.on_new_block(manager.current_block + 4)
        
        auction = manager.get_auction(intent.intent_id)
        assert auction.state == AuctionState.FINALIZED
        # Winner determined by tie-break (depends on Poseidon hash)
        assert auction.winner_solver_id in solver_ids


class TestExecutionFlow:
    """Tests for execution and slashing."""
    
    def test_successful_execution(self, manager, user_keypair, solver_keypairs):
        """Test successful execution releases bond."""
        # Setup: register, submit, commit, reveal, finalize
        solver_id, _ = manager.register_solver(solver_keypairs[0].public_key, 500)
        
        intent = create_intent(
            user_address=address_from_public_key(user_keypair.public_key),
            intent_type=IntentType.TRANSFER,
            conditions={"amount": 10},
            max_fee=20,
            deadline_block=100,
            private_key=user_keypair.private_key,
        )
        manager.submit_intent(intent)
        
        salt = 42
        commitment = create_commitment(intent.intent_id, solver_id, 50, 123, salt)
        manager.submit_commit(intent.intent_id, solver_id, commitment)
        
        manager.on_new_block(manager.current_block + 5)
        manager.submit_reveal(intent.intent_id, solver_id, 50, 123, salt)
        manager.on_new_block(manager.current_block + 4)
        
        # Get ticket
        assert len(manager.pending_tickets) == 1
        ticket = list(manager.pending_tickets.values())[0]
        
        # Report execution
        success, err = manager.report_execution(ticket.ticket_id, b"\xaa" * 32)
        assert success, err
        
        # Ticket should be completed
        assert len(manager.pending_tickets) == 0
        assert len(manager.completed_tickets) == 1
    
    def test_execution_timeout_slashes(self, manager, user_keypair, solver_keypairs):
        """Test that timeout slashes solver."""
        solver_id, _ = manager.register_solver(solver_keypairs[0].public_key, 500)
        initial_stake = manager.registry.get_solver(solver_id).stake_total
        
        intent = create_intent(
            user_address=address_from_public_key(user_keypair.public_key),
            intent_type=IntentType.TRANSFER,
            conditions={"amount": 10},
            max_fee=20,
            deadline_block=100,
            private_key=user_keypair.private_key,
        )
        manager.submit_intent(intent)
        
        salt = 42
        commitment = create_commitment(intent.intent_id, solver_id, 50, 123, salt)
        manager.submit_commit(intent.intent_id, solver_id, commitment)
        
        manager.on_new_block(manager.current_block + 5)
        manager.submit_reveal(intent.intent_id, solver_id, 50, 123, salt)
        manager.on_new_block(manager.current_block + 4)
        
        # Don't execute, advance past deadline
        manager.on_new_block(manager.current_block + 10)
        
        # Ticket should be slashed
        assert len(manager.pending_tickets) == 0
        assert len(manager.completed_tickets) == 1
        
        # Solver stake reduced
        solver = manager.registry.get_solver(solver_id)
        assert solver.slash_count > 0


class TestEdgeCases:
    """Edge case tests."""
    
    def test_unregistered_solver_cannot_commit(self, manager, user_keypair):
        """Unregistered solver should be rejected."""
        intent = create_intent(
            user_address=address_from_public_key(user_keypair.public_key),
            intent_type=IntentType.TRANSFER,
            conditions={"amount": 10},
            max_fee=20,
            deadline_block=100,
            private_key=user_keypair.private_key,
        )
        manager.submit_intent(intent)
        
        # Try to commit without registration
        success, err = manager.submit_commit(intent.intent_id, solver_id=99999, commitment=12345)
        assert not success
        assert "not registered" in err.lower()
    
    def test_commit_without_reveal_slashes(self, manager, user_keypair, solver_keypairs):
        """Solver who commits but doesn't reveal should be slashed."""
        solver_id, _ = manager.register_solver(solver_keypairs[0].public_key, 500)
        
        intent = create_intent(
            user_address=address_from_public_key(user_keypair.public_key),
            intent_type=IntentType.TRANSFER,
            conditions={"amount": 10},
            max_fee=20,
            deadline_block=100,
            private_key=user_keypair.private_key,
        )
        manager.submit_intent(intent)
        
        commitment = create_commitment(intent.intent_id, solver_id, 50, 123, 42)
        manager.submit_commit(intent.intent_id, solver_id, commitment)
        
        # Advance past reveal phase without revealing
        manager.on_new_block(manager.current_block + 10)
        
        # Auction should be cancelled
        auction = manager.get_auction(intent.intent_id)
        # Auction is cleaned up
        assert auction is None or auction.state == AuctionState.CANCELLED
    
    def test_invalid_reveal_rejected(self, manager, user_keypair, solver_keypairs):
        """Reveal that doesn't match commit should be rejected."""
        solver_id, _ = manager.register_solver(solver_keypairs[0].public_key, 500)
        
        intent = create_intent(
            user_address=address_from_public_key(user_keypair.public_key),
            intent_type=IntentType.TRANSFER,
            conditions={"amount": 10},
            max_fee=20,
            deadline_block=100,
            private_key=user_keypair.private_key,
        )
        manager.submit_intent(intent)
        
        commitment = create_commitment(intent.intent_id, solver_id, 50, 123, 42)
        manager.submit_commit(intent.intent_id, solver_id, commitment)
        
        manager.on_new_block(manager.current_block + 5)
        
        # Reveal with wrong score
        success, err = manager.submit_reveal(intent.intent_id, solver_id, 999, 123, 42)
        assert not success
        assert "does not match" in err.lower()


class TestStats:
    """Statistics tests."""
    
    def test_stats_tracking(self, manager, user_keypair, solver_keypairs):
        """Stats should be tracked correctly."""
        initial_stats = manager.stats()
        assert initial_stats["active_auctions"] == 0
        assert initial_stats["registered_solvers"] == 0
        
        # Register solver
        manager.register_solver(solver_keypairs[0].public_key, 500)
        
        # Submit intent
        intent = create_intent(
            user_address=address_from_public_key(user_keypair.public_key),
            intent_type=IntentType.TRANSFER,
            conditions={"amount": 10},
            max_fee=20,
            deadline_block=100,
            private_key=user_keypair.private_key,
        )
        manager.submit_intent(intent)
        
        stats = manager.stats()
        assert stats["active_auctions"] == 1
        assert stats["registered_solvers"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
