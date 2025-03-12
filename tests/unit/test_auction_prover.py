"""
Tests for Auction Prover.

Tests cover:
1. Witness generation
2. Winner validation
3. Mock proof generation/verification
"""

import pytest
from cfp.core.prover.auction_prover import (
    MockAuctionProver,
    AuctionWitness,
    DEFAULT_K,
)
from cfp.core.auction.transcript import TranscriptBuilder
from cfp.core.auction.scoring import compute_tie_break


class TestAuctionWitness:
    """Tests for witness data structure."""
    
    def test_witness_to_json(self):
        """Should serialize witness to JSON format."""
        witness = AuctionWitness(
            intent_id=12345,
            transcript_root=67890,
            winner_solver_id=1,
            winner_score=100,
            epoch_seed=99999,
            all_solver_ids=[1, 2],
            all_scores=[100, 50],
            all_commitments=[111, 222],
            merkle_proof=[[1, 2, 3, 4], [5, 6, 7, 8]],
            merkle_indices=[0, 1],
        )
        
        json_data = witness.to_json(k=4, tree_depth=4)
        
        assert json_data["intent_id"] == "12345"
        assert json_data["winner_solver_id"] == "1"
        assert len(json_data["all_solver_ids"]) == 4  # Padded to k
        assert len(json_data["merkle_proof"]) == 4
    
    def test_witness_padding(self):
        """Should pad arrays to k."""
        witness = AuctionWitness(
            intent_id=1,
            transcript_root=2,
            winner_solver_id=1,
            winner_score=100,
            epoch_seed=3,
            all_solver_ids=[1],
            all_scores=[100],
            all_commitments=[111],
            merkle_proof=[[1, 2, 3, 4]],
            merkle_indices=[0],
        )
        
        json_data = witness.to_json(k=4, tree_depth=4)
        
        # Should be padded with zeros
        assert json_data["all_solver_ids"] == ["1", "0", "0", "0"]
        assert json_data["all_scores"] == ["100", "0", "0", "0"]


class TestMockAuctionProver:
    """Tests for mock auction prover."""
    
    @pytest.fixture
    def prover(self):
        return MockAuctionProver(k=4, tree_depth=4)
    
    @pytest.fixture
    def sample_bids(self):
        """Sample bids: (solver_id, score, commitment)"""
        return [
            (1, 100, 1001),
            (2, 200, 1002),
            (3, 150, 1003),
        ]
    
    @pytest.fixture
    def transcript(self, sample_bids):
        """Build transcript from sample bids."""
        t = TranscriptBuilder(intent_id=12345)
        for solver_id, score, commitment in sample_bids:
            t.add_entry(solver_id=solver_id, commitment=commitment, timestamp=1000)
        return t
    
    def test_is_setup_complete(self, prover):
        """Mock prover is always ready."""
        assert prover.is_setup_complete()
    
    def test_generate_witness_selects_highest_score(self, prover, sample_bids, transcript):
        """Witness should have highest score winner."""
        witness = prover.generate_witness(
            intent_id=12345,
            epoch_seed=99999,
            bids=sample_bids,
            transcript=transcript,
        )
        
        # Solver 2 has highest score (200)
        assert witness.winner_solver_id == 2
        assert witness.winner_score == 200
    
    def test_generate_witness_includes_all_bids(self, prover, sample_bids, transcript):
        """Witness should include all bids."""
        witness = prover.generate_witness(
            intent_id=12345,
            epoch_seed=99999,
            bids=sample_bids,
            transcript=transcript,
        )
        
        assert len(witness.all_solver_ids) == 3
        assert len(witness.all_scores) == 3
        assert len(witness.merkle_proof) == 3
    
    def test_generate_witness_with_tie(self, prover):
        """Should use tie-break when scores equal."""
        bids = [
            (1, 100, 1001),
            (2, 100, 1002),  # Same score
        ]
        transcript = TranscriptBuilder(intent_id=12345)
        for solver_id, _, commitment in bids:
            transcript.add_entry(solver_id=solver_id, commitment=commitment, timestamp=1000)
        
        witness = prover.generate_witness(
            intent_id=12345,
            epoch_seed=99999,
            bids=bids,
            transcript=transcript,
        )
        
        # Winner depends on tie-break
        assert witness.winner_score == 100
        # Verify tie-break was used correctly
        tie1 = compute_tie_break(99999, 12345, 1)
        tie2 = compute_tie_break(99999, 12345, 2)
        expected_winner = 1 if tie1 < tie2 else 2
        assert witness.winner_solver_id == expected_winner
    
    def test_generate_proof_success(self, prover, sample_bids, transcript):
        """Should generate proof for valid witness."""
        witness = prover.generate_witness(
            intent_id=12345,
            epoch_seed=99999,
            bids=sample_bids,
            transcript=transcript,
        )
        
        proof, public_signals = prover.generate_proof(witness)
        
        assert proof is not None
        assert public_signals is not None
        assert "pi_a" in proof
        assert len(public_signals) >= 5
    
    def test_generate_proof_wrong_winner_fails(self, prover):
        """Should fail if winner is incorrect."""
        # Create witness with wrong winner
        witness = AuctionWitness(
            intent_id=12345,
            transcript_root=67890,
            winner_solver_id=1,  # Wrong! Solver 2 has higher score
            winner_score=100,
            epoch_seed=99999,
            all_solver_ids=[1, 2],
            all_scores=[100, 200],  # Solver 2 has 200
            all_commitments=[111, 222],
            merkle_proof=[[0]*4, [0]*4],
            merkle_indices=[0, 1],
        )
        
        proof, _ = prover.generate_proof(witness)
        
        assert proof is None
    
    def test_verify_proof(self, prover, sample_bids, transcript):
        """Should verify valid proof."""
        witness = prover.generate_witness(
            intent_id=12345,
            epoch_seed=99999,
            bids=sample_bids,
            transcript=transcript,
        )
        
        proof, public_signals = prover.generate_proof(witness)
        
        is_valid = prover.verify_proof(proof, public_signals)
        
        assert is_valid
    
    def test_verify_proof_invalid_format(self, prover):
        """Should reject invalid proof format."""
        is_valid = prover.verify_proof({}, [])
        assert not is_valid


class TestWitnessValidation:
    """Tests for witness validation logic."""
    
    def test_validate_correct_winner(self):
        """Should validate when winner is correct."""
        prover = MockAuctionProver()
        
        witness = AuctionWitness(
            intent_id=1,
            transcript_root=2,
            winner_solver_id=2,
            winner_score=200,
            epoch_seed=1000,
            all_solver_ids=[1, 2, 3],
            all_scores=[100, 200, 150],
            all_commitments=[1, 2, 3],
            merkle_proof=[[0]*4]*3,
            merkle_indices=[0, 1, 2],
        )
        
        assert prover._validate_winner(witness)
    
    def test_validate_wrong_winner(self):
        """Should reject when winner is incorrect."""
        prover = MockAuctionProver()
        
        witness = AuctionWitness(
            intent_id=1,
            transcript_root=2,
            winner_solver_id=1,  # Wrong
            winner_score=100,
            epoch_seed=1000,
            all_solver_ids=[1, 2, 3],
            all_scores=[100, 200, 150],  # Solver 2 should win
            all_commitments=[1, 2, 3],
            merkle_proof=[[0]*4]*3,
            merkle_indices=[0, 1, 2],
        )
        
        assert not prover._validate_winner(witness)
    
    def test_validate_empty_bids(self):
        """Should reject when no bids."""
        prover = MockAuctionProver()
        
        witness = AuctionWitness(
            intent_id=1,
            transcript_root=2,
            winner_solver_id=0,
            winner_score=0,
            epoch_seed=1000,
            all_solver_ids=[],
            all_scores=[],
            all_commitments=[],
            merkle_proof=[],
            merkle_indices=[],
        )
        
        assert not prover._validate_winner(witness)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
