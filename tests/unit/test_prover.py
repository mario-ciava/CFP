"""
Unit tests for ZK prover module.

Tests cover:
1. Mock prover proof generation
2. Proof verification
3. ProverManager batch handling
4. Proof metadata serialization
"""

import pytest
import time
import secrets

from cfp.core.prover import (
    ProofMetadata,
    MockProver,
    ProverManager,
)
from cfp.crypto import sha256


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_prover():
    """Create a mock prover with fast delay."""
    return MockProver(proving_delay_ms=10, success_rate=1.0)


@pytest.fixture
def prover_manager():
    """Create a prover manager with mock prover."""
    return ProverManager(use_mock=True, batch_size=10)


@pytest.fixture
def sample_state_roots():
    """Generate sample state roots."""
    return {
        "old": sha256(b"old_state"),
        "new": sha256(b"new_state"),
    }


@pytest.fixture
def sample_transactions():
    """Generate sample transactions."""
    return [secrets.token_bytes(100) for _ in range(5)]


# =============================================================================
# ProofMetadata Tests
# =============================================================================


class TestProofMetadata:
    """Tests for ProofMetadata serialization."""
    
    def test_to_dict_and_back(self, sample_state_roots):
        """Metadata should survive dict conversion."""
        metadata = ProofMetadata(
            proof_id=sha256(b"proof_id"),
            batch_start=0,
            batch_end=99,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            batch_hash=sha256(b"batch"),
            proof=secrets.token_bytes(256),
            public_inputs=["0x1234", "0x5678"],
            created_at=int(time.time()),
            proving_time_ms=500,
            verified=False,
        )
        
        # Convert to dict and back
        data = metadata.to_dict()
        restored = ProofMetadata.from_dict(data)
        
        assert restored.proof_id == metadata.proof_id
        assert restored.batch_start == metadata.batch_start
        assert restored.batch_end == metadata.batch_end
        assert restored.old_state_root == metadata.old_state_root
        assert restored.new_state_root == metadata.new_state_root
        assert restored.public_inputs == metadata.public_inputs


# =============================================================================
# MockProver Tests
# =============================================================================


class TestMockProver:
    """Tests for MockProver."""
    
    def test_generate_proof(self, mock_prover, sample_state_roots, sample_transactions):
        """Mock prover should generate proof."""
        metadata, error = mock_prover.generate_proof(
            batch_start=0,
            batch_end=99,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            transactions=sample_transactions,
        )
        
        assert error == ""
        assert metadata is not None
        assert metadata.batch_start == 0
        assert metadata.batch_end == 99
        assert len(metadata.proof) == 256  # Mock proof size
        assert not metadata.verified
    
    def test_verify_mock_proof(self, mock_prover, sample_state_roots, sample_transactions):
        """Mock prover should verify its own proofs."""
        metadata, _ = mock_prover.generate_proof(
            batch_start=0,
            batch_end=99,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            transactions=sample_transactions,
        )
        
        is_valid, error = mock_prover.verify_proof(metadata)
        
        assert is_valid
        assert error == "Mock verification passed"
        assert metadata.verified
    
    def test_proofs_generated_counter(self, mock_prover, sample_state_roots):
        """Counter should increment with each proof."""
        assert mock_prover.proofs_generated == 0
        
        for i in range(3):
            mock_prover.generate_proof(
                batch_start=i * 100,
                batch_end=(i + 1) * 100 - 1,
                old_state_root=sample_state_roots["old"],
                new_state_root=sample_state_roots["new"],
                transactions=[],
            )
        
        assert mock_prover.proofs_generated == 3
    
    def test_proof_id_deterministic(self, mock_prover, sample_state_roots):
        """Same inputs should produce same proof ID."""
        txs = [b"tx1", b"tx2"]
        
        m1, _ = mock_prover.generate_proof(
            batch_start=0, batch_end=99,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            transactions=txs,
        )
        m2, _ = mock_prover.generate_proof(
            batch_start=0, batch_end=99,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            transactions=txs,
        )
        
        assert m1.proof_id == m2.proof_id
        assert m1.batch_hash == m2.batch_hash


# =============================================================================
# ProverManager Tests
# =============================================================================


class TestProverManager:
    """Tests for ProverManager."""
    
    def test_should_prove(self, prover_manager):
        """Should prove when batch size reached."""
        # Batch size is 10
        assert not prover_manager.should_prove(current_block=5, last_proven_block=0)
        assert prover_manager.should_prove(current_block=10, last_proven_block=0)
        assert prover_manager.should_prove(current_block=15, last_proven_block=5)
    
    def test_generate_batch_proof(self, prover_manager, sample_state_roots, sample_transactions):
        """Manager should generate and store proofs."""
        metadata, error = prover_manager.generate_batch_proof(
            batch_start=0,
            batch_end=9,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            transactions=sample_transactions,
        )
        
        assert error == ""
        assert metadata is not None
        assert len(prover_manager.proof_history) == 1
    
    def test_get_latest_proof(self, prover_manager, sample_state_roots):
        """Should return most recent proof."""
        # Generate two proofs
        prover_manager.generate_batch_proof(
            batch_start=0, batch_end=9,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            transactions=[],
        )
        prover_manager.generate_batch_proof(
            batch_start=10, batch_end=19,
            old_state_root=sample_state_roots["new"],
            new_state_root=sha256(b"newer_state"),
            transactions=[],
        )
        
        latest = prover_manager.get_latest_proof()
        assert latest.batch_start == 10
        assert latest.batch_end == 19
    
    def test_get_proof_by_range(self, prover_manager, sample_state_roots):
        """Should find proof by block number."""
        prover_manager.generate_batch_proof(
            batch_start=0, batch_end=9,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            transactions=[],
        )
        prover_manager.generate_batch_proof(
            batch_start=10, batch_end=19,
            old_state_root=sample_state_roots["new"],
            new_state_root=sha256(b"newer"),
            transactions=[],
        )
        
        proof = prover_manager.get_proof_by_range(5)
        assert proof is not None
        assert proof.batch_start == 0
        
        proof = prover_manager.get_proof_by_range(15)
        assert proof is not None
        assert proof.batch_start == 10
        
        proof = prover_manager.get_proof_by_range(25)
        assert proof is None
    
    def test_stats(self, prover_manager, sample_state_roots):
        """Stats should reflect current state."""
        prover_manager.generate_batch_proof(
            batch_start=0, batch_end=9,
            old_state_root=sample_state_roots["old"],
            new_state_root=sample_state_roots["new"],
            transactions=[],
        )
        
        stats = prover_manager.stats()
        assert stats["proofs_generated"] == 1
        assert stats["use_mock"] is True
        assert stats["batch_size"] == 10
        assert stats["latest_batch_end"] == 9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
