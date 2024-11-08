"""
Unit tests for escape hatch and storage.
"""

import pytest
from pathlib import Path
import tempfile

from cfp.core.dag import Vertex, PayloadType
from cfp.core.escape_hatch import EscapeHatchValidator, BlockValidationResult
from cfp.core.storage import PruningManager, MockArchivalNode, StorageManager
from cfp.crypto import sha256


# =============================================================================
# Escape Hatch Tests
# =============================================================================


class TestEscapeHatch:
    """Tests for escape hatch validator."""
    
    def test_empty_block_valid(self):
        """Empty block should be valid."""
        validator = EscapeHatchValidator(min_quota=0.10)
        result = validator.validate_block([])
        assert result.is_valid
    
    def test_quota_met(self):
        """Block meeting quota should be valid."""
        validator = EscapeHatchValidator(min_quota=0.10)
        
        # Create 2 raw txs and 8 intent txs (20% raw, meets 10% quota)
        vertices = []
        for i in range(2):
            v = Vertex(
                timestamp=1000,
                parents=[],
                payload=b"raw_tx",
                payload_type=PayloadType.TRANSACTION,
                creator=bytes(64),
            )
            vertices.append(v)
        for i in range(8):
            v = Vertex(
                timestamp=1000,
                parents=[],
                payload=b"intent",
                payload_type=PayloadType.INTENT,
                creator=bytes(64),
            )
            vertices.append(v)
        
        result = validator.validate_block(vertices)
        assert result.is_valid
        assert result.raw_tx_count == 2
        assert result.intent_tx_count == 8
        assert result.raw_percentage == 0.2
    
    def test_quota_not_met(self):
        """Block not meeting quota should be invalid."""
        validator = EscapeHatchValidator(min_quota=0.20)  # 20% quota
        
        # Create 1 raw tx and 9 intent txs (10% raw, fails 20% quota)
        vertices = []
        v = Vertex(
            timestamp=1000,
            parents=[],
            payload=b"raw",
            payload_type=PayloadType.TRANSACTION,
            creator=bytes(64),
        )
        vertices.append(v)
        
        for i in range(9):
            v = Vertex(
                timestamp=1000,
                parents=[],
                payload=b"intent",
                payload_type=PayloadType.INTENT,
                creator=bytes(64),
            )
            vertices.append(v)
        
        result = validator.validate_block(vertices)
        assert not result.is_valid
        assert "quota not met" in result.error


# =============================================================================
# Storage Tests
# =============================================================================


class TestPruning:
    """Tests for pruning manager."""
    
    def test_should_prune(self):
        """Should trigger pruning when above max blocks."""
        pruning = PruningManager(max_blocks=100)
        
        assert not pruning.should_prune(50)
        assert not pruning.should_prune(100)
        assert pruning.should_prune(101)
    
    def test_prune_height(self):
        """Should calculate correct prune height."""
        pruning = PruningManager(max_blocks=100)
        
        assert pruning.get_prune_height(150) == 50
        assert pruning.get_prune_height(200) == 100
    
    def test_prune_execution(self):
        """Should track pruned blocks."""
        pruning = PruningManager(max_blocks=10)
        
        deleted = []
        pruning.prune(15, lambda h: deleted.append(h))
        
        # Should prune blocks 0-4 (keep 5-14)
        assert len(deleted) == 5
        assert 0 in deleted
        assert 4 in deleted


class TestArchival:
    """Tests for mock archival node."""
    
    def test_archive_and_fetch(self):
        """Should archive and retrieve data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            archival = MockArchivalNode(Path(tmpdir))
            
            data = b"test block data"
            archival.archive_block(10, sha256(b"state"), data)
            
            fetched = archival.fetch_block(10)
            assert fetched == data
    
    def test_verify_archive(self):
        """Should verify data integrity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            archival = MockArchivalNode(Path(tmpdir))
            
            data = b"test block data"
            archival.archive_block(10, sha256(b"state"), data)
            
            # Correct hash
            assert archival.verify_archive(10, sha256(data))
            
            # Wrong hash
            assert not archival.verify_archive(10, sha256(b"wrong"))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
