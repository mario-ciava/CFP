"""
Unit tests for escape hatch mechanism.

The escape hatch ensures a minimum percentage of block space is reserved
for raw transactions that bypass the intent auction system.
"""

import pytest

from cfp.core.dag import Vertex, PayloadType
from cfp.core.escape_hatch import EscapeHatchValidator, BlockValidationResult


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
    
    def test_metadata_only_block(self):
        """Block with only metadata (no transactions) should be valid."""
        validator = EscapeHatchValidator(min_quota=0.10)
        
        vertices = [
            Vertex(
                timestamp=1000,
                parents=[],
                payload=b"checkpoint",
                payload_type=PayloadType.METADATA,
                creator=bytes(64),
            )
        ]
        
        result = validator.validate_block(vertices)
        assert result.is_valid
        assert result.raw_percentage == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
