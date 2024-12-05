"""
Unit tests for escape hatch module.

Tests cover:
1. Block validation
2. Raw transaction quota enforcement
3. Transaction prioritization
"""

import pytest

from cfp.crypto import generate_keypair
from cfp.core.escape_hatch import EscapeHatchValidator, BlockValidationResult
from cfp.core.dag import Vertex, PayloadType


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def validator():
    """10% minimum raw transaction quota."""
    return EscapeHatchValidator(min_quota=0.10)


def make_vertex(keypair, payload_type: PayloadType) -> Vertex:
    """Create a test vertex with given payload type."""
    v = Vertex(
        timestamp=1000,
        parents=[],
        payload=b"test",
        payload_type=payload_type,
        creator=keypair.public_key,
    )
    v.sign(keypair.private_key)
    return v


class TestEscapeHatchValidator:
    """Tests for escape hatch validation."""
    
    def test_empty_block_valid(self, validator):
        """Empty block should be valid."""
        result = validator.validate_block([])
        assert result.is_valid
        assert result.raw_percentage == 1.0
    
    def test_all_raw_valid(self, validator, keypair):
        """Block with all raw transactions should be valid."""
        vertices = [make_vertex(keypair, PayloadType.TRANSACTION) for _ in range(5)]
        result = validator.validate_block(vertices)
        
        assert result.is_valid
        assert result.raw_tx_count == 5
        assert result.intent_tx_count == 0
        assert result.raw_percentage == 1.0
    
    def test_mixed_above_quota_valid(self, validator, keypair):
        """Block with raw >= 10% should be valid."""
        # 2 raw + 8 intent = 20% raw
        vertices = [
            make_vertex(keypair, PayloadType.TRANSACTION),
            make_vertex(keypair, PayloadType.TRANSACTION),
            *[make_vertex(keypair, PayloadType.INTENT) for _ in range(8)],
        ]
        result = validator.validate_block(vertices)
        
        assert result.is_valid
        assert result.raw_percentage == 0.2
    
    def test_below_quota_invalid(self, validator, keypair):
        """Block with raw < 10% should be invalid."""
        # 0 raw + 10 intent = 0% raw
        vertices = [make_vertex(keypair, PayloadType.INTENT) for _ in range(10)]
        result = validator.validate_block(vertices)
        
        assert not result.is_valid
        assert "quota not met" in result.error
    
    def test_exactly_at_quota_valid(self, validator, keypair):
        """Block with exactly 10% raw should be valid."""
        # 1 raw + 9 intent = 10%
        vertices = [
            make_vertex(keypair, PayloadType.TRANSACTION),
            *[make_vertex(keypair, PayloadType.INTENT) for _ in range(9)],
        ]
        result = validator.validate_block(vertices)
        
        assert result.is_valid
        assert abs(result.raw_percentage - 0.1) < 0.01
    
    def test_metadata_only_valid(self, validator, keypair):
        """Block with only metadata vertices should be valid."""
        vertices = [make_vertex(keypair, PayloadType.METADATA) for _ in range(3)]
        result = validator.validate_block(vertices)
        
        assert result.is_valid  # No tx/intent means quota doesn't apply


class TestPrioritization:
    """Tests for transaction prioritization."""
    
    def test_prioritize_respects_quota(self, validator):
        """Prioritizer should include minimum raw transactions."""
        raw_txs = [b"raw1", b"raw2"]
        intent_txs = [b"intent" * 10 for _ in range(20)]
        
        selected_raw, selected_intent = validator.prioritize_transactions(
            raw_txs, intent_txs, max_size=1000
        )
        
        # Should include at least 10% raw
        assert len(selected_raw) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
