"""
Tests for Poseidon hash implementation.

These tests verify:
1. Basic functionality of Poseidon hash
2. Determinism (same inputs = same outputs)
3. Domain separation (different domains = different hashes)
4. CFP-specific hash functions
"""

import pytest
from cfp.crypto import (
    poseidon_hash,
    poseidon1,
    poseidon2,
    poseidon_bytes,
    poseidon_bytes_to_bytes,
    int_to_bytes32,
    bytes32_to_int,
    FIELD_PRIME,
    hash_intent_id,
    hash_solver_commit,
    hash_nullifier,
    hash_utxo_commitment,
    hash_transcript_leaf,
    hash_tie_break,
    DOMAIN_INTENT_ID,
    DOMAIN_SOLVER_COMMIT,
)


class TestPoseidonBasic:
    """Basic Poseidon hash tests."""
    
    def test_poseidon2_deterministic(self):
        """Same inputs always produce same output."""
        h1 = poseidon2(1, 2)
        h2 = poseidon2(1, 2)
        assert h1 == h2
    
    def test_poseidon2_different_inputs(self):
        """Different inputs produce different outputs."""
        h1 = poseidon2(1, 2)
        h2 = poseidon2(2, 1)
        h3 = poseidon2(1, 3)
        assert h1 != h2
        assert h1 != h3
        assert h2 != h3
    
    def test_poseidon1(self):
        """Single input hash works."""
        h = poseidon1(42)
        assert isinstance(h, int)
        assert 0 <= h < FIELD_PRIME
    
    def test_poseidon_output_in_field(self):
        """Output is always in the field."""
        for i in range(100):
            h = poseidon2(i, i * 2)
            assert 0 <= h < FIELD_PRIME
    
    def test_poseidon_domain_separation(self):
        """Different domains produce different hashes."""
        h1 = poseidon_hash([1, 2], domain_sep=0)
        h2 = poseidon_hash([1, 2], domain_sep=1)
        h3 = poseidon_hash([1, 2], domain_sep=DOMAIN_INTENT_ID)
        assert h1 != h2
        assert h1 != h3


class TestPoseidonBytes:
    """Tests for bytes hashing."""
    
    def test_poseidon_bytes_basic(self):
        """Bytes hashing works."""
        h = poseidon_bytes(b"hello world")
        assert isinstance(h, int)
        assert 0 <= h < FIELD_PRIME
    
    def test_poseidon_bytes_deterministic(self):
        """Same bytes always produce same hash."""
        h1 = poseidon_bytes(b"test data")
        h2 = poseidon_bytes(b"test data")
        assert h1 == h2
    
    def test_poseidon_bytes_different(self):
        """Different bytes produce different hashes."""
        h1 = poseidon_bytes(b"hello")
        h2 = poseidon_bytes(b"world")
        assert h1 != h2
    
    def test_poseidon_bytes_to_bytes(self):
        """Bytes to bytes returns 32-byte output."""
        result = poseidon_bytes_to_bytes(b"test")
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_poseidon_empty_bytes(self):
        """Empty bytes produces valid hash."""
        h = poseidon_bytes(b"")
        assert isinstance(h, int)
        assert 0 <= h < FIELD_PRIME


class TestFieldConversion:
    """Tests for field element conversion."""
    
    def test_int_to_bytes32(self):
        """Integer to bytes conversion."""
        result = int_to_bytes32(12345)
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_bytes32_to_int(self):
        """Bytes to integer conversion."""
        original = 12345
        as_bytes = int_to_bytes32(original)
        recovered = bytes32_to_int(as_bytes)
        assert recovered == original
    
    def test_bytes32_roundtrip(self):
        """Roundtrip conversion preserves value."""
        for val in [0, 1, 12345, FIELD_PRIME - 1]:
            recovered = bytes32_to_int(int_to_bytes32(val))
            assert recovered == val
    
    def test_bytes32_wrong_length(self):
        """Wrong length bytes raises error."""
        with pytest.raises(ValueError):
            bytes32_to_int(b"short")
    
    def test_bytes32_exceeds_field(self):
        """Value exceeding field raises error."""
        too_large = (FIELD_PRIME + 1).to_bytes(32, "big")
        with pytest.raises(ValueError):
            bytes32_to_int(too_large)


class TestCFPHashFunctions:
    """Tests for CFP-specific hash functions."""
    
    def test_hash_intent_id(self):
        """Intent ID hash works."""
        intent_id = hash_intent_id(
            user_pubkey=b"x" * 64,
            nonce=12345,
            constraints_hash=999,
            deadline=100000,
            chain_id=1
        )
        assert isinstance(intent_id, int)
        assert 0 <= intent_id < FIELD_PRIME
    
    def test_hash_intent_id_deterministic(self):
        """Same inputs produce same intent ID."""
        id1 = hash_intent_id(b"pub" * 21 + b"k", 1, 100, 1000, 1)
        id2 = hash_intent_id(b"pub" * 21 + b"k", 1, 100, 1000, 1)
        assert id1 == id2
    
    def test_hash_intent_id_different_nonce(self):
        """Different nonce produces different ID."""
        id1 = hash_intent_id(b"x" * 64, nonce=1, constraints_hash=100, deadline=1000, chain_id=1)
        id2 = hash_intent_id(b"x" * 64, nonce=2, constraints_hash=100, deadline=1000, chain_id=1)
        assert id1 != id2
    
    def test_hash_solver_commit(self):
        """Solver commitment hash works."""
        commit = hash_solver_commit(
            intent_id=12345,
            solver_id=67890,
            score=100,
            solution_hash=999,
            salt=42
        )
        assert isinstance(commit, int)
        assert 0 <= commit < FIELD_PRIME
    
    def test_hash_solver_commit_different_salt(self):
        """Different salt produces different commitment."""
        c1 = hash_solver_commit(1, 2, 100, 999, salt=1)
        c2 = hash_solver_commit(1, 2, 100, 999, salt=2)
        assert c1 != c2
    
    def test_hash_nullifier(self):
        """Nullifier hash works."""
        nullifier = hash_nullifier(
            nullifier_key=12345,
            merkle_path_index=5
        )
        assert isinstance(nullifier, int)
        assert 0 <= nullifier < FIELD_PRIME
    
    def test_hash_utxo_commitment(self):
        """UTXO commitment hash works."""
        commitment = hash_utxo_commitment(
            amount=1000,
            pubkey_hash=12345,
            salt=67890
        )
        assert isinstance(commitment, int)
        assert 0 <= commitment < FIELD_PRIME
    
    def test_hash_transcript_leaf(self):
        """Transcript leaf hash works."""
        leaf = hash_transcript_leaf(
            intent_id=1,
            solver_id=2,
            commitment=3,
            timestamp_bucket=4
        )
        assert isinstance(leaf, int)
        assert 0 <= leaf < FIELD_PRIME
    
    def test_hash_tie_break(self):
        """Tie-break hash works."""
        tie = hash_tie_break(
            epoch_seed=12345,
            intent_id=67890,
            solver_id=11111
        )
        assert isinstance(tie, int)
        assert 0 <= tie < FIELD_PRIME
    
    def test_hash_tie_break_deterministic(self):
        """Tie-break is deterministic for same inputs."""
        t1 = hash_tie_break(100, 200, 300)
        t2 = hash_tie_break(100, 200, 300)
        assert t1 == t2
    
    def test_hash_tie_break_different_solver(self):
        """Different solver produces different tie-break."""
        t1 = hash_tie_break(100, 200, 300)
        t2 = hash_tie_break(100, 200, 301)
        assert t1 != t2


class TestPoseidonEdgeCases:
    """Edge case tests."""
    
    def test_poseidon_zero_inputs(self):
        """Zero inputs work correctly."""
        h = poseidon2(0, 0)
        assert isinstance(h, int)
        assert h != 0  # Hash of zeros is not zero
    
    def test_poseidon_max_field_element(self):
        """Maximum field element minus 1 works."""
        max_val = FIELD_PRIME - 1
        h = poseidon2(max_val, 0)
        assert isinstance(h, int)
        assert 0 <= h < FIELD_PRIME
    
    def test_poseidon_out_of_range_raises(self):
        """Input >= field prime raises error."""
        with pytest.raises(ValueError):
            poseidon2(FIELD_PRIME, 0)
    
    def test_poseidon_negative_raises(self):
        """Negative input raises error."""
        with pytest.raises(ValueError):
            poseidon2(-1, 0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
