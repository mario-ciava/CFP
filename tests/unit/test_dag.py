"""
Unit tests for DAG vertex and sequencer.

Tests cover:
1. Vertex creation and signing
2. Vertex validation
3. Serialization round-trips
4. DAG operations (add, linearize, tips)
5. Orphan handling
6. Deterministic ordering
"""

import pytest
import time

from cfp.crypto import generate_keypair, KeyPair
from cfp.core.dag import (
    Vertex,
    PayloadType,
    DAGSequencer,
    create_genesis_vertex,
    create_vertex,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def keypair() -> KeyPair:
    """Generate a test keypair."""
    return generate_keypair()


@pytest.fixture
def second_keypair() -> KeyPair:
    """Generate a second test keypair."""
    return generate_keypair()


@pytest.fixture
def sequencer():
    """Create an in-memory DAG sequencer."""
    return DAGSequencer(storage_manager=None)


@pytest.fixture
def sequencer_with_genesis(keypair):
    """Create a sequencer with genesis already added."""
    seq = DAGSequencer(storage_manager=None)
    genesis = create_genesis_vertex(keypair)
    seq.add_vertex(genesis)
    return seq, genesis


# =============================================================================
# Vertex Tests
# =============================================================================


class TestVertex:
    """Tests for Vertex creation, signing, and validation."""
    
    def test_create_genesis_vertex(self, keypair):
        """Genesis vertex should have no parents."""
        genesis = create_genesis_vertex(keypair)
        
        assert genesis.is_genesis()
        assert len(genesis.parents) == 0
        assert genesis.payload_type == PayloadType.METADATA
        assert len(genesis.vertex_id) == 32
        assert len(genesis.signature) == 64
    
    def test_vertex_signature_verification(self, keypair):
        """Signature should verify correctly."""
        genesis = create_genesis_vertex(keypair)
        
        assert genesis.verify_signature()
        assert genesis.verify_vertex_id()
    
    def test_vertex_id_is_content_addressed(self, keypair):
        """Same content should produce same vertex_id."""
        v1 = Vertex(
            timestamp=1000,
            parents=[],
            payload=b"test",
            payload_type=PayloadType.TRANSACTION,
            creator=keypair.public_key,
        )
        v2 = Vertex(
            timestamp=1000,
            parents=[],
            payload=b"test",
            payload_type=PayloadType.TRANSACTION,
            creator=keypair.public_key,
        )
        
        assert v1.compute_vertex_id() == v2.compute_vertex_id()
    
    def test_different_content_different_id(self, keypair):
        """Different content should produce different vertex_id."""
        v1 = Vertex(
            timestamp=1000,
            parents=[],
            payload=b"test1",
            payload_type=PayloadType.TRANSACTION,
            creator=keypair.public_key,
        )
        v2 = Vertex(
            timestamp=1000,
            parents=[],
            payload=b"test2",
            payload_type=PayloadType.TRANSACTION,
            creator=keypair.public_key,
        )
        
        assert v1.compute_vertex_id() != v2.compute_vertex_id()
    
    def test_vertex_with_parents(self, keypair):
        """Vertex with parents should validate correctly."""
        parent_id = bytes(32)  # Dummy parent
        
        vertex = Vertex(
            timestamp=int(time.time()),
            parents=[parent_id],
            payload=b"child",
            payload_type=PayloadType.TRANSACTION,
            creator=keypair.public_key,
        )
        vertex.sign(keypair.private_key)
        
        assert len(vertex.parents) == 1
        assert vertex.verify_signature()
    
    def test_serialization_roundtrip(self, keypair):
        """Vertex should survive serialization/deserialization."""
        original = create_genesis_vertex(keypair)
        
        # Serialize and deserialize
        data = original.to_bytes()
        restored = Vertex.from_bytes(data)
        
        assert restored.vertex_id == original.vertex_id
        assert restored.timestamp == original.timestamp
        assert restored.payload == original.payload
        assert restored.creator == original.creator
        assert restored.signature == original.signature
        assert restored.verify_signature()
    
    def test_invalid_signature_fails_verification(self, keypair, second_keypair):
        """Vertex signed with wrong key should fail verification."""
        vertex = Vertex(
            timestamp=int(time.time()),
            parents=[],
            payload=b"test",
            payload_type=PayloadType.METADATA,
            creator=keypair.public_key,  # Creator is keypair
        )
        # Sign with wrong key
        vertex.sign(second_keypair.private_key)
        
        # Signature won't verify because creator != signer
        assert not vertex.verify_signature()


# =============================================================================
# DAG Sequencer Tests
# =============================================================================


class TestDAGSequencer:
    """Tests for DAG sequencer operations."""
    
    def test_add_genesis(self, sequencer, keypair):
        """Should accept genesis vertex."""
        genesis = create_genesis_vertex(keypair)
        success, msg = sequencer.add_vertex(genesis)
        
        assert success
        assert sequencer.vertex_count() == 1
        assert sequencer.genesis_id == genesis.vertex_id
    
    def test_reject_duplicate_genesis(self, sequencer, keypair, second_keypair):
        """Should reject second genesis vertex."""
        g1 = create_genesis_vertex(keypair)
        g2 = create_genesis_vertex(second_keypair)
        
        sequencer.add_vertex(g1)
        success, msg = sequencer.add_vertex(g2)
        
        assert not success
        assert "Genesis already exists" in msg
    
    def test_add_child_vertex(self, sequencer_with_genesis, keypair):
        """Should accept vertex with valid parent."""
        seq, genesis = sequencer_with_genesis
        
        child = create_vertex(
            parents=[genesis.vertex_id],
            payload=b"child",
            payload_type=PayloadType.TRANSACTION,
            creator_keypair=keypair,
        )
        success, msg = seq.add_vertex(child)
        
        assert success
        assert seq.vertex_count() == 2
    
    def test_tips_update(self, sequencer_with_genesis, keypair):
        """Tips should update when children are added."""
        seq, genesis = sequencer_with_genesis
        
        # Genesis is initially the only tip
        assert seq.get_tips() == [genesis.vertex_id]
        
        # Add child
        child = create_vertex(
            parents=[genesis.vertex_id],
            payload=b"child",
            payload_type=PayloadType.TRANSACTION,
            creator_keypair=keypair,
        )
        seq.add_vertex(child)
        
        # Now child is the only tip
        assert seq.get_tips() == [child.vertex_id]
    
    def test_orphan_handling(self, sequencer_with_genesis, keypair):
        """Orphan should be queued and processed when parent arrives."""
        seq, genesis = sequencer_with_genesis
        
        # Create parent and child
        parent = create_vertex(
            parents=[genesis.vertex_id],
            payload=b"parent",
            payload_type=PayloadType.TRANSACTION,
            creator_keypair=keypair,
        )
        child = create_vertex(
            parents=[parent.vertex_id],
            payload=b"child",
            payload_type=PayloadType.TRANSACTION,
            creator_keypair=keypair,
        )
        
        # Add child BEFORE parent (simulating out-of-order network)
        success, msg = seq.add_vertex(child)
        assert success
        assert "Orphaned" in msg
        assert seq.orphan_count() == 1
        assert seq.vertex_count() == 1  # Only genesis in DAG
        
        # Now add parent
        seq.add_vertex(parent)
        
        # Orphan should be processed automatically
        assert seq.orphan_count() == 0
        assert seq.vertex_count() == 3  # genesis + parent + child
    
    def test_linearization_single_chain(self, sequencer_with_genesis, keypair):
        """Linearization of single chain should be in order."""
        seq, genesis = sequencer_with_genesis
        
        # Build a chain: genesis -> v1 -> v2 -> v3
        prev_id = genesis.vertex_id
        vertices = [genesis]
        
        for i in range(3):
            v = create_vertex(
                parents=[prev_id],
                payload=f"vertex_{i}".encode(),
                payload_type=PayloadType.TRANSACTION,
                creator_keypair=keypair,
            )
            seq.add_vertex(v)
            vertices.append(v)
            prev_id = v.vertex_id
        
        # Linearize
        order = seq.linearize()
        
        assert len(order) == 4
        # Should be in order: genesis, v1, v2, v3
        for i, vertex in enumerate(vertices):
            assert order[i] == vertex.vertex_id
    
    def test_linearization_parallel_branches(self, sequencer_with_genesis, keypair):
        """Linearization of parallel branches should be deterministic."""
        seq, genesis = sequencer_with_genesis
        
        # Create two parallel branches from genesis
        branch_a = create_vertex(
            parents=[genesis.vertex_id],
            payload=b"branch_a",
            payload_type=PayloadType.TRANSACTION,
            creator_keypair=keypair,
        )
        branch_b = create_vertex(
            parents=[genesis.vertex_id],
            payload=b"branch_b",
            payload_type=PayloadType.TRANSACTION,
            creator_keypair=keypair,
        )
        
        seq.add_vertex(branch_a)
        seq.add_vertex(branch_b)
        
        # Merge vertex
        merge = create_vertex(
            parents=[branch_a.vertex_id, branch_b.vertex_id],
            payload=b"merge",
            payload_type=PayloadType.TRANSACTION,
            creator_keypair=keypair,
        )
        seq.add_vertex(merge)
        
        # Linearize
        order = seq.linearize()
        
        assert len(order) == 4
        assert order[0] == genesis.vertex_id  # Genesis first
        assert order[3] == merge.vertex_id    # Merge last
        
        # Branch order should be deterministic (lower vertex_id first)
        concurrent = order[1:3]
        assert concurrent == sorted(concurrent)  # Lexicographic order
    
    def test_linearization_determinism(self, keypair):
        """Same DAG should produce same linearization every time."""
        # Create a single DAG
        seq = DAGSequencer(storage_manager=None)
        genesis = create_genesis_vertex(keypair)
        seq.add_vertex(genesis)
        
        # Add some concurrent vertices (both reference genesis)
        v1 = create_vertex([genesis.vertex_id], b"v1", PayloadType.TRANSACTION, keypair)
        v2 = create_vertex([genesis.vertex_id], b"v2", PayloadType.TRANSACTION, keypair)
        seq.add_vertex(v1)
        seq.add_vertex(v2)
        
        # Call linearize multiple times - should always return same order
        orders = [seq.linearize() for _ in range(5)]
        
        # All orders should be identical
        for order in orders[1:]:
            assert order == orders[0]
        
        # Concurrent vertices should be ordered by vertex_id (lexicographic)
        concurrent = orders[0][1:3]  # v1 and v2
        assert concurrent == sorted(concurrent), "Concurrent vertices should be ordered lexicographically"


# =============================================================================
# Crypto Tests (sanity checks)
# =============================================================================


class TestCrypto:
    """Basic crypto sanity tests."""
    
    def test_keypair_generation(self):
        """Should generate valid keypairs."""
        kp = generate_keypair()
        
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 64
        assert kp.address.startswith("0x")
        assert len(kp.address) == 42
    
    def test_keypairs_are_unique(self):
        """Each keypair should be unique."""
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        
        assert kp1.private_key != kp2.private_key
        assert kp1.public_key != kp2.public_key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
