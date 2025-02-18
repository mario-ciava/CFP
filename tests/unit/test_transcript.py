"""
Tests for PoseidonMerkle Tree and Transcript.

Tests cover:
1. Tree construction and updates
2. Merkle proof generation and verification
3. Transcript building
"""

import pytest
from cfp.core.auction.transcript import (
    PoseidonMerkleTree,
    TranscriptBuilder,
    compute_merkle_root,
    verify_merkle_inclusion,
    EMPTY_LEAF,
)


class TestPoseidonMerkleTree:
    """Tests for PoseidonMerkle tree."""
    
    def test_tree_initialization(self):
        """Should initialize with correct depth."""
        tree = PoseidonMerkleTree(depth=3)
        
        assert tree.depth == 3
        assert tree.capacity == 8
        assert len(tree.leaves) == 8
    
    def test_tree_root_deterministic(self):
        """Same leaves should produce same root."""
        tree1 = PoseidonMerkleTree(depth=2, leaves=[1, 2, 3, 4])
        tree2 = PoseidonMerkleTree(depth=2, leaves=[1, 2, 3, 4])
        
        assert tree1.root == tree2.root
    
    def test_tree_root_changes_on_update(self):
        """Root should change when leaf is updated."""
        tree = PoseidonMerkleTree(depth=2, leaves=[1, 2, 3, 4])
        old_root = tree.root
        
        tree.update(0, 100)
        
        assert tree.root != old_root
    
    def test_insert_and_retrieve(self):
        """Should insert and retrieve values."""
        tree = PoseidonMerkleTree(depth=3)
        
        idx = tree.insert(12345)
        
        assert idx == 0
        assert tree.leaves[0] == 12345
    
    def test_insert_multiple(self):
        """Should insert multiple values at consecutive indices."""
        tree = PoseidonMerkleTree(depth=3)
        
        idx1 = tree.insert(100)
        idx2 = tree.insert(200)
        idx3 = tree.insert(300)
        
        assert idx1 == 0
        assert idx2 == 1
        assert idx3 == 2
        assert tree.num_leaves == 3


class TestMerkleProof:
    """Tests for Merkle proof generation and verification."""
    
    def test_proof_generation(self):
        """Should generate proof of correct length."""
        tree = PoseidonMerkleTree(depth=3, leaves=[1, 2, 3, 4, 5, 6, 7, 8])
        
        proof = tree.get_proof(0)
        
        assert len(proof) == 3  # depth = 3
    
    def test_proof_verification_valid(self):
        """Valid proof should verify."""
        tree = PoseidonMerkleTree(depth=3, leaves=[1, 2, 3, 4, 5, 6, 7, 8])
        
        leaf = tree.leaves[0]
        proof = tree.get_proof(0)
        
        assert tree.verify_proof(leaf, 0, proof)
    
    def test_proof_verification_all_indices(self):
        """Proof should verify for all leaf indices."""
        tree = PoseidonMerkleTree(depth=3, leaves=[1, 2, 3, 4, 5, 6, 7, 8])
        
        for i in range(8):
            leaf = tree.leaves[i]
            proof = tree.get_proof(i)
            assert tree.verify_proof(leaf, i, proof), f"Failed for index {i}"
    
    def test_proof_verification_wrong_leaf(self):
        """Wrong leaf should not verify."""
        tree = PoseidonMerkleTree(depth=3, leaves=[1, 2, 3, 4, 5, 6, 7, 8])
        
        proof = tree.get_proof(0)
        
        assert not tree.verify_proof(9999, 0, proof)  # Wrong leaf value
    
    def test_proof_verification_wrong_index(self):
        """Wrong index should not verify."""
        tree = PoseidonMerkleTree(depth=3, leaves=[1, 2, 3, 4, 5, 6, 7, 8])
        
        leaf = tree.leaves[0]
        proof = tree.get_proof(0)
        
        assert not tree.verify_proof(leaf, 1, proof)  # Wrong index
    
    def test_proof_with_path_bits(self):
        """Should return path bits indicating side."""
        tree = PoseidonMerkleTree(depth=3, leaves=[1, 2, 3, 4, 5, 6, 7, 8])
        
        siblings, path_bits = tree.get_proof_with_path(5)  # index 5 = binary 101
        
        assert len(siblings) == 3
        assert len(path_bits) == 3
        assert path_bits == [1, 0, 1]  # LSB first


class TestComputeMerkleRoot:
    """Tests for convenience root computation."""
    
    def test_compute_root_basic(self):
        """Should compute root from leaves."""
        leaves = [1, 2, 3, 4]
        root = compute_merkle_root(leaves)
        
        assert isinstance(root, int)
        assert root > 0
    
    def test_compute_root_deterministic(self):
        """Same leaves should produce same root."""
        leaves = [1, 2, 3, 4]
        
        root1 = compute_merkle_root(leaves)
        root2 = compute_merkle_root(leaves)
        
        assert root1 == root2
    
    def test_compute_root_empty(self):
        """Empty leaves should return empty leaf."""
        root = compute_merkle_root([])
        assert root == EMPTY_LEAF


class TestVerifyMerkleInclusion:
    """Tests for standalone verification."""
    
    def test_verify_inclusion_valid(self):
        """Valid inclusion should verify."""
        tree = PoseidonMerkleTree(depth=3, leaves=[1, 2, 3, 4, 5, 6, 7, 8])
        
        leaf = tree.leaves[3]
        proof = tree.get_proof(3)
        root = tree.root
        
        assert verify_merkle_inclusion(leaf, 3, proof, root)
    
    def test_verify_inclusion_invalid_root(self):
        """Should reject wrong root."""
        tree = PoseidonMerkleTree(depth=3, leaves=[1, 2, 3, 4, 5, 6, 7, 8])
        
        leaf = tree.leaves[3]
        proof = tree.get_proof(3)
        
        assert not verify_merkle_inclusion(leaf, 3, proof, 9999)


class TestTranscriptBuilder:
    """Tests for transcript building."""
    
    def test_transcript_creation(self):
        """Should create transcript with entries."""
        transcript = TranscriptBuilder(intent_id=12345)
        
        idx1 = transcript.add_entry(solver_id=1, commitment=100, timestamp=1000)
        idx2 = transcript.add_entry(solver_id=2, commitment=200, timestamp=1001)
        
        assert idx1 == 0
        assert idx2 == 1
        assert len(transcript.entries) == 2
    
    def test_transcript_root_changes(self):
        """Root should change as entries are added."""
        transcript = TranscriptBuilder(intent_id=12345)
        
        root0 = transcript.root
        transcript.add_entry(solver_id=1, commitment=100, timestamp=1000)
        root1 = transcript.root
        transcript.add_entry(solver_id=2, commitment=200, timestamp=1001)
        root2 = transcript.root
        
        assert root1 != root0
        assert root2 != root1
    
    def test_transcript_root_deterministic(self):
        """Same entries should produce same root."""
        t1 = TranscriptBuilder(intent_id=12345)
        t1.add_entry(solver_id=1, commitment=100, timestamp=1000)
        t1.add_entry(solver_id=2, commitment=200, timestamp=1000)
        
        t2 = TranscriptBuilder(intent_id=12345)
        t2.add_entry(solver_id=1, commitment=100, timestamp=1000)
        t2.add_entry(solver_id=2, commitment=200, timestamp=1000)
        
        assert t1.root == t2.root
    
    def test_transcript_entry_proof(self):
        """Should generate valid proof for entry."""
        transcript = TranscriptBuilder(intent_id=12345)
        transcript.add_entry(solver_id=1, commitment=100, timestamp=1000)
        idx = transcript.add_entry(solver_id=2, commitment=200, timestamp=1001)
        
        leaf, proof = transcript.get_entry_proof(idx)
        
        assert verify_merkle_inclusion(leaf, idx, proof, transcript.root)
    
    def test_transcript_finalize(self):
        """Finalize should return root."""
        transcript = TranscriptBuilder(intent_id=12345)
        transcript.add_entry(solver_id=1, commitment=100, timestamp=1000)
        
        final_root = transcript.finalize()
        
        assert final_root == transcript.root


class TestTranscriptLeafComputation:
    """Tests for transcript leaf hashing."""
    
    def test_leaf_deterministic(self):
        """Same inputs should produce same leaf."""
        leaf1 = TranscriptBuilder.compute_leaf(
            intent_id=1, solver_id=2, commitment=3, timestamp_bucket=4
        )
        leaf2 = TranscriptBuilder.compute_leaf(
            intent_id=1, solver_id=2, commitment=3, timestamp_bucket=4
        )
        
        assert leaf1 == leaf2
    
    def test_leaf_different_inputs(self):
        """Different inputs should produce different leaves."""
        leaf1 = TranscriptBuilder.compute_leaf(1, 2, 3, 4)
        leaf2 = TranscriptBuilder.compute_leaf(1, 2, 3, 5)  # Different timestamp
        
        assert leaf1 != leaf2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
