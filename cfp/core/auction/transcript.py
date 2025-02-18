"""
PoseidonMerkle Tree - ZK-friendly Merkle tree using Poseidon hash.

This module provides a Merkle tree implementation that uses Poseidon
hash function instead of SHA-256, making it suitable for use in 
ZK circuits (low constraint count).

Key differences from SHA-256 Merkle:
- Uses Poseidon(left, right) instead of SHA256(left || right)
- Leaf/node values are field elements, not byte arrays
- Tree structure optimized for circuit verification

See also: cfp/core/state/merkle.py for the SHA-256 version.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from cfp.crypto import poseidon2, FIELD_PRIME
from cfp.utils.logger import get_logger

logger = get_logger("poseidon_merkle")


# =============================================================================
# Constants
# =============================================================================

# Domain separator for Merkle operations
DOMAIN_MERKLE_LEAF = 0x20
DOMAIN_MERKLE_NODE = 0x21

# Empty leaf value (hash of 0)
EMPTY_LEAF = poseidon2(DOMAIN_MERKLE_LEAF, 0)


# =============================================================================
# Poseidon Merkle Tree
# =============================================================================


@dataclass
class PoseidonMerkleTree:
    """
    A Merkle tree using Poseidon hash function.
    
    Designed for ZK circuit compatibility.
    
    Attributes:
        depth: Tree depth (2^depth leaves)
        leaves: List of leaf values (field elements)
        nodes: Internal nodes (computed from leaves)
    """
    depth: int
    leaves: List[int] = field(default_factory=list)
    nodes: List[List[int]] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize tree structure."""
        self.capacity = 2 ** self.depth
        
        # Initialize empty leaves
        if not self.leaves:
            self.leaves = [EMPTY_LEAF] * self.capacity
        
        # Pad leaves to capacity
        while len(self.leaves) < self.capacity:
            self.leaves.append(EMPTY_LEAF)
        
        # Build initial tree
        self._rebuild()
    
    def _rebuild(self) -> None:
        """Rebuild the entire tree from leaves."""
        self.nodes = [self.leaves.copy()]
        
        # Build levels from bottom up
        for level in range(self.depth):
            prev_level = self.nodes[level]
            current_level = []
            
            for i in range(0, len(prev_level), 2):
                left = prev_level[i]
                right = prev_level[i + 1] if i + 1 < len(prev_level) else EMPTY_LEAF
                parent = self._hash_pair(left, right)
                current_level.append(parent)
            
            self.nodes.append(current_level)
        
        logger.debug(f"Built PoseidonMerkle tree: depth={self.depth}, root={self.root}")
    
    @staticmethod
    def _hash_pair(left: int, right: int) -> int:
        """Hash two children to produce parent node."""
        return poseidon2(left, right)
    
    @staticmethod
    def hash_leaf(value: int) -> int:
        """Hash a leaf value with domain separation."""
        return poseidon2(DOMAIN_MERKLE_LEAF, value)
    
    @property
    def root(self) -> int:
        """Get the Merkle root."""
        if not self.nodes:
            return EMPTY_LEAF
        return self.nodes[-1][0] if self.nodes[-1] else EMPTY_LEAF
    
    @property
    def num_leaves(self) -> int:
        """Number of non-empty leaves."""
        return sum(1 for leaf in self.leaves if leaf != EMPTY_LEAF)
    
    def insert(self, value: int) -> int:
        """
        Insert a value at the next available position.
        
        Args:
            value: Field element to insert
            
        Returns:
            Index where value was inserted
        """
        # Find first empty slot
        for i, leaf in enumerate(self.leaves):
            if leaf == EMPTY_LEAF:
                self.update(i, value)
                return i
        
        raise ValueError("Tree is full")
    
    def update(self, index: int, value: int) -> None:
        """
        Update a leaf at specific index.
        
        Args:
            index: Leaf index
            value: New value (field element)
        """
        if index < 0 or index >= self.capacity:
            raise IndexError(f"Index {index} out of range [0, {self.capacity})")
        
        if value < 0 or value >= FIELD_PRIME:
            raise ValueError(f"Value {value} out of field range")
        
        # Update leaf
        self.leaves[index] = value
        self.nodes[0][index] = value
        
        # Recompute path to root
        idx = index
        for level in range(self.depth):
            sibling_idx = idx ^ 1  # Toggle last bit to get sibling
            left_idx = min(idx, sibling_idx)
            
            left = self.nodes[level][left_idx]
            right = self.nodes[level][left_idx + 1] if left_idx + 1 < len(self.nodes[level]) else EMPTY_LEAF
            
            parent_idx = idx // 2
            parent = self._hash_pair(left, right)
            self.nodes[level + 1][parent_idx] = parent
            
            idx = parent_idx
    
    def get_proof(self, index: int) -> List[int]:
        """
        Get Merkle proof (authentication path) for a leaf.
        
        Args:
            index: Leaf index
            
        Returns:
            List of sibling hashes from leaf to root
        """
        if index < 0 or index >= self.capacity:
            raise IndexError(f"Index {index} out of range")
        
        proof = []
        idx = index
        
        for level in range(self.depth):
            sibling_idx = idx ^ 1  # Toggle last bit
            sibling = self.nodes[level][sibling_idx] if sibling_idx < len(self.nodes[level]) else EMPTY_LEAF
            proof.append(sibling)
            idx = idx // 2
        
        return proof
    
    def get_proof_with_path(self, index: int) -> Tuple[List[int], List[int]]:
        """
        Get Merkle proof with path indicators.
        
        Args:
            index: Leaf index
            
        Returns:
            (siblings, path_bits) where path_bits[i] = 1 if leaf is on right
        """
        proof = self.get_proof(index)
        path_bits = [(index >> i) & 1 for i in range(self.depth)]
        return proof, path_bits
    
    def verify_proof(self, leaf: int, index: int, proof: List[int]) -> bool:
        """
        Verify a Merkle proof.
        
        Args:
            leaf: Leaf value
            index: Leaf index
            proof: Sibling path from leaf to root
            
        Returns:
            True if proof is valid
        """
        if len(proof) != self.depth:
            return False
        
        current = leaf
        idx = index
        
        for sibling in proof:
            if idx & 1:  # Current node is on right
                current = self._hash_pair(sibling, current)
            else:  # Current node is on left
                current = self._hash_pair(current, sibling)
            idx = idx >> 1
        
        return current == self.root
    
    def get_leaves(self) -> List[int]:
        """Get all non-empty leaves."""
        return [leaf for leaf in self.leaves if leaf != EMPTY_LEAF]


# =============================================================================
# Transcript Builder
# =============================================================================


@dataclass
class TranscriptBuilder:
    """
    Builds a transcript of auction bids for binding commitment.
    
    The transcript is a Merkle tree of all bid commitments,
    enabling ZK proof that winner selection considered all bids.
    
    Each leaf: Poseidon(domain, intent_id, solver_id, commitment, timestamp_bucket)
    """
    intent_id: int
    tree: PoseidonMerkleTree = field(default=None)
    entries: List[Tuple[int, int, int]] = field(default_factory=list)  # (solver_id, commitment, timestamp)
    
    def __post_init__(self):
        if self.tree is None:
            # Default to depth 4 (16 entries max, typically K=4 or K=8)
            self.tree = PoseidonMerkleTree(depth=4)
    
    @staticmethod
    def compute_leaf(intent_id: int, solver_id: int, commitment: int, timestamp_bucket: int) -> int:
        """
        Compute transcript leaf hash.
        
        Uses domain-separated Poseidon chain.
        """
        from cfp.crypto import hash_transcript_leaf
        return hash_transcript_leaf(intent_id, solver_id, commitment, timestamp_bucket)
    
    def add_entry(
        self,
        solver_id: int,
        commitment: int,
        timestamp: int,
        bucket_size: int = 100,  # Group timestamps into buckets
    ) -> int:
        """
        Add a bid entry to the transcript.
        
        Args:
            solver_id: Solver's ID
            commitment: Bid commitment
            timestamp: Timestamp (will be bucketed)
            bucket_size: Size of timestamp buckets
            
        Returns:
            Index in transcript
        """
        timestamp_bucket = timestamp // bucket_size
        
        leaf = self.compute_leaf(
            self.intent_id,
            solver_id,
            commitment,
            timestamp_bucket
        )
        
        index = self.tree.insert(leaf)
        self.entries.append((solver_id, commitment, timestamp))
        
        logger.debug(f"Added transcript entry: solver={solver_id}, idx={index}")
        return index
    
    @property
    def root(self) -> int:
        """Get transcript Merkle root."""
        return self.tree.root
    
    def get_entry_proof(self, index: int) -> Tuple[int, List[int]]:
        """
        Get proof for an entry.
        
        Returns:
            (leaf_value, merkle_proof)
        """
        leaf = self.tree.leaves[index]
        proof = self.tree.get_proof(index)
        return leaf, proof
    
    def finalize(self) -> int:
        """
        Finalize the transcript.
        
        Returns the final root hash.
        """
        logger.info(f"Transcript finalized: {len(self.entries)} entries, root={self.root}")
        return self.root


# =============================================================================
# Convenience Functions
# =============================================================================


def compute_merkle_root(leaves: List[int]) -> int:
    """
    Compute Merkle root from a list of leaves.
    
    Automatically determines depth based on number of leaves.
    """
    if not leaves:
        return EMPTY_LEAF
    
    # Determine depth needed
    import math
    depth = max(1, math.ceil(math.log2(len(leaves))))
    
    tree = PoseidonMerkleTree(depth=depth, leaves=leaves)
    return tree.root


def verify_merkle_inclusion(
    leaf: int,
    index: int,
    proof: List[int],
    root: int,
) -> bool:
    """
    Verify Merkle inclusion proof.
    
    Standalone verification without full tree.
    """
    current = leaf
    idx = index
    
    for sibling in proof:
        if idx & 1:
            current = poseidon2(sibling, current)
        else:
            current = poseidon2(current, sibling)
        idx = idx >> 1
    
    return current == root


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "PoseidonMerkleTree",
    "TranscriptBuilder",
    "compute_merkle_root",
    "verify_merkle_inclusion",
    "EMPTY_LEAF",
    "DOMAIN_MERKLE_LEAF",
    "DOMAIN_MERKLE_NODE",
]
