"""
Simple Merkle Tree for state commitment.

Conceptual Background:
---------------------
A Merkle tree allows us to commit to the entire UTXO set with a single hash (the root),
while enabling efficient proofs of inclusion for individual UTXOs.

For this prototype, we implement an append-only Merkle tree:
- Leaves are UTXO commitments
- Never delete leaves (nullifiers track logical spending)
- Simple binary tree with SHA256

In production, you'd use a sparse Merkle tree or accumulator for efficiency.
This simplified version is sufficient for our single-node lab environment.

Properties:
----------
- Insert: O(log n)
- Root: O(1) (cached)
- Prove: O(log n)
- Verify: O(log n)
"""

from typing import List, Optional, Tuple
import math

from cfp.crypto import sha256


# =============================================================================
# Merkle Tree
# =============================================================================


class MerkleTree:
    """
    Simple append-only binary Merkle tree.
    
    Stores leaves and lazily computes internal nodes.
    Root is cached and recomputed on insert.
    
    Attributes:
        leaves: List of leaf values (32-byte hashes)
        nodes: Internal node cache
    """
    
    # Empty leaf placeholder (for incomplete trees)
    EMPTY_LEAF = bytes(32)
    
    def __init__(self):
        self.leaves: List[bytes] = []
        self._root_cache: Optional[bytes] = None
    
    @staticmethod
    def hash_pair(left: bytes, right: bytes) -> bytes:
        """Hash two nodes together."""
        return sha256(left + right)
    
    def insert(self, leaf: bytes) -> int:
        """
        Insert a new leaf into the tree.
        
        Args:
            leaf: 32-byte leaf value (e.g., UTXO commitment)
            
        Returns:
            Index of the inserted leaf
        """
        if len(leaf) != 32:
            raise ValueError("Leaf must be 32 bytes")
        
        index = len(self.leaves)
        self.leaves.append(leaf)
        self._root_cache = None  # Invalidate cache
        return index
    
    def root(self) -> bytes:
        """
        Get the Merkle root.
        
        Returns:
            32-byte root hash
        """
        if not self.leaves:
            return self.EMPTY_LEAF
        
        if self._root_cache is not None:
            return self._root_cache
        
        # Compute root from leaves
        self._root_cache = self._compute_root()
        return self._root_cache
    
    def _compute_root(self) -> bytes:
        """Compute root by hashing from leaves up."""
        if not self.leaves:
            return self.EMPTY_LEAF
        
        # Pad to power of 2
        n = len(self.leaves)
        next_pow2 = 1 << (n - 1).bit_length() if n > 1 else 1
        padded = list(self.leaves) + [self.EMPTY_LEAF] * (next_pow2 - n)
        
        # Build tree bottom-up
        layer = padded
        while len(layer) > 1:
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else self.EMPTY_LEAF
                next_layer.append(self.hash_pair(left, right))
            layer = next_layer
        
        return layer[0]
    
    def prove(self, leaf_index: int) -> List[Tuple[bytes, bool]]:
        """
        Generate Merkle proof for a leaf.
        
        Args:
            leaf_index: Index of the leaf to prove
            
        Returns:
            List of (sibling_hash, is_right) tuples.
            is_right=True means the sibling is on the right.
        """
        if leaf_index >= len(self.leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range")
        
        # Pad to power of 2
        n = len(self.leaves)
        next_pow2 = 1 << (n - 1).bit_length() if n > 1 else 1
        padded = list(self.leaves) + [self.EMPTY_LEAF] * (next_pow2 - n)
        
        proof = []
        layer = padded
        idx = leaf_index
        
        while len(layer) > 1:
            # Sibling index
            if idx % 2 == 0:
                sibling_idx = idx + 1
                is_right = True
            else:
                sibling_idx = idx - 1
                is_right = False
            
            if sibling_idx < len(layer):
                proof.append((layer[sibling_idx], is_right))
            else:
                proof.append((self.EMPTY_LEAF, is_right))
            
            # Move to next layer
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else self.EMPTY_LEAF
                next_layer.append(self.hash_pair(left, right))
            
            layer = next_layer
            idx = idx // 2
        
        return proof
    
    @classmethod
    def verify(
        cls,
        leaf: bytes,
        proof: List[Tuple[bytes, bool]],
        root: bytes,
    ) -> bool:
        """
        Verify a Merkle proof.
        
        Args:
            leaf: The leaf value being proven
            proof: List of (sibling, is_right) tuples
            root: Expected root hash
            
        Returns:
            True if proof is valid
        """
        current = leaf
        
        for sibling, is_right in proof:
            if is_right:
                current = cls.hash_pair(current, sibling)
            else:
                current = cls.hash_pair(sibling, current)
        
        return current == root
    
    def __len__(self) -> int:
        return len(self.leaves)
    
    def __contains__(self, leaf: bytes) -> bool:
        return leaf in self.leaves
    
    def get_leaf(self, index: int) -> bytes:
        """Get leaf at index."""
        return self.leaves[index]
