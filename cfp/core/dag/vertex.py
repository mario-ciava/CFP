"""
DAG Vertex - The atomic unit of the Convergent Flow Protocol DAG.

Conceptual Background:
---------------------
A Vertex is analogous to a "block" in traditional blockchains, but lighter and
designed for partial ordering. Unlike blocks that form a linear chain, vertices
form a Directed Acyclic Graph (DAG) where:

1. Multiple vertices can be created in parallel
2. Each vertex references one or more parent vertices
3. The DAG captures causal relationships between transactions
4. A deterministic linearization algorithm produces a total order for execution

Vertex Structure:
----------------
- vertex_id: Content-addressed hash (immutable identifier)
- timestamp: Unix timestamp (used for tie-breaking in linearization)
- parents: List of parent vertex IDs (captures causality)
- payload: Raw data (transactions, intents, or metadata)
- payload_type: Discriminator for payload interpretation
- creator: Public key of the vertex creator
- signature: ECDSA signature over the vertex content

Design Decisions:
----------------
- Content-addressed: vertex_id = hash(timestamp || parents || payload || creator)
  This makes vertices immutable and verifiable.
  
- Multiple parents: Allows merging of parallel branches, increasing throughput.
  We enforce MIN_PARENTS=1, MAX_PARENTS=5 to balance parallelism and complexity.
  
- Payload types: Support heterogeneous content in the same DAG:
  - TRANSACTION: Raw token transfers
  - INTENT: User intents for solver auction
  - CHECKPOINT: ZK prover checkpoints
  - METADATA: Protocol metadata (governance, parameters)
"""

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional

from cfp.crypto import sha256, sign, verify, bytes_to_hex, hex_to_bytes


# =============================================================================
# Constants
# =============================================================================

# Parent constraints
MIN_PARENTS = 1  # Minimum parents required (except genesis)
MAX_PARENTS = 5  # Maximum parents allowed

# Timestamp constraints
MAX_FUTURE_DELTA_SECONDS = 5  # Max seconds a vertex can be in the future

# Genesis vertex ID (well-known constant)
GENESIS_VERTEX_ID = bytes(32)  # 32 zero bytes


# =============================================================================
# Payload Types
# =============================================================================


class PayloadType(IntEnum):
    """
    Discriminator for vertex payload content.
    
    Each type has different validation and execution semantics:
    - TRANSACTION: Validated by UTXO ledger, affects token balances
    - INTENT: Processed by solver auction, may become transactions
    - CHECKPOINT: Created by ZK prover, contains proof metadata
    - METADATA: Protocol-level data (governance, config updates)
    """
    TRANSACTION = 0
    INTENT = 1
    CHECKPOINT = 2
    METADATA = 3


# =============================================================================
# Vertex Dataclass
# =============================================================================


@dataclass
class Vertex:
    """
    A vertex in the CFP DAG.
    
    Immutable after creation (vertex_id is computed from content).
    
    Attributes:
        timestamp: Unix timestamp (seconds since epoch)
        parents: List of parent vertex IDs (32-byte hashes)
        payload: Raw payload data
        payload_type: Type discriminator for payload
        creator: 64-byte public key of creator
        signature: 64-byte ECDSA signature
        vertex_id: 32-byte content hash (computed, not set directly)
    """
    timestamp: int
    parents: List[bytes]
    payload: bytes
    payload_type: PayloadType
    creator: bytes  # 64-byte public key
    signature: bytes = field(default=b"")  # Set after signing
    vertex_id: bytes = field(default=b"")  # Computed from content
    
    def __post_init__(self):
        """Validate field types and lengths."""
        if not isinstance(self.parents, list):
            self.parents = list(self.parents)
        
        # Validate each parent is 32 bytes
        for i, parent in enumerate(self.parents):
            if len(parent) != 32:
                raise ValueError(f"Parent {i} must be 32 bytes, got {len(parent)}")
        
        # Validate creator length
        if len(self.creator) != 64:
            raise ValueError(f"Creator public key must be 64 bytes, got {len(self.creator)}")
    
    # =========================================================================
    # Content Hash (Vertex ID)
    # =========================================================================
    
    def compute_content_bytes(self) -> bytes:
        """
        Compute the canonical byte representation for hashing.
        
        Format: timestamp(8) || num_parents(1) || parents(32*n) || 
                payload_type(1) || payload_len(4) || payload || creator(64)
        
        This is the data that gets hashed and signed.
        """
        parts = []
        
        # Timestamp: 8 bytes big-endian
        parts.append(self.timestamp.to_bytes(8, byteorder="big"))
        
        # Number of parents: 1 byte
        parts.append(len(self.parents).to_bytes(1, byteorder="big"))
        
        # Parents: sorted for determinism, 32 bytes each
        for parent in sorted(self.parents):
            parts.append(parent)
        
        # Payload type: 1 byte
        parts.append(self.payload_type.to_bytes(1, byteorder="big"))
        
        # Payload length: 4 bytes big-endian
        parts.append(len(self.payload).to_bytes(4, byteorder="big"))
        
        # Payload
        parts.append(self.payload)
        
        # Creator public key: 64 bytes
        parts.append(self.creator)
        
        return b"".join(parts)
    
    def compute_vertex_id(self) -> bytes:
        """
        Compute the vertex ID (content hash).
        
        vertex_id = SHA256(content_bytes)
        
        This is the unique, content-addressed identifier for this vertex.
        """
        return sha256(self.compute_content_bytes())
    
    # =========================================================================
    # Signing and Verification
    # =========================================================================
    
    def sign(self, private_key: bytes) -> None:
        """
        Sign the vertex with the given private key.
        
        Sets both the signature and vertex_id fields.
        
        Args:
            private_key: 32-byte private key (must correspond to self.creator)
        """
        content_hash = self.compute_vertex_id()
        self.signature = sign(content_hash, private_key)
        self.vertex_id = content_hash
    
    def verify_signature(self) -> bool:
        """
        Verify that the signature is valid for the vertex content.
        
        Returns:
            True if signature is valid and was created by self.creator
        """
        if len(self.signature) != 64:
            return False
        
        content_hash = self.compute_vertex_id()
        return verify(content_hash, self.signature, self.creator)
    
    def verify_vertex_id(self) -> bool:
        """
        Verify that the stored vertex_id matches the computed hash.
        
        Returns:
            True if vertex_id is correct
        """
        return self.vertex_id == self.compute_vertex_id()
    
    # =========================================================================
    # Validation
    # =========================================================================
    
    def is_genesis(self) -> bool:
        """Check if this is the genesis vertex (no parents)."""
        return len(self.parents) == 0
    
    def validate_structure(self) -> tuple[bool, str]:
        """
        Validate the structural correctness of the vertex.
        
        Checks:
        1. Parent count within bounds (0 for genesis, 1-5 otherwise)
        2. Timestamp not too far in the future
        3. Signature is valid
        4. Vertex ID is correct
        
        Returns:
            (is_valid, error_message)
        """
        # Check parent count
        if not self.is_genesis():
            if len(self.parents) < MIN_PARENTS:
                return False, f"Must have at least {MIN_PARENTS} parent(s)"
            if len(self.parents) > MAX_PARENTS:
                return False, f"Must have at most {MAX_PARENTS} parent(s)"
        
        # Check timestamp not in future
        now = int(time.time())
        if self.timestamp > now + MAX_FUTURE_DELTA_SECONDS:
            return False, f"Timestamp too far in future: {self.timestamp} > {now + MAX_FUTURE_DELTA_SECONDS}"
        
        # Check vertex ID
        if self.vertex_id and not self.verify_vertex_id():
            return False, "Vertex ID does not match content hash"
        
        # Check signature
        if self.signature and not self.verify_signature():
            return False, "Invalid signature"
        
        return True, ""
    
    # =========================================================================
    # Serialization
    # =========================================================================
    
    def to_bytes(self) -> bytes:
        """
        Serialize vertex to bytes for storage/transmission.
        
        Format:
            vertex_id(32) || signature(64) || content_bytes
        """
        parts = []
        parts.append(self.vertex_id)
        parts.append(self.signature)
        parts.append(self.compute_content_bytes())
        return b"".join(parts)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "Vertex":
        """
        Deserialize vertex from bytes.
        
        Args:
            data: Serialized vertex bytes
            
        Returns:
            Vertex instance
        """
        offset = 0
        
        # vertex_id: 32 bytes
        vertex_id = data[offset:offset + 32]
        offset += 32
        
        # signature: 64 bytes
        signature = data[offset:offset + 64]
        offset += 64
        
        # timestamp: 8 bytes
        timestamp = int.from_bytes(data[offset:offset + 8], byteorder="big")
        offset += 8
        
        # num_parents: 1 byte
        num_parents = data[offset]
        offset += 1
        
        # parents: 32 bytes each
        parents = []
        for _ in range(num_parents):
            parents.append(data[offset:offset + 32])
            offset += 32
        
        # payload_type: 1 byte
        payload_type = PayloadType(data[offset])
        offset += 1
        
        # payload_len: 4 bytes
        payload_len = int.from_bytes(data[offset:offset + 4], byteorder="big")
        offset += 4
        
        # payload
        payload = data[offset:offset + payload_len]
        offset += payload_len
        
        # creator: 64 bytes
        creator = data[offset:offset + 64]
        
        return cls(
            timestamp=timestamp,
            parents=parents,
            payload=payload,
            payload_type=payload_type,
            creator=creator,
            signature=signature,
            vertex_id=vertex_id,
        )
    
    # =========================================================================
    # String Representation
    # =========================================================================
    
    def __repr__(self) -> str:
        vid = bytes_to_hex(self.vertex_id)[:10] + "..." if self.vertex_id else "None"
        return f"Vertex(id={vid}, parents={len(self.parents)}, type={self.payload_type.name})"
    
    def __hash__(self) -> int:
        return hash(self.vertex_id)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Vertex):
            return False
        return self.vertex_id == other.vertex_id


# =============================================================================
# Factory Functions
# =============================================================================


def create_genesis_vertex(creator_keypair) -> Vertex:
    """
    Create the genesis vertex (first vertex in DAG).
    
    The genesis vertex:
    - Has no parents (empty list)
    - Has payload type METADATA
    - Contains protocol initialization data
    
    Args:
        creator_keypair: KeyPair for signing the genesis
        
    Returns:
        Signed genesis Vertex
    """
    genesis = Vertex(
        timestamp=int(time.time()),
        parents=[],  # Genesis has no parents
        payload=b"CFP Genesis Block",
        payload_type=PayloadType.METADATA,
        creator=creator_keypair.public_key,
    )
    genesis.sign(creator_keypair.private_key)
    return genesis


def create_vertex(
    parents: List[bytes],
    payload: bytes,
    payload_type: PayloadType,
    creator_keypair,
) -> Vertex:
    """
    Create a new vertex referencing the given parents.
    
    Args:
        parents: List of parent vertex IDs (1-5 items)
        payload: Raw payload data
        payload_type: Type of payload
        creator_keypair: KeyPair for signing
        
    Returns:
        Signed Vertex
        
    Raises:
        ValueError: If parent count is invalid
    """
    if len(parents) < MIN_PARENTS:
        raise ValueError(f"Must have at least {MIN_PARENTS} parent(s)")
    if len(parents) > MAX_PARENTS:
        raise ValueError(f"Must have at most {MAX_PARENTS} parent(s)")
    
    vertex = Vertex(
        timestamp=int(time.time()),
        parents=parents,
        payload=payload,
        payload_type=payload_type,
        creator=creator_keypair.public_key,
    )
    vertex.sign(creator_keypair.private_key)
    return vertex
