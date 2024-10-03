"""
UTXO - Unspent Transaction Output for CFP.

Conceptual Background:
---------------------
A UTXO represents a discrete unit of value that can be spent exactly once.

Unlike the account model (Ethereum) where state is a mapping of balances,
UTXO model represents state as a set of unspent outputs. This design:

1. Eliminates shared state contention - each UTXO is independent
2. Enables parallelism - non-conflicting spends don't interfere
3. Simplifies double-spend detection - same UTXO can't be spent twice
4. Is ZK-friendly - prove local knowledge without global state access

UTXO Lifecycle:
--------------
1. Created as output of a transaction
2. Exists in UTXO set (spendable)
3. Referenced as input in new transaction
4. Nullifier published, UTXO "logically spent"
5. Cannot be spent again (nullifier check fails)

Commitment Scheme:
-----------------
We use commitments for the Merkle tree to enable future privacy features:
    commitment = hash(value || owner || salt)

The commitment hides the actual values while allowing:
- Merkle proofs of inclusion
- ZK proofs of ownership and value
"""

from dataclasses import dataclass, field
from typing import Optional

from cfp.crypto import sha256, keccak256, bytes_to_hex


# =============================================================================
# UTXO Dataclass
# =============================================================================


@dataclass
class UTXO:
    """
    An Unspent Transaction Output.
    
    Represents a discrete, spendable unit of value in the CFP ledger.
    
    Attributes:
        tx_hash: Hash of the transaction that created this UTXO
        output_index: Index within the transaction's outputs (0-255)
        value: Amount of tokens
        owner: 20-byte address (recipient)
        salt: 32-byte randomness for commitment blinding
    """
    tx_hash: bytes       # 32 bytes
    output_index: int    # 0-255
    value: int           # Token amount (must be > 0)
    owner: bytes         # 20 bytes (address)
    salt: bytes          # 32 bytes (randomness)
    
    def __post_init__(self):
        """Validate field constraints."""
        if len(self.tx_hash) != 32:
            raise ValueError(f"tx_hash must be 32 bytes, got {len(self.tx_hash)}")
        if not (0 <= self.output_index <= 255):
            raise ValueError(f"output_index must be 0-255, got {self.output_index}")
        if self.value <= 0:
            raise ValueError(f"value must be positive, got {self.value}")
        if len(self.owner) != 20:
            raise ValueError(f"owner must be 20 bytes, got {len(self.owner)}")
        if len(self.salt) != 32:
            raise ValueError(f"salt must be 32 bytes, got {len(self.salt)}")
    
    # =========================================================================
    # Cryptographic Operations
    # =========================================================================
    
    def compute_commitment(self) -> bytes:
        """
        Compute the commitment for this UTXO.
        
        commitment = SHA256(value || owner || salt)
        
        This is what gets stored in the Merkle tree.
        The commitment hides the actual value while enabling proofs.
        """
        value_bytes = self.value.to_bytes(8, byteorder="big")
        return sha256(value_bytes + self.owner + self.salt)
    
    def compute_nullifier(self, owner_private_key: bytes) -> bytes:
        """
        Compute the nullifier for spending this UTXO.
        
        nullifier = SHA256(commitment || private_key)
        
        Only the owner (with private key) can compute this.
        Publishing the nullifier marks the UTXO as spent.
        
        Args:
            owner_private_key: 32-byte private key of the owner
            
        Returns:
            32-byte nullifier
        """
        if len(owner_private_key) != 32:
            raise ValueError("Private key must be 32 bytes")
        
        commitment = self.compute_commitment()
        return sha256(commitment + owner_private_key)
    
    @property
    def utxo_id(self) -> bytes:
        """
        Unique identifier for this UTXO.
        
        utxo_id = tx_hash || output_index
        
        Used for referencing in transaction inputs.
        """
        return self.tx_hash + self.output_index.to_bytes(1, byteorder="big")
    
    # =========================================================================
    # Serialization
    # =========================================================================
    
    def to_bytes(self) -> bytes:
        """
        Serialize UTXO to bytes.
        
        Format: tx_hash(32) || output_index(1) || value(8) || owner(20) || salt(32)
        Total: 93 bytes
        """
        return (
            self.tx_hash +
            self.output_index.to_bytes(1, byteorder="big") +
            self.value.to_bytes(8, byteorder="big") +
            self.owner +
            self.salt
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "UTXO":
        """Deserialize UTXO from bytes."""
        if len(data) != 93:
            raise ValueError(f"UTXO data must be 93 bytes, got {len(data)}")
        
        offset = 0
        tx_hash = data[offset:offset + 32]
        offset += 32
        output_index = data[offset]
        offset += 1
        value = int.from_bytes(data[offset:offset + 8], byteorder="big")
        offset += 8
        owner = data[offset:offset + 20]
        offset += 20
        salt = data[offset:offset + 32]
        
        return cls(
            tx_hash=tx_hash,
            output_index=output_index,
            value=value,
            owner=owner,
            salt=salt,
        )
    
    # =========================================================================
    # String Representation
    # =========================================================================
    
    def __repr__(self) -> str:
        tx = bytes_to_hex(self.tx_hash)[:10] + "..."
        owner = bytes_to_hex(self.owner)[:10] + "..."
        return f"UTXO(tx={tx}, idx={self.output_index}, value={self.value}, owner={owner})"
    
    def __hash__(self) -> int:
        return hash(self.utxo_id)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UTXO):
            return False
        return self.utxo_id == other.utxo_id


# =============================================================================
# Factory Functions
# =============================================================================


def create_utxo(
    tx_hash: bytes,
    output_index: int,
    value: int,
    owner_address: bytes,
    salt: Optional[bytes] = None,
) -> UTXO:
    """
    Create a new UTXO.
    
    Args:
        tx_hash: Transaction hash that creates this UTXO
        output_index: Output index within transaction
        value: Token value
        owner_address: 20-byte owner address
        salt: Optional 32-byte salt (random if not provided)
        
    Returns:
        UTXO instance
    """
    import secrets
    
    if salt is None:
        salt = secrets.token_bytes(32)
    
    return UTXO(
        tx_hash=tx_hash,
        output_index=output_index,
        value=value,
        owner=owner_address,
        salt=salt,
    )


def address_from_public_key(public_key: bytes) -> bytes:
    """
    Derive address from public key (Ethereum-style).
    
    address = keccak256(public_key)[-20:]
    
    Args:
        public_key: 64-byte public key
        
    Returns:
        20-byte address
    """
    if len(public_key) != 64:
        raise ValueError("Public key must be 64 bytes")
    return keccak256(public_key)[-20:]
