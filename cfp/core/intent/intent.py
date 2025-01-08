"""
Intent Layer - User intents and execution tickets for CFP.

The intent layer enables users to express desired outcomes rather than
exact transactions. Solvers compete in auctions to fulfill intents.

This module supports two modes:
- Legacy mode: SHA-256 based intent_id (backward compatible)
- ZK mode: Poseidon-based intent_id (for ZK circuits)

See spec/intent.md for the formal specification.
"""

import time
import secrets
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Any

from cfp.crypto import sha256, sign, verify, bytes_to_hex
from cfp.utils.logger import get_logger

logger = get_logger("intent")


# =============================================================================
# Enums
# =============================================================================


class IntentType(IntEnum):
    """Types of intents supported."""
    TRANSFER = 0      # Simple token transfer
    SWAP = 1          # Token swap
    CUSTOM = 2        # Custom intent with conditions


class TicketStatus(IntEnum):
    """Status of an execution ticket."""
    PENDING = 0       # Awaiting execution
    EXECUTED = 1      # Successfully executed
    EXPIRED = 2       # Deadline passed
    SLASHED = 3       # Solver slashed


# =============================================================================
# Constants
# =============================================================================

# Default chain ID for the prototype
DEFAULT_CHAIN_ID = 1

# Flag to control whether to use Poseidon (ZK-friendly) or SHA-256 (legacy)
USE_POSEIDON_INTENT_ID = True


# =============================================================================
# Intent
# =============================================================================


@dataclass
class Intent:
    """
    A user's intent for execution.
    
    Represents a desired outcome rather than an exact transaction.
    Solvers compete to fulfill intents via auction.
    
    Attributes:
        user: User's public key (64 bytes) or address (20 bytes)
        intent_type: Type of intent
        conditions: Serialized conditions (JSON bytes)
        max_fee: Maximum fee willing to pay
        deadline_block: Must be executed by this block
        nonce: Unique per-user counter to prevent replay
        chain_id: Chain identifier
        signature: User's signature
        intent_id: Unique identifier (computed)
        created_at: Creation timestamp
    """
    user: bytes                     # 64 bytes (pubkey) or 20 bytes (address)
    intent_type: IntentType
    conditions: bytes               # Serialized conditions
    max_fee: int
    deadline_block: int
    nonce: int = field(default_factory=lambda: secrets.randbelow(2**64))
    chain_id: int = field(default=DEFAULT_CHAIN_ID)
    signature: bytes = field(default=b"")
    intent_id: bytes = field(default=b"")
    created_at: int = field(default_factory=lambda: int(time.time()))
    
    def compute_content_bytes(self) -> bytes:
        """
        Compute canonical bytes for hashing.
        
        Used for legacy SHA-256 based intent_id.
        """
        return (
            self.user +
            self.intent_type.to_bytes(1, "big") +
            len(self.conditions).to_bytes(4, "big") +
            self.conditions +
            self.max_fee.to_bytes(8, "big") +
            self.deadline_block.to_bytes(8, "big") +
            self.nonce.to_bytes(8, "big") +
            self.chain_id.to_bytes(8, "big") +
            self.created_at.to_bytes(8, "big")
        )
    
    def compute_constraints_hash(self) -> int:
        """
        Compute Poseidon hash of constraints.
        
        Returns constraints_hash as field element for ZK circuits.
        """
        from cfp.crypto import poseidon_bytes
        return poseidon_bytes(self.conditions)
    
    def compute_intent_id_poseidon(self) -> bytes:
        """
        Compute intent_id using Poseidon hash (ZK-friendly).
        
        intent_id = Poseidon(domain, user_pk_hash, nonce, constraints_hash, deadline, chain_id)
        
        Returns 32-byte intent_id.
        """
        from cfp.crypto import hash_intent_id, int_to_bytes32
        
        constraints_hash = self.compute_constraints_hash()
        
        intent_id_int = hash_intent_id(
            user_pubkey=self.user if len(self.user) == 64 else self.user.ljust(64, b'\x00'),
            nonce=self.nonce,
            constraints_hash=constraints_hash,
            deadline=self.deadline_block,
            chain_id=self.chain_id
        )
        
        return int_to_bytes32(intent_id_int)
    
    def compute_intent_id_sha256(self) -> bytes:
        """
        Compute intent_id using SHA-256 (legacy, backward compatible).
        """
        return sha256(self.compute_content_bytes())
    
    def compute_intent_id(self) -> bytes:
        """
        Compute unique intent ID.
        
        Uses Poseidon if USE_POSEIDON_INTENT_ID is True, otherwise SHA-256.
        """
        if USE_POSEIDON_INTENT_ID:
            return self.compute_intent_id_poseidon()
        else:
            return self.compute_intent_id_sha256()
    
    def intent_id_as_int(self) -> int:
        """
        Get intent_id as a field element (for use in scoring/circuits).
        """
        from cfp.crypto import bytes32_to_int, FIELD_PRIME
        if not self.intent_id:
            self.intent_id = self.compute_intent_id()
        
        val = int.from_bytes(self.intent_id, 'big')
        return val % FIELD_PRIME
    
    def sign(self, private_key: bytes) -> None:
        """Sign the intent."""
        # Always use SHA-256 for the signature hash (ECDSA compatibility)
        content_hash = sha256(self.compute_content_bytes())
        self.signature = sign(content_hash, private_key)
        # But store Poseidon-based intent_id
        self.intent_id = self.compute_intent_id()
    
    def verify_signature(self, public_key: bytes) -> bool:
        """Verify intent signature."""
        content_hash = sha256(self.compute_content_bytes())
        return verify(content_hash, self.signature, public_key)
    
    def is_expired(self, current_block: int) -> bool:
        """Check if intent has expired."""
        return current_block > self.deadline_block
    
    def __repr__(self) -> str:
        iid = bytes_to_hex(self.intent_id)[:10] + "..." if self.intent_id else "unsigned"
        return f"Intent(id={iid}, type={self.intent_type.name}, max_fee={self.max_fee})"


# =============================================================================
# Typed Constraints
# =============================================================================


@dataclass
class TransferConstraints:
    """Constraints for a transfer intent."""
    recipient: bytes     # 20 bytes
    amount: int
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return (
            self.recipient +
            self.amount.to_bytes(8, "big")
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "TransferConstraints":
        """Deserialize from bytes."""
        return cls(
            recipient=data[:20],
            amount=int.from_bytes(data[20:28], "big")
        )
    
    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        return {
            "recipient": "0x" + self.recipient.hex(),
            "amount": self.amount
        }


@dataclass
class SwapConstraints:
    """Constraints for a swap intent."""
    asset_in: bytes      # 20 bytes (token address)
    asset_out: bytes     # 20 bytes
    max_in: int          # Maximum input amount
    min_out: int         # Minimum output amount
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return (
            self.asset_in +
            self.asset_out +
            self.max_in.to_bytes(8, "big") +
            self.min_out.to_bytes(8, "big")
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "SwapConstraints":
        """Deserialize from bytes."""
        return cls(
            asset_in=data[:20],
            asset_out=data[20:40],
            max_in=int.from_bytes(data[40:48], "big"),
            min_out=int.from_bytes(data[48:56], "big")
        )
    
    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        return {
            "asset_in": "0x" + self.asset_in.hex(),
            "asset_out": "0x" + self.asset_out.hex(),
            "max_in": self.max_in,
            "min_out": self.min_out
        }


# =============================================================================
# Execution Ticket
# =============================================================================


@dataclass
class ExecutionTicket:
    """
    Right to execute an intent.
    
    Issued to winning solver in auction. Solver must execute
    within deadline or lose their bond.
    
    Attributes:
        ticket_id: Unique identifier
        intent_id: Intent being executed
        solver: Solver's address
        fee_bid: Fee solver will pay
        bond: Amount staked
        deadline_block: Execute by this block
        status: Current status
    """
    intent_id: bytes
    solver: bytes                   # 20 bytes
    fee_bid: int
    bond: int
    deadline_block: int
    status: TicketStatus = TicketStatus.PENDING
    ticket_id: bytes = field(default=b"")
    created_at: int = field(default_factory=lambda: int(time.time()))
    executed_at: Optional[int] = None
    execution_tx: Optional[bytes] = None
    
    def __post_init__(self):
        if not self.ticket_id:
            self.ticket_id = sha256(
                self.intent_id +
                self.solver +
                self.fee_bid.to_bytes(8, "big") +
                self.created_at.to_bytes(8, "big")
            )
    
    def is_expired(self, current_block: int) -> bool:
        """Check if ticket has expired."""
        return current_block > self.deadline_block and self.status == TicketStatus.PENDING
    
    def mark_executed(self, tx_hash: bytes) -> None:
        """Mark ticket as executed."""
        self.status = TicketStatus.EXECUTED
        self.executed_at = int(time.time())
        self.execution_tx = tx_hash
    
    def mark_slashed(self) -> None:
        """Mark ticket as slashed (solver failed)."""
        self.status = TicketStatus.SLASHED
    
    def __repr__(self) -> str:
        tid = bytes_to_hex(self.ticket_id)[:10] + "..."
        return f"Ticket(id={tid}, fee={self.fee_bid}, status={self.status.name})"


# =============================================================================
# Solver Bid
# =============================================================================


@dataclass
class SolverBid:
    """
    A solver's bid in an intent auction.
    
    For the commit-reveal auction, see cfp.core.auction.commit_reveal.
    """
    intent_id: bytes
    solver: bytes           # 20 bytes
    fee_bid: int            # Fee paying to user/protocol
    bond: int               # Staked amount
    signature: bytes = b""
    
    @property
    def solver_id(self) -> int:
        """Get solver_id as integer for scoring."""
        from cfp.crypto import poseidon_bytes
        return poseidon_bytes(self.solver)
    
    @property
    def fee_offered(self) -> int:
        """Alias for fee_bid (for scoring compatibility)."""
        return self.fee_bid
    
    def sign(self, private_key: bytes) -> None:
        """Sign the bid."""
        content = self.intent_id + self.solver + self.fee_bid.to_bytes(8, "big") + self.bond.to_bytes(8, "big")
        self.signature = sign(sha256(content), private_key)


# =============================================================================
# Factory Functions
# =============================================================================


def create_intent(
    user_address: bytes,
    intent_type: IntentType,
    conditions: dict,
    max_fee: int,
    deadline_block: int,
    private_key: bytes,
    nonce: Optional[int] = None,
    chain_id: int = DEFAULT_CHAIN_ID,
) -> Intent:
    """
    Create and sign a new intent.
    
    Args:
        user_address: User's address (20 bytes) or public key (64 bytes)
        intent_type: Type of intent
        conditions: Intent conditions as dict
        max_fee: Maximum fee
        deadline_block: Execution deadline
        private_key: User's private key for signing
        nonce: Optional nonce (random if not provided)
        chain_id: Chain identifier
        
    Returns:
        Signed Intent
    """
    import json
    
    intent = Intent(
        user=user_address,
        intent_type=intent_type,
        conditions=json.dumps(conditions).encode(),
        max_fee=max_fee,
        deadline_block=deadline_block,
        nonce=nonce if nonce is not None else secrets.randbelow(2**64),
        chain_id=chain_id,
    )
    intent.sign(private_key)
    return intent


def create_transfer_intent(
    user_pubkey: bytes,
    recipient: bytes,
    amount: int,
    max_fee: int,
    deadline_block: int,
    private_key: bytes,
    nonce: Optional[int] = None,
) -> Intent:
    """
    Create a transfer intent with typed constraints.
    
    Args:
        user_pubkey: User's public key (64 bytes)
        recipient: Recipient address (20 bytes)
        amount: Amount to transfer
        max_fee: Maximum fee
        deadline_block: Execution deadline
        private_key: User's private key
        nonce: Optional nonce
        
    Returns:
        Signed Intent
    """
    constraints = TransferConstraints(recipient=recipient, amount=amount)
    
    intent = Intent(
        user=user_pubkey,
        intent_type=IntentType.TRANSFER,
        conditions=constraints.to_bytes(),
        max_fee=max_fee,
        deadline_block=deadline_block,
        nonce=nonce if nonce is not None else secrets.randbelow(2**64),
    )
    intent.sign(private_key)
    return intent


def create_swap_intent(
    user_pubkey: bytes,
    asset_in: bytes,
    asset_out: bytes,
    max_in: int,
    min_out: int,
    max_fee: int,
    deadline_block: int,
    private_key: bytes,
    nonce: Optional[int] = None,
) -> Intent:
    """
    Create a swap intent with typed constraints.
    
    Args:
        user_pubkey: User's public key (64 bytes)
        asset_in: Input token address (20 bytes)
        asset_out: Output token address (20 bytes)
        max_in: Maximum input amount
        min_out: Minimum output amount
        max_fee: Maximum fee
        deadline_block: Execution deadline
        private_key: User's private key
        nonce: Optional nonce
        
    Returns:
        Signed Intent
    """
    constraints = SwapConstraints(
        asset_in=asset_in,
        asset_out=asset_out,
        max_in=max_in,
        min_out=min_out
    )
    
    intent = Intent(
        user=user_pubkey,
        intent_type=IntentType.SWAP,
        conditions=constraints.to_bytes(),
        max_fee=max_fee,
        deadline_block=deadline_block,
        nonce=nonce if nonce is not None else secrets.randbelow(2**64),
    )
    intent.sign(private_key)
    return intent
