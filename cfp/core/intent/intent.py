"""
Intent Layer - User intents and execution tickets for CFP.

The intent layer enables users to express desired outcomes rather than
exact transactions. Solvers compete in auctions to fulfill intents.
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
# Intent
# =============================================================================


@dataclass
class Intent:
    """
    A user's intent for execution.
    
    Represents a desired outcome rather than an exact transaction.
    Solvers compete to fulfill intents via auction.
    
    Attributes:
        intent_id: Unique identifier
        user: User's address (20 bytes)
        intent_type: Type of intent
        conditions: JSON-serialized conditions
        max_fee: Maximum fee willing to pay
        deadline_block: Must be executed by this block
        signature: User's signature
        created_at: Creation timestamp
    """
    user: bytes                     # 20 bytes
    intent_type: IntentType
    conditions: bytes               # Serialized conditions
    max_fee: int
    deadline_block: int
    signature: bytes = field(default=b"")
    intent_id: bytes = field(default=b"")
    created_at: int = field(default_factory=lambda: int(time.time()))
    
    def compute_content_bytes(self) -> bytes:
        """Compute canonical bytes for hashing."""
        return (
            self.user +
            self.intent_type.to_bytes(1, "big") +
            len(self.conditions).to_bytes(4, "big") +
            self.conditions +
            self.max_fee.to_bytes(8, "big") +
            self.deadline_block.to_bytes(8, "big") +
            self.created_at.to_bytes(8, "big")
        )
    
    def compute_intent_id(self) -> bytes:
        """Compute unique intent ID."""
        return sha256(self.compute_content_bytes())
    
    def sign(self, private_key: bytes) -> None:
        """Sign the intent."""
        content_hash = self.compute_intent_id()
        self.signature = sign(content_hash, private_key)
        self.intent_id = content_hash
    
    def verify_signature(self, public_key: bytes) -> bool:
        """Verify intent signature."""
        content_hash = self.compute_intent_id()
        return verify(content_hash, self.signature, public_key)
    
    def is_expired(self, current_block: int) -> bool:
        """Check if intent has expired."""
        return current_block > self.deadline_block
    
    def __repr__(self) -> str:
        iid = bytes_to_hex(self.intent_id)[:10] + "..." if self.intent_id else "unsigned"
        return f"Intent(id={iid}, type={self.intent_type.name}, max_fee={self.max_fee})"


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
    """
    intent_id: bytes
    solver: bytes           # 20 bytes
    fee_bid: int            # Fee paying to user/protocol
    bond: int               # Staked amount
    signature: bytes = b""
    
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
) -> Intent:
    """
    Create and sign a new intent.
    
    Args:
        user_address: User's address
        intent_type: Type of intent
        conditions: Intent conditions as dict
        max_fee: Maximum fee
        deadline_block: Execution deadline
        private_key: User's private key for signing
        
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
    )
    intent.sign(private_key)
    return intent
