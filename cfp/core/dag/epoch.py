"""
Epoch - Batching and aggregation for ZK proofs.

An Epoch represents a batch of intents/transactions that are proven together.
This enables:
- Proof aggregation (single proof for many transactions)
- Ordered commitment of auction results
- Deterministic state transitions per epoch

Each epoch:
1. Collects intents during the collection window
2. Runs auctions and selects winners
3. Freezes the set for proof generation
4. Generates aggregated ZK proof
5. Commits to L1 (for based rollup)
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple, Set
import time

from cfp.crypto import poseidon_bytes, poseidon2
from cfp.utils.logger import get_logger

logger = get_logger("epoch")


# =============================================================================
# Constants
# =============================================================================

# Default epoch duration in blocks
DEFAULT_EPOCH_DURATION = 100

# Collection window (how long to accept intents)
DEFAULT_COLLECTION_WINDOW = 80

# Auction window (within collection)
DEFAULT_AUCTION_WINDOW = 60

# Domain separator for epoch seed
DOMAIN_EPOCH_SEED = 0x30


# =============================================================================
# Enums
# =============================================================================


class EpochStatus(IntEnum):
    """Status of an epoch."""
    COLLECTING = 0    # Accepting new intents
    AUCTIONING = 1    # Running auctions
    FROZEN = 2        # Set finalized, generating proofs
    PROVING = 3       # Proof generation in progress
    PROVEN = 4        # Proof generated
    COMMITTED = 5     # Committed to L1
    FAILED = 6        # Epoch failed (no valid intents)


# =============================================================================
# Data Structures
# =============================================================================


@dataclass
class EpochIntent:
    """An intent within an epoch."""
    intent_id: bytes
    intent: any  # Intent object
    auction_result: Optional[Tuple[int, int]] = None  # (winner_solver_id, score)
    proof_generated: bool = False


@dataclass
class Epoch:
    """
    A batch of intents processed together.
    
    Attributes:
        epoch_number: Sequential epoch identifier
        start_block: First block of this epoch
        end_block: Last block of this epoch
        status: Current epoch status
        intents: Intents in this epoch
        epoch_seed: Randomness for tie-breaks
        state_root_before: State Merkle root at epoch start
        state_root_after: State Merkle root after execution
        proof: Aggregated ZK proof (if generated)
    """
    epoch_number: int
    start_block: int
    end_block: int
    status: EpochStatus = EpochStatus.COLLECTING
    
    # Timing
    collection_end_block: int = 0
    auction_end_block: int = 0
    
    # Intents
    intents: Dict[bytes, EpochIntent] = field(default_factory=dict)
    execution_order: List[bytes] = field(default_factory=list)
    
    # Randomness
    epoch_seed: int = 0
    
    # State
    state_root_before: Optional[int] = None
    state_root_after: Optional[int] = None
    
    # Proof
    proof: Optional[dict] = None
    proof_public_signals: Optional[List[str]] = None
    
    # Metadata
    created_at: int = field(default_factory=lambda: int(time.time()))
    finalized_at: Optional[int] = None
    
    def __post_init__(self):
        """Initialize timing windows."""
        if self.collection_end_block == 0:
            self.collection_end_block = self.start_block + DEFAULT_COLLECTION_WINDOW
        if self.auction_end_block == 0:
            self.auction_end_block = self.start_block + DEFAULT_AUCTION_WINDOW
    
    # =========================================================================
    # Intent Management
    # =========================================================================
    
    def add_intent(self, intent: any) -> Tuple[bool, str]:
        """
        Add an intent to this epoch.
        
        Args:
            intent: Intent object with intent_id attribute
            
        Returns:
            (success, error_message)
        """
        if self.status != EpochStatus.COLLECTING:
            return False, f"Epoch not collecting (status: {self.status.name})"
        
        intent_id = intent.intent_id
        if intent_id in self.intents:
            return False, "Intent already in epoch"
        
        self.intents[intent_id] = EpochIntent(
            intent_id=intent_id,
            intent=intent,
        )
        
        logger.debug(f"Added intent {intent_id.hex()[:8]}... to epoch {self.epoch_number}")
        return True, ""
    
    def set_auction_result(
        self,
        intent_id: bytes,
        winner_solver_id: int,
        score: int,
    ) -> None:
        """Record auction result for an intent."""
        if intent_id in self.intents:
            self.intents[intent_id].auction_result = (winner_solver_id, score)
            if intent_id not in self.execution_order:
                self.execution_order.append(intent_id)
    
    # =========================================================================
    # Epoch Lifecycle
    # =========================================================================
    
    def update_status(self, current_block: int) -> EpochStatus:
        """
        Update epoch status based on current block.
        
        Returns the new status.
        """
        if self.status == EpochStatus.COLLECTING:
            if current_block >= self.collection_end_block:
                if len(self.intents) > 0:
                    self.status = EpochStatus.AUCTIONING
                else:
                    self.status = EpochStatus.FAILED
                    logger.warning(f"Epoch {self.epoch_number} failed: no intents")
        
        if self.status == EpochStatus.AUCTIONING:
            if current_block >= self.end_block:
                self.freeze()
        
        return self.status
    
    def freeze(self) -> None:
        """
        Freeze the epoch for proof generation.
        
        No more changes allowed after this.
        """
        if self.status not in (EpochStatus.COLLECTING, EpochStatus.AUCTIONING):
            return
        
        self.status = EpochStatus.FROZEN
        self.finalized_at = int(time.time())
        
        # Filter to only intents with auction results
        valid_intents = [
            iid for iid in self.execution_order
            if self.intents[iid].auction_result is not None
        ]
        self.execution_order = valid_intents
        
        logger.info(f"Epoch {self.epoch_number} frozen with {len(valid_intents)} intents")
    
    def start_proving(self) -> None:
        """Mark epoch as proving."""
        if self.status == EpochStatus.FROZEN:
            self.status = EpochStatus.PROVING
    
    def set_proof(self, proof: dict, public_signals: List[str]) -> None:
        """Set the generated proof."""
        self.proof = proof
        self.proof_public_signals = public_signals
        self.status = EpochStatus.PROVEN
        logger.info(f"Epoch {self.epoch_number} proven")
    
    def mark_committed(self) -> None:
        """Mark epoch as committed to L1."""
        self.status = EpochStatus.COMMITTED
        logger.info(f"Epoch {self.epoch_number} committed")
    
    # =========================================================================
    # Epoch Seed
    # =========================================================================
    
    def compute_epoch_seed(self, external_randomness: bytes) -> int:
        """
        Compute epoch seed from external randomness.
        
        The seed is used for tie-breaks in auctions.
        
        Args:
            external_randomness: External source (e.g., L1 block hash)
            
        Returns:
            Epoch seed as field element
        """
        rand_hash = poseidon_bytes(external_randomness)
        self.epoch_seed = poseidon2(DOMAIN_EPOCH_SEED, rand_hash)
        return self.epoch_seed
    
    # =========================================================================
    # Queries
    # =========================================================================
    
    def get_intent_count(self) -> int:
        """Number of intents in epoch."""
        return len(self.intents)
    
    def get_executed_count(self) -> int:
        """Number of intents with auction results."""
        return len(self.execution_order)
    
    def is_active(self) -> bool:
        """Whether epoch is still accepting intents or running auctions."""
        return self.status in (EpochStatus.COLLECTING, EpochStatus.AUCTIONING)
    
    def is_finalized(self) -> bool:
        """Whether epoch is frozen or later."""
        return self.status.value >= EpochStatus.FROZEN.value


# =============================================================================
# Epoch Manager
# =============================================================================


class EpochManager:
    """
    Manages epoch lifecycle and transitions.
    
    Coordinates:
    - Epoch creation and rotation
    - Intent assignment to epochs
    - Proof aggregation
    """
    
    def __init__(
        self,
        epoch_duration: int = DEFAULT_EPOCH_DURATION,
        collection_window: int = DEFAULT_COLLECTION_WINDOW,
    ):
        """
        Initialize the manager.
        
        Args:
            epoch_duration: Blocks per epoch
            collection_window: Blocks for intent collection
        """
        self.epoch_duration = epoch_duration
        self.collection_window = collection_window
        
        # Epochs by number
        self.epochs: Dict[int, Epoch] = {}
        
        # Current epoch
        self.current_epoch_number: int = 0
        self.current_epoch: Optional[Epoch] = None
        
        # Tracking
        self.last_committed_epoch: int = -1
        
        logger.info(f"EpochManager initialized: duration={epoch_duration}, window={collection_window}")
    
    # =========================================================================
    # Epoch Lifecycle
    # =========================================================================
    
    def create_epoch(self, start_block: int) -> Epoch:
        """
        Create a new epoch.
        
        Args:
            start_block: First block of the epoch
            
        Returns:
            The new Epoch
        """
        epoch_number = self.current_epoch_number
        self.current_epoch_number += 1
        
        epoch = Epoch(
            epoch_number=epoch_number,
            start_block=start_block,
            end_block=start_block + self.epoch_duration,
            collection_end_block=start_block + self.collection_window,
        )
        
        self.epochs[epoch_number] = epoch
        self.current_epoch = epoch
        
        logger.info(f"Created epoch {epoch_number}: blocks {start_block}-{epoch.end_block}")
        return epoch
    
    def on_new_block(self, block_number: int, randomness: Optional[bytes] = None) -> None:
        """
        Process a new block.
        
        Updates epoch statuses and rotates if needed.
        
        Args:
            block_number: The new block number
            randomness: Optional external randomness for epoch seed
        """
        # Update current epoch status
        if self.current_epoch:
            self.current_epoch.update_status(block_number)
            
            # Set epoch seed when transitioning to auctioning
            if (randomness and 
                self.current_epoch.status == EpochStatus.AUCTIONING and
                self.current_epoch.epoch_seed == 0):
                self.current_epoch.compute_epoch_seed(randomness)
            
            # Start new epoch if current is frozen
            if self.current_epoch.is_finalized():
                self.create_epoch(block_number)
    
    def get_active_epoch(self) -> Optional[Epoch]:
        """Get the currently active (collecting) epoch."""
        if self.current_epoch and self.current_epoch.is_active():
            return self.current_epoch
        return None
    
    def get_epoch(self, epoch_number: int) -> Optional[Epoch]:
        """Get epoch by number."""
        return self.epochs.get(epoch_number)
    
    # =========================================================================
    # Intent Routing
    # =========================================================================
    
    def add_intent(self, intent: any, current_block: int) -> Tuple[int, str]:
        """
        Add an intent to the appropriate epoch.
        
        Args:
            intent: Intent to add
            current_block: Current block number
            
        Returns:
            (epoch_number, error_message) - epoch_number is -1 on failure
        """
        epoch = self.get_active_epoch()
        
        if epoch is None:
            # Create new epoch if none active
            epoch = self.create_epoch(current_block)
        
        success, err = epoch.add_intent(intent)
        if not success:
            return -1, err
        
        return epoch.epoch_number, ""
    
    # =========================================================================
    # Proof Aggregation
    # =========================================================================
    
    def get_epochs_to_prove(self) -> List[Epoch]:
        """Get epochs that are ready for proof generation."""
        return [
            epoch for epoch in self.epochs.values()
            if epoch.status == EpochStatus.FROZEN
        ]
    
    def get_epochs_to_commit(self) -> List[Epoch]:
        """Get epochs that have proofs ready to commit."""
        return [
            epoch for epoch in self.epochs.values()
            if epoch.status == EpochStatus.PROVEN
        ]
    
    # =========================================================================
    # Stats
    # =========================================================================
    
    def stats(self) -> dict:
        """Get manager statistics."""
        return {
            "total_epochs": len(self.epochs),
            "current_epoch": self.current_epoch_number - 1,
            "last_committed": self.last_committed_epoch,
            "active_intents": (
                self.current_epoch.get_intent_count()
                if self.current_epoch else 0
            ),
        }


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "Epoch",
    "EpochManager",
    "EpochStatus",
    "EpochIntent",
    "DEFAULT_EPOCH_DURATION",
    "DEFAULT_COLLECTION_WINDOW",
]
