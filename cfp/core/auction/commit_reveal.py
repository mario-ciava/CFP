"""
Commit-Reveal Auction - Sealed-bid auction for intent execution.

This module implements a two-phase auction mechanism:
1. Commit Phase: Solvers submit hash commitments to bids
2. Reveal Phase: Solvers reveal actual bids

Benefits:
- Prevents bid sniping (copying a revealed bid)
- Enables sealed-bid auctions
- ZK-provable winner selection

See spec/auction.md for the formal specification.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple
import time

from cfp.crypto import (
    hash_solver_commit,
    poseidon_bytes,
    FIELD_PRIME,
    sign,
    verify,
    sha256,
)
from cfp.core.auction.scoring import (
    compute_utility,
    compute_tie_break,
    select_winner,
    IntentType,
)
from cfp.utils.logger import get_logger

logger = get_logger("commit_reveal")


# =============================================================================
# Constants
# =============================================================================

# Default phase durations (in blocks)
DEFAULT_COMMIT_WINDOW = 10
DEFAULT_REVEAL_WINDOW = 5

# Timestamp tolerance for commit ordering
TIMESTAMP_TOLERANCE = 2

# Domain separator
DOMAIN_SOLVER_COMMIT = 0x02


# =============================================================================
# Enums
# =============================================================================


class AuctionState(IntEnum):
    """State of a commit-reveal auction."""
    OPEN = 0           # Just created, not started
    COMMIT_PHASE = 1   # Accepting commitments
    REVEAL_PHASE = 2   # Accepting reveals
    FINALIZED = 3      # Winner selected
    CANCELLED = 4      # No valid reveals


# =============================================================================
# Data Structures
# =============================================================================


@dataclass
class SolverCommit:
    """
    A solver's commitment to a bid.
    
    The commitment hides the actual bid value using:
    C = Poseidon(domain, intent_id, solver_id, score, solution_hash, salt)
    """
    intent_id: bytes
    solver_id: int
    commitment: int      # Poseidon hash
    solver_sig: bytes = b""
    timestamp: int = field(default_factory=lambda: int(time.time()))
    block_number: int = 0
    
    def to_bytes(self) -> bytes:
        """Serialize for signing."""
        return (
            self.intent_id +
            self.solver_id.to_bytes(32, "big") +
            self.commitment.to_bytes(32, "big") +
            self.timestamp.to_bytes(8, "big")
        )
    
    def sign(self, private_key: bytes) -> None:
        """Sign the commitment."""
        msg_hash = sha256(self.to_bytes())
        self.solver_sig = sign(msg_hash, private_key)
    
    def verify_signature(self, public_key: bytes) -> bool:
        """Verify commitment signature."""
        msg_hash = sha256(self.to_bytes())
        return verify(msg_hash, self.solver_sig, public_key)


@dataclass
class SolverReveal:
    """
    A solver's bid reveal.
    
    Must match the commitment from the commit phase.
    """
    intent_id: bytes
    solver_id: int
    score: int           # Utility/fee offered
    solution_hash: int   # Hash of execution plan
    salt: int            # Random blinding factor
    
    def compute_commitment(self) -> int:
        """Compute commitment that should match."""
        intent_id_int = int.from_bytes(self.intent_id[:32].ljust(32, b'\x00'), 'big') % FIELD_PRIME
        return hash_solver_commit(
            intent_id=intent_id_int,
            solver_id=self.solver_id,
            score=self.score,
            solution_hash=self.solution_hash,
            salt=self.salt
        )


@dataclass
class RevealedBid:
    """
    A validated bid after successful reveal.
    
    Used for winner selection.
    """
    solver_id: int
    score: int
    solution_hash: int
    reveal_block: int
    
    @property
    def fee_offered(self) -> int:
        """Alias for scoring compatibility."""
        return self.score


# =============================================================================
# Commit-Reveal Auction
# =============================================================================


@dataclass
class CommitRevealAuction:
    """
    A single commit-reveal auction for an intent.
    
    Manages the two-phase bidding process.
    """
    intent_id: bytes
    intent: any  # Intent object
    
    # State
    state: AuctionState = AuctionState.OPEN
    
    # Timing (block numbers)
    created_block: int = 0
    commit_start_block: int = 0
    commit_end_block: int = 0
    reveal_end_block: int = 0
    
    # Phase durations
    commit_window: int = DEFAULT_COMMIT_WINDOW
    reveal_window: int = DEFAULT_REVEAL_WINDOW
    
    # Commits and Reveals (solver_id -> data)
    commits: Dict[int, SolverCommit] = field(default_factory=dict)
    reveals: Dict[int, SolverReveal] = field(default_factory=dict)
    validated_bids: List[RevealedBid] = field(default_factory=list)
    
    # Result
    winner_solver_id: Optional[int] = None
    winner_score: Optional[int] = None
    transcript_root: Optional[int] = None
    epoch_seed: int = 0
    
    def start(self, current_block: int) -> None:
        """Start the auction (enter commit phase)."""
        self.created_block = current_block
        self.commit_start_block = current_block
        self.commit_end_block = current_block + self.commit_window
        self.reveal_end_block = self.commit_end_block + self.reveal_window
        self.state = AuctionState.COMMIT_PHASE
        
        logger.info(f"Auction started for intent {self.intent_id.hex()[:16]}... "
                   f"commit until block {self.commit_end_block}, "
                   f"reveal until block {self.reveal_end_block}")
    
    def update_state(self, current_block: int) -> AuctionState:
        """
        Update auction state based on current block.
        
        Handles multiple state transitions if block is far ahead.
        
        Returns the new state.
        """
        # First transition: COMMIT -> REVEAL
        if self.state == AuctionState.COMMIT_PHASE:
            if current_block >= self.commit_end_block:
                self.state = AuctionState.REVEAL_PHASE
                logger.debug(f"Auction {self.intent_id.hex()[:8]}... entered reveal phase")
        
        # Second transition: REVEAL -> FINALIZED/CANCELLED
        # Check again (not elif) to allow consecutive transitions
        if self.state == AuctionState.REVEAL_PHASE:
            if current_block >= self.reveal_end_block:
                # Time to finalize
                if len(self.validated_bids) > 0:
                    self._finalize()
                else:
                    self.state = AuctionState.CANCELLED
                    logger.warning(f"Auction {self.intent_id.hex()[:8]}... cancelled: no valid reveals")
        
        return self.state
    
    # =========================================================================
    # Commit Phase
    # =========================================================================
    
    def submit_commit(
        self,
        commit: SolverCommit,
        current_block: int,
    ) -> Tuple[bool, str]:
        """
        Submit a commitment during commit phase.
        
        Args:
            commit: The solver's commitment
            current_block: Current block number
            
        Returns:
            (success, error_message)
        """
        # Check state
        self.update_state(current_block)
        if self.state != AuctionState.COMMIT_PHASE:
            return False, f"Not in commit phase (state: {self.state.name})"
        
        # Check timing
        if current_block > self.commit_end_block:
            return False, "Commit phase has ended"
        
        # Check intent match
        if commit.intent_id != self.intent_id:
            return False, "Intent ID mismatch"
        
        # Check for duplicate
        if commit.solver_id in self.commits:
            return False, "Solver already committed"
        
        # Validate commitment value
        if commit.commitment <= 0 or commit.commitment >= FIELD_PRIME:
            return False, "Invalid commitment value"
        
        # Store commit
        commit.block_number = current_block
        self.commits[commit.solver_id] = commit
        
        logger.debug(f"Received commit from solver {commit.solver_id} for intent {self.intent_id.hex()[:8]}...")
        return True, ""
    
    # =========================================================================
    # Reveal Phase
    # =========================================================================
    
    def submit_reveal(
        self,
        reveal: SolverReveal,
        current_block: int,
    ) -> Tuple[bool, str]:
        """
        Submit a reveal during reveal phase.
        
        Args:
            reveal: The solver's reveal
            current_block: Current block number
            
        Returns:
            (success, error_message)
        """
        # Check state
        self.update_state(current_block)
        if self.state != AuctionState.REVEAL_PHASE:
            return False, f"Not in reveal phase (state: {self.state.name})"
        
        # Check timing
        if current_block > self.reveal_end_block:
            return False, "Reveal phase has ended"
        
        # Check intent match
        if reveal.intent_id != self.intent_id:
            return False, "Intent ID mismatch"
        
        # Check for commitment
        if reveal.solver_id not in self.commits:
            return False, "No commitment found for solver"
        
        # Check for duplicate reveal
        if reveal.solver_id in self.reveals:
            return False, "Already revealed"
        
        # Verify reveal matches commitment
        expected_commitment = reveal.compute_commitment()
        actual_commitment = self.commits[reveal.solver_id].commitment
        
        if expected_commitment != actual_commitment:
            logger.warning(f"Reveal mismatch for solver {reveal.solver_id}: "
                          f"expected {expected_commitment}, got {actual_commitment}")
            return False, "Reveal does not match commitment"
        
        # Store reveal and create validated bid
        self.reveals[reveal.solver_id] = reveal
        
        bid = RevealedBid(
            solver_id=reveal.solver_id,
            score=reveal.score,
            solution_hash=reveal.solution_hash,
            reveal_block=current_block
        )
        self.validated_bids.append(bid)
        
        logger.debug(f"Valid reveal from solver {reveal.solver_id}: score={reveal.score}")
        return True, ""
    
    # =========================================================================
    # Finalization
    # =========================================================================
    
    def _finalize(self) -> None:
        """
        Finalize auction and select winner.
        
        Called automatically when reveal phase ends.
        """
        if not self.validated_bids:
            self.state = AuctionState.CANCELLED
            return
        
        # Select winner
        winner, winner_idx = select_winner(
            intent=self.intent,
            solutions=self.validated_bids,
            epoch_seed=self.epoch_seed,
            intent_id=int.from_bytes(self.intent_id[:32].ljust(32, b'\x00'), 'big') % FIELD_PRIME
        )
        
        if winner is not None:
            self.winner_solver_id = winner.solver_id
            self.winner_score = winner.score
            self.state = AuctionState.FINALIZED
            
            logger.info(f"Auction finalized: winner={self.winner_solver_id}, score={self.winner_score}")
        else:
            self.state = AuctionState.CANCELLED
    
    def finalize(
        self,
        current_block: int,
        epoch_seed: int,
    ) -> Tuple[Optional[int], str]:
        """
        Explicitly finalize the auction.
        
        Args:
            current_block: Current block number
            epoch_seed: External randomness for tie-break
            
        Returns:
            (winner_solver_id, error_message)
        """
        self.epoch_seed = epoch_seed
        self.update_state(current_block)
        
        if self.state == AuctionState.FINALIZED:
            return self.winner_solver_id, ""
        
        if self.state == AuctionState.CANCELLED:
            return None, "Auction cancelled: no valid reveals"
        
        if self.state not in (AuctionState.REVEAL_PHASE, AuctionState.FINALIZED):
            return None, f"Cannot finalize in state {self.state.name}"
        
        # Force finalization if in reveal phase and time is up
        if current_block >= self.reveal_end_block:
            self._finalize()
            return self.winner_solver_id, ""
        
        return None, "Reveal phase not complete"
    
    # =========================================================================
    # Queries
    # =========================================================================
    
    def get_commit_count(self) -> int:
        """Number of commitments received."""
        return len(self.commits)
    
    def get_reveal_count(self) -> int:
        """Number of reveals received."""
        return len(self.reveals)
    
    def get_unrevealed_solvers(self) -> List[int]:
        """Solvers who committed but didn't reveal."""
        committed = set(self.commits.keys())
        revealed = set(self.reveals.keys())
        return list(committed - revealed)
    
    def is_active(self) -> bool:
        """Whether auction is still accepting bids/reveals."""
        return self.state in (AuctionState.COMMIT_PHASE, AuctionState.REVEAL_PHASE)


# =============================================================================
# Helper Functions
# =============================================================================


def create_commitment(
    intent_id: bytes,
    solver_id: int,
    score: int,
    solution_hash: int,
    salt: int,
) -> int:
    """
    Create a commitment for a bid.
    
    Args:
        intent_id: Intent being bid on
        solver_id: Solver's ID
        score: Utility/fee offered
        solution_hash: Hash of execution plan
        salt: Random blinding factor
        
    Returns:
        Commitment value (Poseidon hash)
    """
    intent_id_int = int.from_bytes(intent_id[:32].ljust(32, b'\x00'), 'big') % FIELD_PRIME
    return hash_solver_commit(
        intent_id=intent_id_int,
        solver_id=solver_id,
        score=score,
        solution_hash=solution_hash,
        salt=salt
    )


def create_solver_commit(
    intent_id: bytes,
    solver_id: int,
    score: int,
    solution_hash: int,
    salt: int,
    private_key: Optional[bytes] = None,
) -> Tuple[SolverCommit, SolverReveal]:
    """
    Create a matching commit-reveal pair.
    
    Args:
        intent_id: Intent being bid on
        solver_id: Solver's ID
        score: Utility/fee offered
        solution_hash: Hash of execution plan
        salt: Random blinding factor
        private_key: Optional key for signing commit
        
    Returns:
        (SolverCommit, SolverReveal) pair
    """
    commitment = create_commitment(intent_id, solver_id, score, solution_hash, salt)
    
    commit = SolverCommit(
        intent_id=intent_id,
        solver_id=solver_id,
        commitment=commitment,
    )
    
    if private_key:
        commit.sign(private_key)
    
    reveal = SolverReveal(
        intent_id=intent_id,
        solver_id=solver_id,
        score=score,
        solution_hash=solution_hash,
        salt=salt,
    )
    
    return commit, reveal


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "CommitRevealAuction",
    "SolverCommit",
    "SolverReveal",
    "RevealedBid",
    "AuctionState",
    "create_commitment",
    "create_solver_commit",
    "DEFAULT_COMMIT_WINDOW",
    "DEFAULT_REVEAL_WINDOW",
]
