"""
Verifiable Auction Manager - Integrated commit-reveal auction with ZK proofs.

This module combines:
- CommitRevealAuction for sealed-bid auctions
- SolverRegistry for identity management  
- EpochManager for batching
- AuctionProver for ZK proof generation
- TranscriptBuilder for bid binding

Provides a unified interface for the verifiable auction system.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import time

from cfp.crypto import sha256, bytes_to_hex, poseidon_bytes
from cfp.core.auction.commit_reveal import (
    CommitRevealAuction,
    SolverCommit,
    SolverReveal,
    AuctionState,
    create_solver_commit,
)
from cfp.core.auction.scoring import compute_utility, compute_tie_break
from cfp.core.auction.transcript import TranscriptBuilder
from cfp.core.registry import SolverRegistry
from cfp.core.dag.epoch import Epoch, EpochManager, EpochStatus
from cfp.core.prover.auction_prover import MockAuctionProver, AuctionWitness
from cfp.core.intent.intent import Intent, ExecutionTicket, TicketStatus
from cfp.utils.logger import get_logger

logger = get_logger("verifiable_auction")


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class VerifiableAuctionConfig:
    """Configuration for verifiable auction system."""
    min_solver_stake: int = 1000
    min_bid_bond: int = 100
    commit_window: int = 10  # blocks
    reveal_window: int = 5   # blocks
    execution_window: int = 10  # blocks
    slash_percentage: float = 0.5
    max_candidates_k: int = 4


# =============================================================================
# Verifiable Auction Manager
# =============================================================================


class VerifiableAuctionManager:
    """
    Unified manager for verifiable auctions.
    
    Integrates all auction components into a single interface.
    """
    
    def __init__(
        self,
        config: Optional[VerifiableAuctionConfig] = None,
        ledger: Any = None,
    ):
        self.config = config or VerifiableAuctionConfig()
        self.ledger = ledger
        
        # Core components
        self.registry = SolverRegistry(min_stake=self.config.min_solver_stake, ledger=ledger)
        self.epoch_manager = EpochManager()
        self.prover = MockAuctionProver(k=self.config.max_candidates_k)
        
        # Active auctions: intent_id -> CommitRevealAuction
        self.auctions: Dict[bytes, CommitRevealAuction] = {}
        
        # Transcripts: intent_id -> TranscriptBuilder
        self.transcripts: Dict[bytes, TranscriptBuilder] = {}
        
        # Pending tickets: ticket_id -> ExecutionTicket
        self.pending_tickets: Dict[bytes, ExecutionTicket] = {}
        
        # Ticket to solver mapping (for slashing)
        self.ticket_to_solver: Dict[bytes, int] = {}
        
        # Completed (for history)
        self.completed_tickets: List[ExecutionTicket] = []
        
        # Proofs: intent_id -> (proof, public_signals)
        self.proofs: Dict[bytes, Tuple[dict, List[str]]] = {}
        
        # Current block
        self.current_block: int = 0
        
        logger.info("VerifiableAuctionManager initialized")
    
    # =========================================================================
    # Block Processing
    # =========================================================================
    
    def on_new_block(self, block_number: int, randomness: Optional[bytes] = None) -> None:
        """
        Process a new block.
        
        Updates all auction states and triggers finalization.
        """
        self.current_block = block_number
        
        # Update registry
        self.registry.on_new_block(block_number)
        
        # Update epoch manager
        self.epoch_manager.on_new_block(block_number, randomness)
        
        # Update all auction states
        for auction in list(self.auctions.values()):
            old_state = auction.state
            new_state = auction.update_state(block_number)
            
            # Auto-finalize if ready
            if old_state == AuctionState.REVEAL_PHASE and new_state == AuctionState.FINALIZED:
                self._on_auction_finalized(auction)
            elif new_state == AuctionState.CANCELLED:
                self._on_auction_cancelled(auction)
        
        # Check for expired tickets
        self._check_expired_tickets()
    
    # =========================================================================
    # Solver Registration
    # =========================================================================
    
    def register_solver(
        self,
        public_key: bytes,
        initial_stake: int,
    ) -> Tuple[Optional[int], str]:
        """
        Register a new solver.
        
        Returns:
            (solver_id, error_message)
        """
        return self.registry.register(public_key, initial_stake)
    
    def is_solver_registered(self, solver_id: int) -> bool:
        """Check if solver is registered and active."""
        return self.registry.is_registered(solver_id)
    
    # =========================================================================
    # Intent Submission
    # =========================================================================
    
    def submit_intent(self, intent: Intent) -> Tuple[bool, str]:
        """
        Submit an intent for auction.
        
        Creates auction and adds to current epoch.
        """
        if not intent.intent_id:
            return False, "Intent not signed"
        
        if intent.intent_id in self.auctions:
            return False, "Intent already submitted"
        
        # Create auction
        auction = CommitRevealAuction(
            intent_id=intent.intent_id,
            intent=intent,
            commit_window=self.config.commit_window,
            reveal_window=self.config.reveal_window,
        )
        auction.start(self.current_block)
        
        # Create transcript
        intent_id_int = int.from_bytes(intent.intent_id[:32].ljust(32, b'\x00'), 'big')
        transcript = TranscriptBuilder(intent_id=intent_id_int % (2**254))
        
        self.auctions[intent.intent_id] = auction
        self.transcripts[intent.intent_id] = transcript
        
        # Add to epoch
        self.epoch_manager.add_intent(intent, self.current_block)
        
        logger.info(f"Intent submitted: {bytes_to_hex(intent.intent_id)[:16]}")
        return True, ""
    
    # =========================================================================
    # Commit Phase
    # =========================================================================
    
    def submit_commit(
        self,
        intent_id: bytes,
        solver_id: int,
        commitment: int,
    ) -> Tuple[bool, str]:
        """
        Submit a bid commitment.
        
        Args:
            intent_id: Intent to bid on
            solver_id: Registered solver ID
            commitment: Poseidon hash commitment
            
        Returns:
            (success, error_message)
        """
        # Check solver registered
        if not self.registry.is_registered(solver_id):
            return False, "Solver not registered"
        
        # Get auction
        auction = self.auctions.get(intent_id)
        if not auction:
            return False, "Intent not found"
        
        # Create commit
        commit = SolverCommit(
            intent_id=intent_id,
            solver_id=solver_id,
            commitment=commitment,
        )
        
        # Submit to auction
        success, err = auction.submit_commit(commit, self.current_block)
        if not success:
            return False, err
        
        # Bond solver stake
        self.registry.bond_stake(solver_id, self.config.min_bid_bond)
        
        return True, ""
    
    # =========================================================================
    # Reveal Phase
    # =========================================================================
    
    def submit_reveal(
        self,
        intent_id: bytes,
        solver_id: int,
        score: int,
        solution_hash: int,
        salt: int,
    ) -> Tuple[bool, str]:
        """
        Reveal a bid.
        
        Returns:
            (success, error_message)
        """
        auction = self.auctions.get(intent_id)
        if not auction:
            return False, "Intent not found"
        
        reveal = SolverReveal(
            intent_id=intent_id,
            solver_id=solver_id,
            score=score,
            solution_hash=solution_hash,
            salt=salt,
        )
        
        # Submit reveal
        success, err = auction.submit_reveal(reveal, self.current_block)
        if not success:
            return False, err
        
        # Add to transcript
        transcript = self.transcripts.get(intent_id)
        if transcript:
            commit = auction.commits.get(solver_id)
            if commit:
                transcript.add_entry(
                    solver_id=solver_id,
                    commitment=commit.commitment,
                    timestamp=commit.timestamp,
                )
        
        return True, ""
    
    # =========================================================================
    # Finalization
    # =========================================================================
    
    def _on_auction_finalized(self, auction: CommitRevealAuction) -> None:
        """Handle auction finalization."""
        if auction.winner_solver_id is None:
            return
        
        # Generate proof
        transcript = self.transcripts.get(auction.intent_id)
        if transcript and auction.validated_bids:
            bids = [
                (bid.solver_id, bid.score, auction.commits[bid.solver_id].commitment)
                for bid in auction.validated_bids
            ]
            
            try:
                witness = self.prover.generate_witness(
                    intent_id=transcript.intent_id,
                    epoch_seed=auction.epoch_seed,
                    bids=bids,
                    transcript=transcript,
                )
                proof, public_signals = self.prover.generate_proof(witness)
                if proof:
                    self.proofs[auction.intent_id] = (proof, public_signals)
            except Exception as e:
                logger.error(f"Proof generation failed: {e}")
        
        # Create execution ticket
        ticket = ExecutionTicket(
            intent_id=auction.intent_id,
            solver=auction.winner_solver_id.to_bytes(32, 'big')[:20],  # Truncate for address
            fee_bid=auction.winner_score or 0,
            bond=self.config.min_bid_bond,
            deadline_block=self.current_block + self.config.execution_window,
        )
        
        self.pending_tickets[ticket.ticket_id] = ticket
        self.ticket_to_solver[ticket.ticket_id] = auction.winner_solver_id
        
        # Update epoch
        epoch = self.epoch_manager.get_active_epoch()
        if epoch:
            epoch.set_auction_result(
                auction.intent_id,
                auction.winner_solver_id,
                auction.winner_score or 0,
            )
        
        logger.info(f"Auction finalized: winner={auction.winner_solver_id}, score={auction.winner_score}")
    
    def _on_auction_cancelled(self, auction: CommitRevealAuction) -> None:
        """Handle auction cancellation."""
        # Slash unrevealed commits
        for solver_id in auction.get_unrevealed_solvers():
            solver = self.registry.get_solver(solver_id)
            if solver:
                slash_amount = int(solver.stake_total * 0.1)  # 10% for no reveal
                self.registry.slash(solver_id, slash_amount, "commit_without_reveal")
        
        # Cleanup
        del self.auctions[auction.intent_id]
        if auction.intent_id in self.transcripts:
            del self.transcripts[auction.intent_id]
        
        logger.warning(f"Auction cancelled: {bytes_to_hex(auction.intent_id)[:16]}")
    
    # =========================================================================
    # Execution
    # =========================================================================
    
    def report_execution(
        self,
        ticket_id: bytes,
        tx_hash: bytes,
    ) -> Tuple[bool, str]:
        """Report successful execution."""
        ticket = self.pending_tickets.get(ticket_id)
        if not ticket:
            return False, "Ticket not found"
        
        if ticket.status != TicketStatus.PENDING:
            return False, f"Ticket already {ticket.status.name}"
        
        # Mark executed
        ticket.mark_executed(tx_hash)
        
        # Release bond
        solver_id = self.ticket_to_solver.get(ticket_id)
        if solver_id:
            self.registry.release_bond(solver_id, ticket.bond)
            del self.ticket_to_solver[ticket_id]
        
        # Move to completed
        del self.pending_tickets[ticket_id]
        self.completed_tickets.append(ticket)
        
        return True, ""
    
    def _check_expired_tickets(self) -> List[ExecutionTicket]:
        """Check and slash expired tickets."""
        slashed = []
        
        for ticket_id, ticket in list(self.pending_tickets.items()):
            if ticket.is_expired(self.current_block):
                ticket.mark_slashed()
                
                # Slash solver
                solver_id = self.ticket_to_solver.get(ticket_id)
                if solver_id:
                    slash_amount = int(ticket.bond * self.config.slash_percentage)
                    self.registry.slash(solver_id, slash_amount, "execution_timeout")
                    del self.ticket_to_solver[ticket_id]
                
                del self.pending_tickets[ticket_id]
                self.completed_tickets.append(ticket)
                slashed.append(ticket)
        
        return slashed
    
    # =========================================================================
    # Queries
    # =========================================================================
    
    def get_auction(self, intent_id: bytes) -> Optional[CommitRevealAuction]:
        """Get auction by intent ID."""
        return self.auctions.get(intent_id)
    
    def get_proof(self, intent_id: bytes) -> Optional[Tuple[dict, List[str]]]:
        """Get proof for an intent."""
        return self.proofs.get(intent_id)
    
    def stats(self) -> dict:
        """Get manager statistics."""
        return {
            "active_auctions": len(self.auctions),
            "pending_tickets": len(self.pending_tickets),
            "completed_tickets": len(self.completed_tickets),
            "proofs_generated": len(self.proofs),
            "registered_solvers": self.registry.stats()["active_solvers"],
            "current_block": self.current_block,
        }


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "VerifiableAuctionManager",
    "VerifiableAuctionConfig",
]
