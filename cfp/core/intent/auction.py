"""
Auction - Intent auction mechanism for CFP.

Manages the auction process for intent execution:
- Bid submission and validation
- Winner selection
- Execution ticket issuance
- Bond management and slashing
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

from cfp.core.intent.intent import (
    Intent, ExecutionTicket, SolverBid, TicketStatus
)
from cfp.crypto import sha256, bytes_to_hex
from cfp.utils.logger import get_logger

logger = get_logger("auction")


# =============================================================================
# Auction Configuration
# =============================================================================


@dataclass
class AuctionConfig:
    """Configuration for the auction system."""
    min_bond: int = 100                 # Minimum bond required
    execution_window: int = 10          # Blocks to execute after winning
    slash_percentage: float = 0.5       # Percentage of bond slashed on failure
    protocol_fee_percentage: float = 0.1  # Fee to protocol


# =============================================================================
# Intent Auction
# =============================================================================


@dataclass
class IntentAuction:
    """
    Auction for a single intent.
    
    Collects bids, selects winner, and tracks execution.
    """
    intent: Intent
    bids: List[SolverBid] = field(default_factory=list)
    winning_bid: Optional[SolverBid] = None
    ticket: Optional[ExecutionTicket] = None
    closed: bool = False
    
    def submit_bid(self, bid: SolverBid, min_bond: int) -> Tuple[bool, str]:
        """
        Submit a bid to this auction.
        
        Args:
            bid: The solver's bid
            min_bond: Minimum required bond
            
        Returns:
            (success, error_message)
        """
        if self.closed:
            return False, "Auction is closed"
        
        if bid.intent_id != self.intent.intent_id:
            return False, "Bid intent_id mismatch"
        
        if bid.fee_bid > self.intent.max_fee:
            return False, f"Bid fee {bid.fee_bid} exceeds max_fee {self.intent.max_fee}"
        
        if bid.bond < min_bond:
            return False, f"Bond {bid.bond} below minimum {min_bond}"
        
        self.bids.append(bid)
        logger.debug(f"Bid received for intent {bytes_to_hex(self.intent.intent_id)[:8]}: fee={bid.fee_bid}")
        return True, ""
    
    def select_winner(self, current_block: int, config: AuctionConfig) -> Optional[ExecutionTicket]:
        """
        Close auction and select winning bid.
        
        Winner is the highest fee bid.
        
        Returns:
            ExecutionTicket for winner, or None if no valid bids
        """
        if self.closed:
            return self.ticket
        
        if not self.bids:
            self.closed = True
            return None
        
        # Select highest fee bid
        self.bids.sort(key=lambda b: b.fee_bid, reverse=True)
        self.winning_bid = self.bids[0]
        
        # Create execution ticket
        self.ticket = ExecutionTicket(
            intent_id=self.intent.intent_id,
            solver=self.winning_bid.solver,
            fee_bid=self.winning_bid.fee_bid,
            bond=self.winning_bid.bond,
            deadline_block=current_block + config.execution_window,
        )
        
        self.closed = True
        logger.info(f"Auction won: intent={bytes_to_hex(self.intent.intent_id)[:8]}, fee={self.winning_bid.fee_bid}")
        
        return self.ticket


# =============================================================================
# Auction Manager
# =============================================================================


class AuctionManager:
    """
    Manages all intent auctions.
    
    Handles auction lifecycle, bond tracking, and slashing.
    """
    
    def __init__(self, config: Optional[AuctionConfig] = None):
        self.config = config or AuctionConfig()
        
        # Active auctions by intent_id
        self.active_auctions: Dict[bytes, IntentAuction] = {}
        
        # Pending execution tickets
        self.pending_tickets: Dict[bytes, ExecutionTicket] = {}
        
        # Completed tickets (for history)
        self.completed_tickets: List[ExecutionTicket] = []
        
        # Solver bonds (solver_address -> bonded amount)
        self.solver_bonds: Dict[bytes, int] = defaultdict(int)
        
        # Slashed amounts waiting for distribution
        self.slashed_pool: int = 0
    
    # =========================================================================
    # Intent Submission
    # =========================================================================
    
    def submit_intent(self, intent: Intent) -> Tuple[bool, str]:
        """
        Submit a new intent for auction.
        
        Args:
            intent: The user's intent
            
        Returns:
            (success, error_message)
        """
        if not intent.intent_id:
            return False, "Intent not signed"
        
        if intent.intent_id in self.active_auctions:
            return False, "Intent already submitted"
        
        auction = IntentAuction(intent=intent)
        self.active_auctions[intent.intent_id] = auction
        
        logger.info(f"Intent submitted: {bytes_to_hex(intent.intent_id)[:8]}, max_fee={intent.max_fee}")
        return True, ""
    
    # =========================================================================
    # Bid Submission
    # =========================================================================
    
    def submit_bid(self, bid: SolverBid) -> Tuple[bool, str]:
        """
        Submit a solver bid for an intent.
        
        Args:
            bid: The solver's bid
            
        Returns:
            (success, error_message)
        """
        auction = self.active_auctions.get(bid.intent_id)
        if not auction:
            return False, "Intent not found"
        
        # Check solver has enough bond
        available_bond = self.solver_bonds.get(bid.solver, 0)
        if available_bond < bid.bond:
            return False, f"Insufficient bond: have {available_bond}, need {bid.bond}"
        
        return auction.submit_bid(bid, self.config.min_bond)
    
    # =========================================================================
    # Auction Resolution
    # =========================================================================
    
    def resolve_auction(self, intent_id: bytes, current_block: int) -> Optional[ExecutionTicket]:
        """
        Resolve an auction and issue execution ticket.
        
        Args:
            intent_id: Intent to resolve
            current_block: Current block number
            
        Returns:
            ExecutionTicket if winner, None otherwise
        """
        auction = self.active_auctions.get(intent_id)
        if not auction:
            return None
        
        ticket = auction.select_winner(current_block, self.config)
        
        if ticket:
            # Lock solver's bond
            self.solver_bonds[ticket.solver] -= ticket.bond
            self.pending_tickets[ticket.ticket_id] = ticket
        
        # Remove from active auctions
        del self.active_auctions[intent_id]
        
        return ticket
    
    def resolve_all_auctions(self, current_block: int) -> List[ExecutionTicket]:
        """Resolve all active auctions."""
        tickets = []
        intent_ids = list(self.active_auctions.keys())
        
        for intent_id in intent_ids:
            ticket = self.resolve_auction(intent_id, current_block)
            if ticket:
                tickets.append(ticket)
        
        return tickets
    
    # =========================================================================
    # Execution Tracking
    # =========================================================================
    
    def report_execution(
        self,
        ticket_id: bytes,
        tx_hash: bytes,
    ) -> Tuple[bool, str]:
        """
        Report successful execution of an intent.
        
        Args:
            ticket_id: The execution ticket
            tx_hash: Transaction hash that fulfilled the intent
            
        Returns:
            (success, error_message)
        """
        ticket = self.pending_tickets.get(ticket_id)
        if not ticket:
            return False, "Ticket not found"
        
        if ticket.status != TicketStatus.PENDING:
            return False, f"Ticket already {ticket.status.name}"
        
        # Mark as executed
        ticket.mark_executed(tx_hash)
        
        # Return bond to solver
        self.solver_bonds[ticket.solver] += ticket.bond
        
        # Move to completed
        del self.pending_tickets[ticket_id]
        self.completed_tickets.append(ticket)
        
        logger.info(f"Execution confirmed: ticket={bytes_to_hex(ticket_id)[:8]}")
        return True, ""
    
    def check_expired_tickets(self, current_block: int) -> List[ExecutionTicket]:
        """
        Check for and slash expired tickets.
        
        Returns:
            List of slashed tickets
        """
        slashed = []
        
        for ticket_id, ticket in list(self.pending_tickets.items()):
            if ticket.is_expired(current_block):
                self._slash_ticket(ticket)
                slashed.append(ticket)
        
        return slashed
    
    def _slash_ticket(self, ticket: ExecutionTicket) -> None:
        """Slash a solver for failing to execute."""
        ticket.mark_slashed()
        
        # Calculate slash amount
        slash_amount = int(ticket.bond * self.config.slash_percentage)
        refund_amount = ticket.bond - slash_amount
        
        # Add to slashed pool
        self.slashed_pool += slash_amount
        
        # Refund remaining to solver
        self.solver_bonds[ticket.solver] += refund_amount
        
        # Move to completed
        del self.pending_tickets[ticket.ticket_id]
        self.completed_tickets.append(ticket)
        
        logger.warning(f"Solver slashed: ticket={bytes_to_hex(ticket.ticket_id)[:8]}, amount={slash_amount}")
    
    # =========================================================================
    # Bond Management
    # =========================================================================
    
    def deposit_bond(self, solver: bytes, amount: int) -> None:
        """Deposit bond for a solver."""
        self.solver_bonds[solver] += amount
        logger.debug(f"Bond deposited: solver={bytes_to_hex(solver)[:8]}, amount={amount}")
    
    def withdraw_bond(self, solver: bytes, amount: int) -> Tuple[bool, str]:
        """Withdraw bond (if not locked)."""
        available = self.solver_bonds.get(solver, 0)
        if amount > available:
            return False, f"Insufficient balance: have {available}, want {amount}"
        
        self.solver_bonds[solver] -= amount
        return True, ""
    
    def get_solver_bond(self, solver: bytes) -> int:
        """Get solver's available bond."""
        return self.solver_bonds.get(solver, 0)
    
    # =========================================================================
    # Stats
    # =========================================================================
    
    def stats(self) -> dict:
        """Get auction statistics."""
        return {
            "active_auctions": len(self.active_auctions),
            "pending_tickets": len(self.pending_tickets),
            "completed_tickets": len(self.completed_tickets),
            "slashed_pool": self.slashed_pool,
            "total_bonded": sum(self.solver_bonds.values()),
        }
