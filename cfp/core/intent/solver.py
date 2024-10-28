"""
Mock Solver - Automated intent fulfillment for testing.

Provides a simple solver agent that:
- Monitors for new intents
- Submits bids
- Executes winning intents
"""

import json
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cfp.core.intent.intent import Intent, IntentType, SolverBid
from cfp.core.intent.auction import AuctionManager
from cfp.core.state import Ledger, create_transfer, address_from_public_key
from cfp.crypto import generate_keypair, KeyPair
from cfp.utils.logger import get_logger

logger = get_logger("solver")


@dataclass
class MockSolver:
    """
    A mock solver for testing the intent system.
    
    Automatically bids on and executes intents.
    """
    keypair: KeyPair = field(default_factory=generate_keypair)
    bid_percentage: float = 0.9   # Bid this % of max_fee
    default_bond: int = 200
    
    @property
    def address(self) -> bytes:
        """Solver's address."""
        return address_from_public_key(self.keypair.public_key)
    
    def create_bid(self, intent: Intent) -> SolverBid:
        """
        Create a bid for an intent.
        
        Bids at bid_percentage of the max_fee.
        """
        fee_bid = int(intent.max_fee * self.bid_percentage)
        
        bid = SolverBid(
            intent_id=intent.intent_id,
            solver=self.address,
            fee_bid=fee_bid,
            bond=self.default_bond,
        )
        bid.sign(self.keypair.private_key)
        
        return bid
    
    def execute_intent(
        self,
        intent: Intent,
        ledger: Ledger,
    ) -> Tuple[Optional[bytes], str]:
        """
        Execute an intent.
        
        For prototype, handles simple transfer intents.
        
        Returns:
            (tx_hash, error_message)
        """
        try:
            conditions = json.loads(intent.conditions.decode())
        except Exception as e:
            return None, f"Failed to parse conditions: {e}"
        
        if intent.intent_type == IntentType.TRANSFER:
            return self._execute_transfer(intent, conditions, ledger)
        
        return None, f"Unsupported intent type: {intent.intent_type}"
    
    def _execute_transfer(
        self,
        intent: Intent,
        conditions: dict,
        ledger: Ledger,
    ) -> Tuple[Optional[bytes], str]:
        """Execute a transfer intent."""
        recipient = bytes.fromhex(conditions.get("recipient", "").replace("0x", ""))
        amount = conditions.get("amount", 0)
        
        if len(recipient) != 20:
            return None, "Invalid recipient address"
        
        # Get solver's UTXOs
        utxos = ledger.get_utxos_for_address(self.address)
        if not utxos:
            return None, "Solver has no UTXOs"
        
        # Find sufficient inputs
        total = 0
        selected = []
        for utxo in utxos:
            selected.append(utxo)
            total += utxo.value
            if total >= amount:
                break
        
        if total < amount:
            return None, f"Insufficient funds: have {total}, need {amount}"
        
        # Create transfer
        change = total - amount
        recipients = [(recipient, amount)]
        if change > 0:
            recipients.append((self.address, change))
        
        tx = create_transfer(
            inputs=[(u, self.keypair.private_key) for u in selected],
            recipients=recipients,
            fee=0,
        )
        
        # Apply to ledger
        success, error = ledger.apply_transaction(tx)
        if not success:
            return None, error
        
        logger.info(f"Executed transfer: {amount} to {recipient.hex()[:8]}...")
        return tx.tx_hash, ""


class SolverPool:
    """
    Pool of mock solvers for testing competition.
    """
    
    def __init__(self, num_solvers: int = 3):
        self.solvers = [MockSolver() for _ in range(num_solvers)]
    
    def compete_for_intent(
        self,
        intent: Intent,
        auction_manager: AuctionManager,
    ) -> List[SolverBid]:
        """
        Have all solvers bid on an intent.
        
        Each solver bids at a slightly different rate.
        """
        bids = []
        for i, solver in enumerate(self.solvers):
            # Vary bid percentage
            solver.bid_percentage = 0.8 + (i * 0.05)
            bid = solver.create_bid(intent)
            
            # Ensure solver has bond
            auction_manager.deposit_bond(solver.address, solver.default_bond)
            
            success, _ = auction_manager.submit_bid(bid)
            if success:
                bids.append(bid)
        
        return bids
