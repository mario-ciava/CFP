"""
Tokenomics - Fee system and token economics for CFP.

Manages:
- Transaction fee calculation
- Fee distribution (sequencer, protocol, burn)
- Staking rewards (simulated)
- Economic parameters
"""

from dataclasses import dataclass, field
from typing import Dict, Optional

from cfp.utils.logger import get_logger

logger = get_logger("tokenomics")


@dataclass
class TokenomicsConfig:
    """Configuration for token economics."""
    
    # Fee parameters
    base_fee_per_byte: int = 1              # Base fee per byte
    priority_multiplier: float = 2.0        # Multiplier for priority txs
    
    # Fee distribution
    sequencer_share: float = 0.7            # 70% to sequencer
    protocol_share: float = 0.2             # 20% to protocol treasury
    burn_share: float = 0.1                 # 10% burned
    
    # Staking
    min_stake: int = 10000                  # Minimum stake for sequencer
    slash_percentage: float = 0.1           # 10% slash for misbehavior
    
    # Supply
    initial_supply: int = 1_000_000_000     # 1 billion tokens
    max_supply: int = 2_000_000_000         # 2 billion cap


@dataclass
class FeeReceipt:
    """Receipt for fee payment."""
    tx_hash: bytes
    total_fee: int
    sequencer_fee: int
    protocol_fee: int
    burned: int


class FeeManager:
    """
    Manages transaction fees and distribution.
    """
    
    def __init__(self, config: Optional[TokenomicsConfig] = None):
        self.config = config or TokenomicsConfig()
        
        # Track totals
        self.total_fees_collected: int = 0
        self.total_sequencer_fees: int = 0
        self.total_protocol_fees: int = 0
        self.total_burned: int = 0
        
        # Protocol treasury
        self.protocol_treasury: int = 0
    
    def calculate_fee(self, tx_size: int, priority: bool = False) -> int:
        """
        Calculate fee for a transaction.
        
        Args:
            tx_size: Transaction size in bytes
            priority: Is this a priority transaction?
            
        Returns:
            Fee amount
        """
        base = tx_size * self.config.base_fee_per_byte
        if priority:
            return int(base * self.config.priority_multiplier)
        return base
    
    def process_fee(self, tx_hash: bytes, fee: int) -> FeeReceipt:
        """
        Process a transaction fee.
        
        Distributes fee according to config shares.
        
        Args:
            tx_hash: Transaction hash
            fee: Total fee paid
            
        Returns:
            FeeReceipt with breakdown
        """
        sequencer_fee = int(fee * self.config.sequencer_share)
        protocol_fee = int(fee * self.config.protocol_share)
        burned = fee - sequencer_fee - protocol_fee  # Remainder
        
        # Update totals
        self.total_fees_collected += fee
        self.total_sequencer_fees += sequencer_fee
        self.total_protocol_fees += protocol_fee
        self.total_burned += burned
        
        self.protocol_treasury += protocol_fee
        
        return FeeReceipt(
            tx_hash=tx_hash,
            total_fee=fee,
            sequencer_fee=sequencer_fee,
            protocol_fee=protocol_fee,
            burned=burned,
        )
    
    def stats(self) -> dict:
        """Get fee statistics."""
        return {
            "total_collected": self.total_fees_collected,
            "sequencer_share": self.total_sequencer_fees,
            "protocol_share": self.total_protocol_fees,
            "total_burned": self.total_burned,
            "treasury_balance": self.protocol_treasury,
        }


class MockStaking:
    """
    Mock staking system for sequencer selection.
    
    In production, this would manage:
    - Stake deposits/withdrawals
    - Validator set rotation
    - Slashing execution
    """
    
    def __init__(self, config: Optional[TokenomicsConfig] = None):
        self.config = config or TokenomicsConfig()
        
        # Staker balances
        self.stakes: Dict[bytes, int] = {}
        
        # Active sequencer
        self.active_sequencer: Optional[bytes] = None
    
    def stake(self, address: bytes, amount: int) -> bool:
        """Stake tokens."""
        current = self.stakes.get(address, 0)
        self.stakes[address] = current + amount
        
        # If first eligible staker, make active
        if self.stakes[address] >= self.config.min_stake and self.active_sequencer is None:
            self.active_sequencer = address
        
        return True
    
    def unstake(self, address: bytes, amount: int) -> bool:
        """Unstake tokens."""
        current = self.stakes.get(address, 0)
        if amount > current:
            return False
        
        self.stakes[address] = current - amount
        
        # If below minimum, can't be sequencer
        if self.stakes[address] < self.config.min_stake:
            if self.active_sequencer == address:
                self.active_sequencer = None
                # Would rotate to next eligible
        
        return True
    
    def slash(self, address: bytes) -> int:
        """Slash a staker for misbehavior."""
        current = self.stakes.get(address, 0)
        slash_amount = int(current * self.config.slash_percentage)
        
        self.stakes[address] = current - slash_amount
        
        if self.active_sequencer == address:
            self.active_sequencer = None
        
        return slash_amount
    
    def is_eligible_sequencer(self, address: bytes) -> bool:
        """Check if address can be sequencer."""
        return self.stakes.get(address, 0) >= self.config.min_stake
