"""
Escape Hatch - Censorship resistance mechanism for CFP.

The escape hatch ensures a minimum percentage of block space is reserved
for raw transactions that bypass the intent auction system.

This prevents solver collusion or MEV extraction from completely
blocking user transactions.

Configuration:
- raw_tx_min_quota: Minimum percentage (e.g., 10%)
- Block is invalid if quota not met
"""

from dataclasses import dataclass
from typing import List, Tuple

from cfp.core.dag import Vertex, PayloadType
from cfp.utils.logger import get_logger

logger = get_logger("escape_hatch")


@dataclass
class BlockValidationResult:
    """Result of block validation."""
    is_valid: bool
    raw_tx_count: int
    intent_tx_count: int
    raw_percentage: float
    error: str = ""


class EscapeHatchValidator:
    """
    Validates that blocks meet escape hatch requirements.
    
    Ensures minimum raw transaction quota is met.
    """
    
    def __init__(self, min_quota: float = 0.10):
        """
        Args:
            min_quota: Minimum percentage of raw transactions (0.0-1.0)
        """
        self.min_quota = min_quota
    
    def validate_block(
        self,
        vertices: List[Vertex],
    ) -> BlockValidationResult:
        """
        Validate a block meets escape hatch requirements.
        
        Args:
            vertices: Vertices in the block
            
        Returns:
            BlockValidationResult
        """
        if not vertices:
            return BlockValidationResult(
                is_valid=True,
                raw_tx_count=0,
                intent_tx_count=0,
                raw_percentage=1.0,
            )
        
        # Count transaction types
        raw_count = sum(1 for v in vertices if v.payload_type == PayloadType.TRANSACTION)
        intent_count = sum(1 for v in vertices if v.payload_type == PayloadType.INTENT)
        
        total = raw_count + intent_count
        if total == 0:
            # No transactions, metadata only - valid
            return BlockValidationResult(
                is_valid=True,
                raw_tx_count=0,
                intent_tx_count=0,
                raw_percentage=1.0,
            )
        
        raw_percentage = raw_count / total
        
        if raw_percentage < self.min_quota:
            return BlockValidationResult(
                is_valid=False,
                raw_tx_count=raw_count,
                intent_tx_count=intent_count,
                raw_percentage=raw_percentage,
                error=f"Raw tx quota not met: {raw_percentage:.1%} < {self.min_quota:.0%}",
            )
        
        return BlockValidationResult(
            is_valid=True,
            raw_tx_count=raw_count,
            intent_tx_count=intent_count,
            raw_percentage=raw_percentage,
        )
    
    def prioritize_transactions(
        self,
        raw_txs: List[bytes],
        intent_txs: List[bytes],
        max_size: int,
    ) -> Tuple[List[bytes], List[bytes]]:
        """
        Select transactions to include while meeting quota.
        
        Prioritizes by fee/byte within each category.
        
        Args:
            raw_txs: Raw transactions (fee, data)
            intent_txs: Intent transactions
            max_size: Maximum total bytes
            
        Returns:
            (selected_raw, selected_intent)
        """
        # Sort by size (proxy for fee/byte for now)
        raw_sorted = sorted(raw_txs, key=len)
        intent_sorted = sorted(intent_txs, key=len)
        
        # Calculate minimum raw needed
        total_count = len(raw_txs) + len(intent_txs)
        min_raw_count = max(1, int(total_count * self.min_quota))
        
        # Select raw first (up to quota)
        selected_raw = raw_sorted[:min_raw_count]
        
        # Fill rest with intents
        remaining = max_size - sum(len(t) for t in selected_raw)
        selected_intent = []
        
        for tx in intent_sorted:
            if len(tx) <= remaining:
                selected_intent.append(tx)
                remaining -= len(tx)
        
        return selected_raw, selected_intent
