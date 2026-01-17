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

import math
from dataclasses import dataclass
from typing import Any, List, Tuple

from cfp.core.dag import PayloadType, Vertex
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

    def select_transactions(
        self,
        raw: List[Tuple[Any, int]],
        intent: List[Tuple[Any, int]],
        max_count: int,
    ) -> List[Any]:
        """
        Choose up to ``max_count`` items for a block while guaranteeing that raw
        (non-intent) transactions get at least ``min_quota`` of the slots whenever
        enough raw items are available.

        This is the *enforcement* side of the escape hatch: a sequencer cannot
        crowd out user (raw) transactions with intent-derived ones, because a
        share of every block is reserved for raw txs before the rest is filled by
        global priority.

        Args:
            raw: ``(item, priority)`` pairs for raw transactions.
            intent: ``(item, priority)`` pairs for intent transactions.
                ``priority`` is fee-per-byte (higher is better); lists need not be
                pre-sorted.
            max_count: Maximum number of items to include.

        Returns:
            The selected items (raw-reserved first, then the best-priced remainder).
        """
        if max_count <= 0:
            return []

        raw_sorted = sorted(raw, key=lambda x: x[1], reverse=True)
        reserved = min(len(raw_sorted), math.ceil(max_count * self.min_quota))

        selected: List[Any] = [item for item, _ in raw_sorted[:reserved]]

        # Fill the remaining slots with the globally best-priced leftovers.
        rest = raw_sorted[reserved:] + list(intent)
        rest.sort(key=lambda x: x[1], reverse=True)
        for item, _ in rest:
            if len(selected) >= max_count:
                break
            selected.append(item)

        return selected
