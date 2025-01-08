"""
CFP Auction Module.

This module provides the auction system for intent execution:
- Scoring and utility computation
- Commit-reveal auction mechanism
- Transcript commitment
- Winner selection
"""

from cfp.core.auction.scoring import (
    compute_utility,
    compute_tie_break,
    compare_solutions,
    select_winner,
    SCALE_FACTOR,
    MAX_UTILITY,
)

__all__ = [
    "compute_utility",
    "compute_tie_break", 
    "compare_solutions",
    "select_winner",
    "SCALE_FACTOR",
    "MAX_UTILITY",
]
