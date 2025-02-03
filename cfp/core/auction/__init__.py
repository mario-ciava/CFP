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

from cfp.core.auction.commit_reveal import (
    CommitRevealAuction,
    SolverCommit,
    SolverReveal,
    RevealedBid,
    AuctionState,
    create_commitment,
    create_solver_commit,
    DEFAULT_COMMIT_WINDOW,
    DEFAULT_REVEAL_WINDOW,
)

__all__ = [
    # Scoring
    "compute_utility",
    "compute_tie_break", 
    "compare_solutions",
    "select_winner",
    "SCALE_FACTOR",
    "MAX_UTILITY",
    # Commit-Reveal
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
