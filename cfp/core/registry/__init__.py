"""
CFP Solver Registry Module.

Manages solver identities and stake for auction participation.
"""

from cfp.core.registry.solver_registry import (
    DOMAIN_SOLVER_ID,
    MIN_STAKE,
    RegisteredSolver,
    SolverRegistry,
    StakeState,
)

__all__ = [
    "SolverRegistry",
    "RegisteredSolver",
    "StakeState",
    "MIN_STAKE",
    "DOMAIN_SOLVER_ID",
]
