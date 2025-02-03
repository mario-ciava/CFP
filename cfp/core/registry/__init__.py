"""
CFP Solver Registry Module.

Manages solver identities and stake for auction participation.
"""

from cfp.core.registry.solver_registry import (
    SolverRegistry,
    RegisteredSolver,
    StakeState,
    MIN_STAKE,
    DOMAIN_SOLVER_ID,
)

__all__ = [
    "SolverRegistry",
    "RegisteredSolver",
    "StakeState",
    "MIN_STAKE",
    "DOMAIN_SOLVER_ID",
]
