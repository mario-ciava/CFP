"""
Solver Registry - Identity management for auction participants.

This module provides:
- Solver registration with stake requirements
- Identity verification (Sybil resistance)
- Stake management (deposit, withdraw, bond, slash)

See spec/registry.md for the formal specification.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple
import time

from cfp.crypto import poseidon_bytes, FIELD_PRIME
from cfp.utils.logger import get_logger

logger = get_logger("registry")


# =============================================================================
# Constants
# =============================================================================

# Domain separator for solver ID computation
DOMAIN_SOLVER_ID = 0x10

# Minimum stake required to register
MIN_STAKE = 1000

# Maximum registrations per block (rate limiting)
MAX_REGISTRATIONS_PER_BLOCK = 10

# Cooldown before deregistration (in blocks)
DEREGISTRATION_COOLDOWN = 1000


# =============================================================================
# Enums
# =============================================================================


class StakeState(IntEnum):
    """State of staked tokens."""
    LOCKED = 0      # Available for bonding
    BONDED = 1      # Locked in active execution
    SLASHED = 2     # Confiscated
    WITHDRAWN = 3   # Returned to solver


# =============================================================================
# Data Structures
# =============================================================================


@dataclass
class RegisteredSolver:
    """
    A registered solver in the registry.
    
    Attributes:
        solver_id: Unique identifier (Poseidon hash of pubkey)
        public_key: Solver's public key (64 bytes)
        stake_total: Total stake deposited
        stake_available: Available for bonding
        stake_bonded: Locked in active executions
        registered_at: Registration timestamp
        last_activity: Last activity timestamp
        is_active: Whether solver can participate
        slash_count: Number of times slashed
    """
    solver_id: int
    public_key: bytes
    stake_total: int = 0
    stake_available: int = 0
    stake_bonded: int = 0
    registered_at: int = field(default_factory=lambda: int(time.time()))
    last_activity: int = field(default_factory=lambda: int(time.time()))
    is_active: bool = True
    slash_count: int = 0
    pending_deregistration: bool = False
    deregistration_block: Optional[int] = None
    
    @property
    def solver_id_bytes(self) -> bytes:
        """Get solver_id as 32-byte representation."""
        return self.solver_id.to_bytes(32, byteorder="big")
    
    def can_bond(self, amount: int) -> bool:
        """Check if solver can bond the given amount."""
        return self.is_active and self.stake_available >= amount
    
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = int(time.time())


# =============================================================================
# Solver Registry
# =============================================================================


class SolverRegistry:
    """
    Registry of authorized solvers.
    
    Manages solver identities, stake, and provides Sybil resistance
    through stake requirements.
    """
    
    def __init__(
        self,
        min_stake: int = MIN_STAKE,
        ledger = None,  # Optional ledger for UTXO verification
    ):
        """
        Initialize the registry.
        
        Args:
            min_stake: Minimum stake required to register
            ledger: Optional ledger for stake verification
        """
        self.min_stake = min_stake
        self.ledger = ledger
        
        # Solver ID -> RegisteredSolver
        self.solvers: Dict[int, RegisteredSolver] = {}
        
        # Public key hash -> Solver ID (prevent duplicate registrations)
        self.pubkey_to_solver: Dict[int, int] = {}
        
        # Slashed stake pool (can be redistributed)
        self.slashed_pool: int = 0
        
        # Rate limiting
        self.registrations_this_block: int = 0
        self.current_block: int = 0
        
        logger.info(f"SolverRegistry initialized with min_stake={min_stake}")
    
    # =========================================================================
    # Solver ID Computation
    # =========================================================================
    
    @staticmethod
    def compute_solver_id(public_key: bytes) -> int:
        """
        Compute unique solver ID from public key.
        
        solver_id = Poseidon(DOMAIN_SOLVER_ID, pk_hash)
        
        Args:
            public_key: 64-byte public key
            
        Returns:
            Solver ID as field element
        """
        from cfp.crypto import poseidon2
        pk_hash = poseidon_bytes(public_key)
        return poseidon2(DOMAIN_SOLVER_ID, pk_hash)
    
    # =========================================================================
    # Registration
    # =========================================================================
    
    def register(
        self,
        public_key: bytes,
        initial_stake: int = 0,
        utxo_ids: Optional[List[bytes]] = None,
    ) -> Tuple[Optional[int], str]:
        """
        Register a new solver.
        
        Args:
            public_key: Solver's public key (64 bytes)
            initial_stake: Initial stake amount
            utxo_ids: Optional UTXO IDs to lock as stake
            
        Returns:
            (solver_id, error_message) - solver_id is None on failure
        """
        # Validate public key
        if len(public_key) != 64:
            return None, f"Invalid public key length: {len(public_key)}, expected 64"
        
        # Check rate limiting
        if self.registrations_this_block >= MAX_REGISTRATIONS_PER_BLOCK:
            return None, "Registration rate limit exceeded"
        
        # Compute solver ID
        solver_id = self.compute_solver_id(public_key)
        pk_hash = poseidon_bytes(public_key)
        
        # Check for duplicate registration
        if solver_id in self.solvers:
            return None, "Solver already registered"
        if pk_hash in self.pubkey_to_solver:
            return None, "Public key already registered"
        
        # Verify stake if ledger connected
        # SECURITY: Verify UTXO ownership to prevent using other users' funds as stake
        stake = initial_stake
        if self.ledger and utxo_ids:
            from cfp.crypto import keccak256
            expected_owner = keccak256(public_key)[-20:]
            
            total_value = 0
            for utxo_id in utxo_ids:
                utxo = self.ledger.get_utxo(utxo_id)
                if utxo is None:
                    return None, f"UTXO not found: {utxo_id.hex()}"
                # SECURITY: Verify the registrant owns this UTXO
                if utxo.owner != expected_owner:
                    return None, f"UTXO {utxo_id.hex()[:16]}... not owned by registrant"
                total_value += utxo.value
            stake = total_value
        
        # Check minimum stake
        if stake < self.min_stake:
            return None, f"Insufficient stake: {stake} < {self.min_stake}"
        
        # Create registration
        solver = RegisteredSolver(
            solver_id=solver_id,
            public_key=public_key,
            stake_total=stake,
            stake_available=stake,
        )
        
        self.solvers[solver_id] = solver
        self.pubkey_to_solver[pk_hash] = solver_id
        self.registrations_this_block += 1
        
        logger.info(f"Registered solver {solver_id} with stake {stake}")
        return solver_id, ""
    
    def unregister(
        self,
        solver_id: int,
        current_block: int,
    ) -> Tuple[bool, str]:
        """
        Request deregistration of a solver.
        
        Starts cooldown period before stake can be withdrawn.
        
        Args:
            solver_id: Solver to deregister
            current_block: Current block number
            
        Returns:
            (success, error_message)
        """
        solver = self.solvers.get(solver_id)
        if solver is None:
            return False, "Solver not found"
        
        if solver.stake_bonded > 0:
            return False, f"Cannot deregister: {solver.stake_bonded} stake still bonded"
        
        if solver.pending_deregistration:
            return False, "Deregistration already pending"
        
        solver.pending_deregistration = True
        solver.deregistration_block = current_block + DEREGISTRATION_COOLDOWN
        solver.is_active = False
        
        logger.info(f"Solver {solver_id} deregistration pending until block {solver.deregistration_block}")
        return True, ""
    
    def complete_deregistration(
        self,
        solver_id: int,
        current_block: int,
    ) -> Tuple[int, str]:
        """
        Complete deregistration and return stake.
        
        Args:
            solver_id: Solver to complete deregistration
            current_block: Current block number
            
        Returns:
            (stake_returned, error_message)
        """
        solver = self.solvers.get(solver_id)
        if solver is None:
            return 0, "Solver not found"
        
        if not solver.pending_deregistration:
            return 0, "No pending deregistration"
        
        if solver.deregistration_block and current_block < solver.deregistration_block:
            return 0, f"Cooldown not complete: wait until block {solver.deregistration_block}"
        
        stake_returned = solver.stake_available
        
        # Remove from registry
        pk_hash = poseidon_bytes(solver.public_key)
        del self.solvers[solver_id]
        del self.pubkey_to_solver[pk_hash]
        
        logger.info(f"Solver {solver_id} deregistered, returned {stake_returned} stake")
        return stake_returned, ""
    
    # =========================================================================
    # Lookup
    # =========================================================================
    
    def get_solver(self, solver_id: int) -> Optional[RegisteredSolver]:
        """Get solver by ID."""
        return self.solvers.get(solver_id)
    
    def get_solver_by_pubkey(self, public_key: bytes) -> Optional[RegisteredSolver]:
        """Get solver by public key."""
        pk_hash = poseidon_bytes(public_key)
        solver_id = self.pubkey_to_solver.get(pk_hash)
        if solver_id is None:
            return None
        return self.solvers.get(solver_id)
    
    def is_registered(self, solver_id: int) -> bool:
        """Check if solver is registered."""
        solver = self.solvers.get(solver_id)
        return solver is not None and solver.is_active
    
    def is_registered_pubkey(self, public_key: bytes) -> bool:
        """Check if public key is registered."""
        pk_hash = poseidon_bytes(public_key)
        solver_id = self.pubkey_to_solver.get(pk_hash)
        if solver_id is None:
            return False
        return self.is_registered(solver_id)
    
    # =========================================================================
    # Stake Management
    # =========================================================================
    
    def deposit_stake(
        self,
        solver_id: int,
        amount: int,
        utxo_ids: Optional[List[bytes]] = None,
    ) -> Tuple[bool, str]:
        """
        Deposit additional stake.
        
        Args:
            solver_id: Solver to deposit for
            amount: Amount to deposit
            utxo_ids: Optional UTXO IDs for verification
            
        Returns:
            (success, error_message)
        """
        solver = self.solvers.get(solver_id)
        if solver is None:
            return False, "Solver not found"
        
        if amount <= 0:
            return False, "Amount must be positive"
        
        # Verify UTXOs if ledger connected
        # SECURITY: Verify UTXO ownership to prevent using other users' funds as stake
        if self.ledger and utxo_ids:
            from cfp.crypto import keccak256
            expected_owner = keccak256(solver.public_key)[-20:]
            
            total_value = 0
            for utxo_id in utxo_ids:
                utxo = self.ledger.get_utxo(utxo_id)
                if utxo is None:
                    return False, f"UTXO not found: {utxo_id.hex()}"
                # SECURITY: Verify the solver owns this UTXO
                if utxo.owner != expected_owner:
                    return False, f"UTXO {utxo_id.hex()[:16]}... not owned by solver"
                total_value += utxo.value
            if total_value < amount:
                return False, f"UTXO value {total_value} < deposit amount {amount}"
        
        solver.stake_total += amount
        solver.stake_available += amount
        solver.update_activity()
        
        logger.debug(f"Solver {solver_id} deposited {amount} stake")
        return True, ""
    
    def withdraw_stake(
        self,
        solver_id: int,
        amount: int,
    ) -> Tuple[bool, str]:
        """
        Withdraw available stake.
        
        Args:
            solver_id: Solver to withdraw from
            amount: Amount to withdraw
            
        Returns:
            (success, error_message)
        """
        solver = self.solvers.get(solver_id)
        if solver is None:
            return False, "Solver not found"
        
        if amount <= 0:
            return False, "Amount must be positive"
        
        if solver.stake_available < amount:
            return False, f"Insufficient available stake: {solver.stake_available} < {amount}"
        
        # Check minimum stake maintained
        remaining = solver.stake_total - amount
        if remaining < self.min_stake and solver.is_active:
            return False, f"Would go below minimum stake: {remaining} < {self.min_stake}"
        
        solver.stake_total -= amount
        solver.stake_available -= amount
        solver.update_activity()
        
        logger.debug(f"Solver {solver_id} withdrew {amount} stake")
        return True, ""
    
    def bond_stake(
        self,
        solver_id: int,
        amount: int,
    ) -> Tuple[bool, str]:
        """
        Bond stake for auction participation.
        
        Args:
            solver_id: Solver to bond for
            amount: Amount to bond
            
        Returns:
            (success, error_message)
        """
        solver = self.solvers.get(solver_id)
        if solver is None:
            return False, "Solver not found"
        
        if not solver.is_active:
            return False, "Solver is not active"
        
        if not solver.can_bond(amount):
            return False, f"Cannot bond {amount}: only {solver.stake_available} available"
        
        solver.stake_available -= amount
        solver.stake_bonded += amount
        solver.update_activity()
        
        logger.debug(f"Solver {solver_id} bonded {amount} stake")
        return True, ""
    
    def release_bond(
        self,
        solver_id: int,
        amount: int,
    ) -> Tuple[bool, str]:
        """
        Release bonded stake (after successful execution).
        
        Args:
            solver_id: Solver to release for
            amount: Amount to release
            
        Returns:
            (success, error_message)
        """
        solver = self.solvers.get(solver_id)
        if solver is None:
            return False, "Solver not found"
        
        if solver.stake_bonded < amount:
            return False, f"Cannot release {amount}: only {solver.stake_bonded} bonded"
        
        solver.stake_bonded -= amount
        solver.stake_available += amount
        solver.update_activity()
        
        logger.debug(f"Solver {solver_id} released {amount} bond")
        return True, ""
    
    def slash(
        self,
        solver_id: int,
        amount: int,
        reason: str = "",
    ) -> Tuple[bool, str]:
        """
        Slash solver stake.
        
        Args:
            solver_id: Solver to slash
            amount: Amount to slash
            reason: Reason for slashing
            
        Returns:
            (success, error_message)
        """
        solver = self.solvers.get(solver_id)
        if solver is None:
            return False, "Solver not found"
        
        # Slash from bonded first, then available
        slashed = 0
        
        if solver.stake_bonded >= amount:
            solver.stake_bonded -= amount
            slashed = amount
        else:
            slashed = solver.stake_bonded
            remaining = amount - solver.stake_bonded
            solver.stake_bonded = 0
            
            if solver.stake_available >= remaining:
                solver.stake_available -= remaining
                slashed += remaining
            else:
                slashed += solver.stake_available
                solver.stake_available = 0
        
        solver.stake_total -= slashed
        solver.slash_count += 1
        self.slashed_pool += slashed
        
        logger.warning(f"Slashed solver {solver_id}: {slashed} for '{reason}'")
        
        # Deactivate if below minimum stake
        if solver.stake_total < self.min_stake:
            solver.is_active = False
            logger.warning(f"Solver {solver_id} deactivated: stake below minimum")
        
        return True, ""
    
    # =========================================================================
    # Block Processing
    # =========================================================================
    
    def on_new_block(self, block_number: int) -> None:
        """
        Called when a new block is processed.
        
        Resets rate limiting counters.
        """
        self.current_block = block_number
        self.registrations_this_block = 0
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def stats(self) -> dict:
        """Get registry statistics."""
        active_count = sum(1 for s in self.solvers.values() if s.is_active)
        total_stake = sum(s.stake_total for s in self.solvers.values())
        total_bonded = sum(s.stake_bonded for s in self.solvers.values())
        
        return {
            "total_solvers": len(self.solvers),
            "active_solvers": active_count,
            "total_stake": total_stake,
            "total_bonded": total_bonded,
            "slashed_pool": self.slashed_pool,
            "min_stake": self.min_stake,
        }


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "SolverRegistry",
    "RegisteredSolver",
    "StakeState",
    "MIN_STAKE",
    "DOMAIN_SOLVER_ID",
]
