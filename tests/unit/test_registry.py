"""
Tests for Solver Registry.

Tests cover:
1. Registration and deregistration
2. Solver ID computation
3. Stake management
4. Bonding and slashing
"""

import pytest
from cfp.crypto import generate_keypair
from cfp.core.registry import (
    SolverRegistry,
    RegisteredSolver,
    MIN_STAKE,
)


class TestSolverIdComputation:
    """Tests for solver ID computation."""
    
    def test_solver_id_deterministic(self):
        """Same public key produces same solver ID."""
        kp = generate_keypair()
        
        id1 = SolverRegistry.compute_solver_id(kp.public_key)
        id2 = SolverRegistry.compute_solver_id(kp.public_key)
        
        assert id1 == id2
    
    def test_solver_id_different_keys(self):
        """Different keys produce different IDs."""
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        
        id1 = SolverRegistry.compute_solver_id(kp1.public_key)
        id2 = SolverRegistry.compute_solver_id(kp2.public_key)
        
        assert id1 != id2


class TestRegistration:
    """Tests for solver registration."""
    
    def test_register_success(self):
        """Should register solver with sufficient stake."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        
        solver_id, err = registry.register(kp.public_key, initial_stake=500)
        
        assert solver_id is not None
        assert err == ""
        assert registry.is_registered(solver_id)
    
    def test_register_insufficient_stake(self):
        """Should reject registration with insufficient stake."""
        registry = SolverRegistry(min_stake=1000)
        kp = generate_keypair()
        
        solver_id, err = registry.register(kp.public_key, initial_stake=500)
        
        assert solver_id is None
        assert "Insufficient stake" in err
    
    def test_register_duplicate(self):
        """Should reject duplicate registration."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        
        solver_id1, _ = registry.register(kp.public_key, initial_stake=500)
        solver_id2, err = registry.register(kp.public_key, initial_stake=500)
        
        assert solver_id1 is not None
        assert solver_id2 is None
        assert "already registered" in err.lower()
    
    def test_register_invalid_pubkey(self):
        """Should reject invalid public key."""
        registry = SolverRegistry(min_stake=100)
        
        solver_id, err = registry.register(b"short", initial_stake=500)
        
        assert solver_id is None
        assert "Invalid public key" in err


class TestDeregistration:
    """Tests for solver deregistration."""
    
    def test_deregister_requests_cooldown(self):
        """Deregistration should start cooldown."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        success, err = registry.unregister(solver_id, current_block=100)
        
        assert success
        solver = registry.get_solver(solver_id)
        assert solver.pending_deregistration
        assert not solver.is_active
    
    def test_deregister_with_bonded_stake_fails(self):
        """Cannot deregister while stake is bonded."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        # Bond some stake
        registry.bond_stake(solver_id, 100)
        
        success, err = registry.unregister(solver_id, current_block=100)
        
        assert not success
        assert "bonded" in err.lower()
    
    def test_complete_deregistration_after_cooldown(self):
        """Can complete deregistration after cooldown."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        registry.unregister(solver_id, current_block=100)
        
        # Try before cooldown
        stake, err = registry.complete_deregistration(solver_id, current_block=200)
        assert stake == 0
        assert "Cooldown" in err
        
        # Complete after cooldown
        stake, err = registry.complete_deregistration(solver_id, current_block=2000)
        assert stake == 500
        assert not registry.is_registered(solver_id)


class TestStakeManagement:
    """Tests for stake operations."""
    
    def test_deposit_stake(self):
        """Should deposit additional stake."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        success, _ = registry.deposit_stake(solver_id, 200)
        
        assert success
        solver = registry.get_solver(solver_id)
        assert solver.stake_total == 700
        assert solver.stake_available == 700
    
    def test_withdraw_stake(self):
        """Should withdraw available stake."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        success, _ = registry.withdraw_stake(solver_id, 200)
        
        assert success
        solver = registry.get_solver(solver_id)
        assert solver.stake_total == 300
        assert solver.stake_available == 300
    
    def test_withdraw_below_minimum_fails(self):
        """Cannot withdraw below minimum stake."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=200)
        
        success, err = registry.withdraw_stake(solver_id, 150)
        
        assert not success
        assert "minimum" in err.lower()
    
    def test_bond_stake(self):
        """Should bond available stake."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        success, _ = registry.bond_stake(solver_id, 200)
        
        assert success
        solver = registry.get_solver(solver_id)
        assert solver.stake_available == 300
        assert solver.stake_bonded == 200
    
    def test_bond_exceeds_available_fails(self):
        """Cannot bond more than available."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        success, err = registry.bond_stake(solver_id, 600)
        
        assert not success
        assert "Cannot bond" in err
    
    def test_release_bond(self):
        """Should release bonded stake."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        registry.bond_stake(solver_id, 200)
        success, _ = registry.release_bond(solver_id, 200)
        
        assert success
        solver = registry.get_solver(solver_id)
        assert solver.stake_available == 500
        assert solver.stake_bonded == 0


class TestSlashing:
    """Tests for stake slashing."""
    
    def test_slash_from_bonded(self):
        """Should slash from bonded stake first."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        registry.bond_stake(solver_id, 200)
        success, _ = registry.slash(solver_id, 150, reason="test")
        
        assert success
        solver = registry.get_solver(solver_id)
        assert solver.stake_bonded == 50  # 200 - 150
        assert solver.stake_total == 350  # 500 - 150
        assert solver.slash_count == 1
        assert registry.slashed_pool == 150
    
    def test_slash_deactivates_if_below_minimum(self):
        """Should deactivate solver if slashed below minimum."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=150)
        
        registry.slash(solver_id, 100, reason="test")
        
        solver = registry.get_solver(solver_id)
        assert not solver.is_active


class TestQueries:
    """Tests for registry queries."""
    
    def test_get_solver(self):
        """Should get solver by ID."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        solver = registry.get_solver(solver_id)
        
        assert solver is not None
        assert solver.public_key == kp.public_key
    
    def test_get_solver_by_pubkey(self):
        """Should get solver by public key."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        solver_id, _ = registry.register(kp.public_key, initial_stake=500)
        
        solver = registry.get_solver_by_pubkey(kp.public_key)
        
        assert solver is not None
        assert solver.solver_id == solver_id
    
    def test_stats(self):
        """Should return statistics."""
        registry = SolverRegistry(min_stake=100)
        kp = generate_keypair()
        registry.register(kp.public_key, initial_stake=500)
        
        stats = registry.stats()
        
        assert stats["total_solvers"] == 1
        assert stats["active_solvers"] == 1
        assert stats["total_stake"] == 500


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
