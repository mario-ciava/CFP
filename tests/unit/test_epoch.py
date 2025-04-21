"""
Tests for Epoch management.

Tests cover:
1. Epoch lifecycle
2. Intent collection
3. Status transitions
4. Epoch manager
"""

import pytest
from cfp.core.dag.epoch import (
    Epoch,
    EpochManager,
    EpochStatus,
    DEFAULT_EPOCH_DURATION,
)


# =============================================================================
# Mock Intent
# =============================================================================


class MockIntent:
    """Mock intent for testing."""
    def __init__(self, intent_id: bytes):
        self.intent_id = intent_id


# =============================================================================
# Epoch Tests
# =============================================================================


class TestEpochLifecycle:
    """Tests for epoch status transitions."""
    
    def test_epoch_starts_collecting(self):
        """New epoch should start in collecting status."""
        epoch = Epoch(epoch_number=0, start_block=100, end_block=200)
        assert epoch.status == EpochStatus.COLLECTING
    
    def test_epoch_transitions_to_auctioning(self):
        """Epoch should transition when collection window ends."""
        epoch = Epoch(
            epoch_number=0,
            start_block=100,
            end_block=200,
            collection_end_block=150,
        )
        epoch.add_intent(MockIntent(b"\x01" * 32))
        
        # Still collecting
        epoch.update_status(current_block=140)
        assert epoch.status == EpochStatus.COLLECTING
        
        # Transition to auctioning
        epoch.update_status(current_block=150)
        assert epoch.status == EpochStatus.AUCTIONING
    
    def test_epoch_fails_if_no_intents(self):
        """Epoch should fail if no intents when collection ends."""
        epoch = Epoch(
            epoch_number=0,
            start_block=100,
            end_block=200,
            collection_end_block=150,
        )
        
        epoch.update_status(current_block=150)
        assert epoch.status == EpochStatus.FAILED
    
    def test_epoch_freezes_at_end(self):
        """Epoch should freeze at end block."""
        epoch = Epoch(
            epoch_number=0,
            start_block=100,
            end_block=200,
            collection_end_block=150,
        )
        intent = MockIntent(b"\x01" * 32)
        epoch.add_intent(intent)
        epoch.set_auction_result(intent.intent_id, winner_solver_id=1, score=100)
        
        # Move to end
        epoch.update_status(current_block=150)  # -> AUCTIONING
        epoch.update_status(current_block=200)  # -> FROZEN
        
        assert epoch.status == EpochStatus.FROZEN


class TestEpochIntents:
    """Tests for intent management."""
    
    def test_add_intent(self):
        """Should add intent to epoch."""
        epoch = Epoch(epoch_number=0, start_block=100, end_block=200)
        intent = MockIntent(b"\x01" * 32)
        
        success, err = epoch.add_intent(intent)
        
        assert success
        assert epoch.get_intent_count() == 1
    
    def test_add_duplicate_intent_fails(self):
        """Should reject duplicate intent."""
        epoch = Epoch(epoch_number=0, start_block=100, end_block=200)
        intent = MockIntent(b"\x01" * 32)
        
        epoch.add_intent(intent)
        success, err = epoch.add_intent(intent)
        
        assert not success
        assert "already in epoch" in err.lower()
    
    def test_add_intent_when_frozen_fails(self):
        """Should reject intent when epoch is frozen."""
        epoch = Epoch(epoch_number=0, start_block=100, end_block=200)
        epoch.status = EpochStatus.FROZEN
        
        success, err = epoch.add_intent(MockIntent(b"\x01" * 32))
        
        assert not success
    
    def test_set_auction_result(self):
        """Should record auction result."""
        epoch = Epoch(epoch_number=0, start_block=100, end_block=200)
        intent = MockIntent(b"\x01" * 32)
        epoch.add_intent(intent)
        
        epoch.set_auction_result(intent.intent_id, winner_solver_id=5, score=100)
        
        assert epoch.intents[intent.intent_id].auction_result == (5, 100)
        assert intent.intent_id in epoch.execution_order


class TestEpochSeed:
    """Tests for epoch seed computation."""
    
    def test_compute_epoch_seed(self):
        """Should compute deterministic seed."""
        epoch = Epoch(epoch_number=0, start_block=100, end_block=200)
        
        seed1 = epoch.compute_epoch_seed(b"randomness")
        seed2 = epoch.compute_epoch_seed(b"randomness")
        
        assert seed1 == seed2
        assert seed1 > 0
    
    def test_different_randomness_different_seed(self):
        """Different randomness should produce different seed."""
        epoch1 = Epoch(epoch_number=0, start_block=100, end_block=200)
        epoch2 = Epoch(epoch_number=0, start_block=100, end_block=200)
        
        seed1 = epoch1.compute_epoch_seed(b"randomness1")
        seed2 = epoch2.compute_epoch_seed(b"randomness2")
        
        assert seed1 != seed2


# =============================================================================
# EpochManager Tests
# =============================================================================


class TestEpochManager:
    """Tests for epoch manager."""
    
    def test_create_epoch(self):
        """Should create new epoch."""
        manager = EpochManager()
        
        epoch = manager.create_epoch(start_block=100)
        
        assert epoch.epoch_number == 0
        assert epoch.start_block == 100
        assert manager.current_epoch == epoch
    
    def test_create_multiple_epochs(self):
        """Should increment epoch numbers."""
        manager = EpochManager()
        
        e1 = manager.create_epoch(100)
        e2 = manager.create_epoch(200)
        
        assert e1.epoch_number == 0
        assert e2.epoch_number == 1
    
    def test_add_intent_to_active_epoch(self):
        """Should add intent to current epoch."""
        manager = EpochManager()
        manager.create_epoch(100)
        
        intent = MockIntent(b"\x01" * 32)
        epoch_num, err = manager.add_intent(intent, current_block=110)
        
        assert epoch_num == 0
        assert err == ""
    
    def test_add_intent_creates_epoch_if_needed(self):
        """Should create epoch if none active."""
        manager = EpochManager()
        
        intent = MockIntent(b"\x01" * 32)
        epoch_num, err = manager.add_intent(intent, current_block=100)
        
        assert epoch_num == 0
        assert manager.current_epoch is not None
    
    def test_on_new_block_rotates_epoch(self):
        """Should create new epoch when current freezes."""
        manager = EpochManager(epoch_duration=10, collection_window=5)
        manager.create_epoch(100)
        manager.current_epoch.add_intent(MockIntent(b"\x01" * 32))
        manager.current_epoch.set_auction_result(b"\x01" * 32, 1, 100)
        
        # Move past end
        manager.on_new_block(105)  # -> AUCTIONING
        manager.on_new_block(110)  # -> FROZEN + new epoch
        
        assert manager.current_epoch.epoch_number == 1
        assert manager.epochs[0].status == EpochStatus.FROZEN
    
    def test_get_epochs_to_prove(self):
        """Should return frozen epochs."""
        manager = EpochManager()
        e1 = manager.create_epoch(100)
        e1.status = EpochStatus.FROZEN
        e2 = manager.create_epoch(200)
        
        to_prove = manager.get_epochs_to_prove()
        
        assert len(to_prove) == 1
        assert to_prove[0] == e1
    
    def test_stats(self):
        """Should return manager stats."""
        manager = EpochManager()
        manager.create_epoch(100)
        
        stats = manager.stats()
        
        assert stats["total_epochs"] == 1
        assert stats["current_epoch"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
