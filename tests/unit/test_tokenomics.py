"""
Unit tests for tokenomics module.

Tests cover:
1. Fee calculation
2. Fee distribution
3. Protocol treasury
4. Mock staking
"""

import pytest

from cfp.core.tokenomics import (
    TokenomicsConfig,
    FeeManager,
    FeeReceipt,
    MockStaking,
)


class TestFeeManager:
    """Tests for fee calculation and distribution."""
    
    def test_default_config(self):
        """Default config should have sane values."""
        config = TokenomicsConfig()
        assert config.base_fee_per_byte == 1
        assert config.sequencer_share + config.protocol_share + config.burn_share == pytest.approx(1.0)
    
    def test_calculate_fee_basic(self):
        """Fee should scale with transaction size."""
        fm = FeeManager()
        fee_100 = fm.calculate_fee(tx_size=100)
        fee_200 = fm.calculate_fee(tx_size=200)
        assert fee_200 == 2 * fee_100
    
    def test_calculate_fee_priority(self):
        """Priority fee should apply multiplier."""
        fm = FeeManager()
        normal = fm.calculate_fee(tx_size=100, priority=False)
        priority = fm.calculate_fee(tx_size=100, priority=True)
        assert priority == int(normal * fm.config.priority_multiplier)
    
    def test_process_fee_distribution(self):
        """Fee should be split correctly."""
        fm = FeeManager()
        tx_hash = b"test" * 8
        
        receipt = fm.process_fee(tx_hash, fee=1000)
        
        assert receipt.total_fee == 1000
        assert receipt.sequencer_fee == 700  # 70%
        assert receipt.protocol_fee == 200   # 20%
        assert receipt.burned == 100         # 10%
        assert receipt.sequencer_fee + receipt.protocol_fee + receipt.burned == 1000
    
    def test_process_fee_updates_totals(self):
        """Processing fees should update running totals."""
        fm = FeeManager()
        
        fm.process_fee(b"tx1" * 8, 100)
        fm.process_fee(b"tx2" * 8, 200)
        
        assert fm.total_fees_collected == 300
        assert fm.protocol_treasury == 60  # 20% of 300
    
    def test_stats(self):
        """Stats should return current state."""
        fm = FeeManager()
        fm.process_fee(b"tx" * 8, 1000)
        
        stats = fm.stats()
        assert stats["total_collected"] == 1000
        assert stats["treasury_balance"] == 200


class TestMockStaking:
    """Tests for mock staking system."""
    
    def test_stake_adds_balance(self):
        """Staking should increase balance."""
        staking = MockStaking()
        addr = b"solver" + b"\x00" * 14
        
        staking.stake(addr, 5000)
        assert staking.stakes[addr] == 5000
        
        staking.stake(addr, 5000)
        assert staking.stakes[addr] == 10000
    
    def test_unstake_reduces_balance(self):
        """Unstaking should decrease balance."""
        staking = MockStaking()
        addr = b"solver" + b"\x00" * 14
        
        staking.stake(addr, 10000)
        assert staking.unstake(addr, 3000)
        assert staking.stakes[addr] == 7000
    
    def test_unstake_fails_insufficient(self):
        """Cannot unstake more than staked."""
        staking = MockStaking()
        addr = b"solver" + b"\x00" * 14
        
        staking.stake(addr, 1000)
        assert not staking.unstake(addr, 2000)
    
    def test_is_eligible_sequencer(self):
        """Should check minimum stake requirement."""
        staking = MockStaking()
        addr = b"solver" + b"\x00" * 14
        
        assert not staking.is_eligible_sequencer(addr)
        staking.stake(addr, staking.config.min_stake - 1)
        assert not staking.is_eligible_sequencer(addr)
        staking.stake(addr, 1)
        assert staking.is_eligible_sequencer(addr)
    
    def test_slash_reduces_stake(self):
        """Slashing should reduce stake by percentage."""
        staking = MockStaking()
        addr = b"solver" + b"\x00" * 14
        
        staking.stake(addr, 10000)
        slashed = staking.slash(addr)
        
        assert slashed == 1000  # 10% of 10000
        assert staking.stakes[addr] == 9000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
