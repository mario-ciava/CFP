"""
Unit tests for intent layer.

Tests cover:
1. Intent creation and signing
2. Auction bidding
3. Winner selection
4. Execution reporting
5. Slashing
"""

import pytest
import json

from cfp.crypto import generate_keypair
from cfp.core.intent import (
    Intent,
    IntentType,
    ExecutionTicket,
    TicketStatus,
    SolverBid,
    AuctionManager,
    AuctionConfig,
    create_intent,
    MockSolver,
)
from cfp.core.state import address_from_public_key


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def user_keypair():
    return generate_keypair()


@pytest.fixture
def solver_keypair():
    return generate_keypair()


@pytest.fixture
def auction_manager():
    return AuctionManager(AuctionConfig(min_bond=100, execution_window=10))


@pytest.fixture
def sample_intent(user_keypair):
    return create_intent(
        user_address=address_from_public_key(user_keypair.public_key),
        intent_type=IntentType.TRANSFER,
        conditions={"recipient": "0x" + "ab" * 20, "amount": 100},
        max_fee=50,
        deadline_block=1000,
        private_key=user_keypair.private_key,
    )


# =============================================================================
# Intent Tests
# =============================================================================


class TestIntent:
    """Tests for Intent creation."""
    
    def test_create_intent(self, user_keypair):
        """Should create signed intent."""
        intent = create_intent(
            user_address=address_from_public_key(user_keypair.public_key),
            intent_type=IntentType.SWAP,
            conditions={"token_in": "A", "token_out": "B"},
            max_fee=100,
            deadline_block=500,
            private_key=user_keypair.private_key,
        )
        
        assert intent.intent_id
        assert intent.signature
        assert intent.intent_type == IntentType.SWAP
    
    def test_intent_id_deterministic(self, user_keypair):
        """Same intent should produce same ID."""
        addr = address_from_public_key(user_keypair.public_key)
        
        # Create two intents with same values including nonce
        i1 = Intent(
            user=addr,
            intent_type=IntentType.TRANSFER,
            conditions=b'{"a": 1}',
            max_fee=50,
            deadline_block=100,
            nonce=12345,  # Explicit nonce for determinism
            chain_id=1,
            created_at=12345,
        )
        i2 = Intent(
            user=addr,
            intent_type=IntentType.TRANSFER,
            conditions=b'{"a": 1}',
            max_fee=50,
            deadline_block=100,
            nonce=12345,  # Same nonce
            chain_id=1,
            created_at=12345,
        )
        
        assert i1.compute_intent_id() == i2.compute_intent_id()
    
    def test_intent_expiration(self, sample_intent):
        """Intent should expire after deadline."""
        assert not sample_intent.is_expired(999)
        assert sample_intent.is_expired(1001)


# =============================================================================
# Auction Tests
# =============================================================================


class TestAuction:
    """Tests for auction mechanism."""
    
    def test_submit_intent(self, auction_manager, sample_intent):
        """Should accept intent submission."""
        success, msg = auction_manager.submit_intent(sample_intent)
        
        assert success
        assert len(auction_manager.active_auctions) == 1
    
    def test_submit_bid(self, auction_manager, sample_intent, solver_keypair):
        """Should accept valid bid."""
        auction_manager.submit_intent(sample_intent)
        
        solver_addr = address_from_public_key(solver_keypair.public_key)
        auction_manager.deposit_bond(solver_addr, 200)
        
        bid = SolverBid(
            intent_id=sample_intent.intent_id,
            solver=solver_addr,
            fee_bid=40,
            bond=100,
        )
        
        success, msg = auction_manager.submit_bid(bid)
        assert success
    
    def test_reject_bid_exceeding_max_fee(self, auction_manager, sample_intent, solver_keypair):
        """Should reject bid above max_fee."""
        auction_manager.submit_intent(sample_intent)
        
        solver_addr = address_from_public_key(solver_keypair.public_key)
        auction_manager.deposit_bond(solver_addr, 200)
        
        bid = SolverBid(
            intent_id=sample_intent.intent_id,
            solver=solver_addr,
            fee_bid=100,  # max_fee is 50
            bond=100,
        )
        
        success, msg = auction_manager.submit_bid(bid)
        assert not success
        assert "exceeds max_fee" in msg
    
    def test_winner_selection(self, auction_manager, sample_intent):
        """Highest bidder should win."""
        auction_manager.submit_intent(sample_intent)
        
        # Create two solvers with different bids
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        addr1 = address_from_public_key(kp1.public_key)
        addr2 = address_from_public_key(kp2.public_key)
        
        auction_manager.deposit_bond(addr1, 200)
        auction_manager.deposit_bond(addr2, 200)
        
        bid1 = SolverBid(intent_id=sample_intent.intent_id, solver=addr1, fee_bid=30, bond=100)
        bid2 = SolverBid(intent_id=sample_intent.intent_id, solver=addr2, fee_bid=40, bond=100)
        
        auction_manager.submit_bid(bid1)
        auction_manager.submit_bid(bid2)
        
        ticket = auction_manager.resolve_auction(sample_intent.intent_id, current_block=10)
        
        assert ticket is not None
        assert ticket.solver == addr2  # Higher bidder
        assert ticket.fee_bid == 40
    
    def test_execution_reporting(self, auction_manager, sample_intent, solver_keypair):
        """Should track successful execution."""
        auction_manager.submit_intent(sample_intent)
        
        solver_addr = address_from_public_key(solver_keypair.public_key)
        auction_manager.deposit_bond(solver_addr, 200)
        
        bid = SolverBid(intent_id=sample_intent.intent_id, solver=solver_addr, fee_bid=40, bond=100)
        auction_manager.submit_bid(bid)
        
        ticket = auction_manager.resolve_auction(sample_intent.intent_id, current_block=10)
        
        # Report execution
        tx_hash = bytes(32)
        success, msg = auction_manager.report_execution(ticket.ticket_id, tx_hash)
        
        assert success
        assert len(auction_manager.completed_tickets) == 1
        assert auction_manager.completed_tickets[0].status == TicketStatus.EXECUTED
    
    def test_slashing(self, auction_manager, sample_intent, solver_keypair):
        """Should slash solver on timeout."""
        auction_manager.submit_intent(sample_intent)
        
        solver_addr = address_from_public_key(solver_keypair.public_key)
        auction_manager.deposit_bond(solver_addr, 200)
        
        bid = SolverBid(intent_id=sample_intent.intent_id, solver=solver_addr, fee_bid=40, bond=100)
        auction_manager.submit_bid(bid)
        
        ticket = auction_manager.resolve_auction(sample_intent.intent_id, current_block=10)
        
        # Bond should be locked
        assert auction_manager.get_solver_bond(solver_addr) == 100  # 200 - 100
        
        # Simulate timeout (deadline was block 20, now at 25)
        slashed = auction_manager.check_expired_tickets(current_block=25)
        
        assert len(slashed) == 1
        assert slashed[0].status == TicketStatus.SLASHED
        assert auction_manager.slashed_pool == 50  # 50% of 100


# =============================================================================
# Mock Solver Tests
# =============================================================================


class TestMockSolver:
    """Tests for mock solver."""
    
    def test_create_bid(self, sample_intent):
        """Solver should create valid bid."""
        solver = MockSolver()
        bid = solver.create_bid(sample_intent)
        
        assert bid.intent_id == sample_intent.intent_id
        assert bid.fee_bid == 45  # 90% of 50
        assert bid.solver == solver.address


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
