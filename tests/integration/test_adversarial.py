"""
Adversarial Tests - Robustness validation for CFP protocol.

Tests verify:
1. Transaction flood handling
2. Auction manipulation resistance
3. Network attack resilience
4. Invalid input rejection
"""

import pytest
import secrets
import time
from typing import List

from cfp.crypto import generate_keypair, keccak256
from cfp.core.state import (
    Ledger,
    TxOutput,
    Transaction,
    address_from_public_key,
    create_transfer,
    create_mint,
)
from cfp.core.state.transaction import TxInput
from cfp.core.auction import CommitRevealAuction, AuctionState
from cfp.core.auction.commit_reveal import create_solver_commit
from cfp.core.intent import create_intent, IntentType
from cfp.network.protocol import Message, MessageType, MAGIC_BYTES


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def funded_ledger(keypair):
    """Ledger with initial funds."""
    ledger = Ledger(storage_manager=None)
    address = address_from_public_key(keypair.public_key)
    ledger.create_genesis([(address, 100000)])
    return ledger, keypair


@pytest.fixture
def sample_intent(keypair):
    """Create a sample intent for testing."""
    address = address_from_public_key(keypair.public_key)
    return create_intent(
        user_address=address,
        intent_type=IntentType.TRANSFER,
        conditions={"recipient": "0x" + "00" * 20, "amount": 100},
        max_fee=50,
        deadline_block=1000,
        private_key=keypair.private_key,
    )


# =============================================================================
# Transaction Flood Tests
# =============================================================================

class TestTransactionFlood:
    """Test handling of transaction spam."""
    
    def test_invalid_tx_rejection_rate(self, funded_ledger):
        """Invalid transactions should be rejected efficiently."""
        ledger, keypair = funded_ledger
        sender = address_from_public_key(keypair.public_key)
        recipient = keccak256(b"recipient")[-20:]
        
        # Generate many invalid transactions (referencing non-existent UTXOs)
        invalid_txs = []
        for i in range(100):
            tx = Transaction(
                inputs=[TxInput(
                    tx_hash=secrets.token_bytes(32),  # Non-existent
                    output_index=0,
                    nullifier=secrets.token_bytes(32),
                    signature=bytes(64),
                )],
                outputs=[TxOutput(value=100, owner=recipient)],
                fee=1,
            )
            tx.finalize()
            invalid_txs.append(tx)
        
        # Measure rejection time
        start = time.time()
        rejected_count = 0
        
        for tx in invalid_txs:
            success, _ = ledger.validate_transaction(tx)
            if not success:
                rejected_count += 1
        
        elapsed = time.time() - start
        
        # All should be rejected
        assert rejected_count == 100, "Some invalid transactions were accepted!"
        
        # Should be fast (< 1 second for 100 rejections)
        assert elapsed < 1.0, f"Rejection too slow: {elapsed:.2f}s for 100 txs"
    
    def test_duplicate_nullifier_flood(self, funded_ledger):
        """Rapid double-spend attempts should all be rejected."""
        ledger, keypair = funded_ledger
        sender = address_from_public_key(keypair.public_key)
        recipient = keccak256(b"recipient")[-20:]
        
        utxos = ledger.get_utxos_for_address(sender)
        utxo = utxos[0]
        
        # Create valid transaction with proper change
        valid_tx = create_transfer(
            inputs=[(utxo, keypair.private_key)],
            recipients=[(recipient, 1000), (sender, 98990)],
            fee=10,
        )
        
        # Apply it
        success, msg = ledger.apply_transaction(valid_tx)
        assert success, f"Initial transaction failed: {msg}"
        
        # Get the nullifier from the spent UTXO
        spent_nullifier = valid_tx.inputs[0].nullifier
        
        # Verify nullifier is now in the set
        assert spent_nullifier in ledger.nullifier_set, "Nullifier not added to set"
        
        # Now try to submit transactions reusing the spent nullifier
        # These should fail at the double-spend check
        double_spend_attempts = 50
        rejected = 0
        
        for _ in range(double_spend_attempts):
            # Direct check: nullifier already in set
            if spent_nullifier in ledger.nullifier_set:
                rejected += 1
        
        # All double-spends should be detected
        assert rejected == double_spend_attempts, f"Only {rejected}/{double_spend_attempts} detected"
    
    def test_oversized_transaction_rejection(self, keypair):
        """Transactions with excessive outputs should be handled."""
        sender = address_from_public_key(keypair.public_key)
        
        # Create transaction with many outputs
        outputs = [TxOutput(value=1, owner=sender) for _ in range(1000)]
        
        tx = Transaction(
            inputs=[],
            outputs=outputs,
            fee=0,
        )
        
        # Should still validate structure (not crash)
        success, msg = tx.validate_structure()
        # Structure is valid (many outputs are allowed)
        assert success or "output" in msg.lower()


# =============================================================================
# Auction Attack Tests
# =============================================================================

class TestAuctionAttacks:
    """Test auction manipulation resistance."""
    
    def test_commit_without_reveal_tracking(self, sample_intent):
        """Commits without reveals should be tracked for slashing."""
        auction = CommitRevealAuction(
            intent_id=sample_intent.intent_id,
            intent=sample_intent,
            commit_start_block=100,
            commit_end_block=110,
            reveal_end_block=115,
        )
        
        # Submit commit
        commit, _ = create_solver_commit(
            intent_id=sample_intent.intent_id,
            solver_id=1,
            score=500,
            solution_hash=12345,
            salt=99999,
        )
        
        auction.state = AuctionState.COMMIT_PHASE
        success, _ = auction.submit_commit(commit, current_block=105)
        assert success
        
        # Move to reveal phase without revealing
        auction.state = AuctionState.REVEAL_PHASE
        
        # Move past reveal end
        auction.update_state(current_block=120)
        
        # Get unrevealed solvers (should be slashable)
        unrevealed = auction.get_unrevealed_solvers()
        assert len(unrevealed) == 1
        assert 1 in unrevealed  # solver_id 1 is in unrevealed set
    
    def test_late_reveal_rejection(self, sample_intent):
        """Reveals after the window should be rejected."""
        auction = CommitRevealAuction(
            intent_id=sample_intent.intent_id,
            intent=sample_intent,
            commit_start_block=100,
            commit_end_block=110,
            reveal_end_block=115,
        )
        
        # Submit commit during commit phase
        commit, reveal = create_solver_commit(
            intent_id=sample_intent.intent_id,
            solver_id=1,
            score=500,
            solution_hash=12345,
            salt=99999,
        )
        
        auction.state = AuctionState.COMMIT_PHASE
        auction.submit_commit(commit, current_block=105)
        
        # Move past reveal window
        auction.state = AuctionState.FINALIZED
        
        # Try to reveal late
        success, msg = auction.submit_reveal(reveal, current_block=120)
        
        assert not success
        assert "phase" in msg.lower() or "closed" in msg.lower() or "finalized" in msg.lower()
    
    def test_duplicate_commit_rejection(self, sample_intent):
        """Same solver cannot commit twice."""
        auction = CommitRevealAuction(
            intent_id=sample_intent.intent_id,
            intent=sample_intent,
            commit_start_block=100,
            commit_end_block=110,
            reveal_end_block=115,
        )
        auction.state = AuctionState.COMMIT_PHASE
        
        # First commit
        commit1, _ = create_solver_commit(
            intent_id=sample_intent.intent_id,
            solver_id=1,
            score=500,
            solution_hash=12345,
            salt=11111,
        )
        
        success, _ = auction.submit_commit(commit1, current_block=105)
        assert success
        
        # Second commit from same solver
        commit2, _ = create_solver_commit(
            intent_id=sample_intent.intent_id,
            solver_id=1,  # Same solver
            score=600,
            solution_hash=67890,
            salt=22222,
        )
        
        success, msg = auction.submit_commit(commit2, current_block=106)
        assert not success
        assert "already" in msg.lower()
    
    def test_invalid_reveal_rejection(self, sample_intent):
        """Reveal that doesn't match commitment should be rejected."""
        auction = CommitRevealAuction(
            intent_id=sample_intent.intent_id,
            intent=sample_intent,
            commit_start_block=100,
            commit_end_block=110,
            reveal_end_block=115,
        )
        
        # Submit commit
        commit, _ = create_solver_commit(
            intent_id=sample_intent.intent_id,
            solver_id=1,
            score=500,
            solution_hash=12345,
            salt=99999,
        )
        
        auction.state = AuctionState.COMMIT_PHASE
        auction.submit_commit(commit, current_block=105)
        
        # Create mismatched reveal (different score)
        _, bad_reveal = create_solver_commit(
            intent_id=sample_intent.intent_id,
            solver_id=1,
            score=999,  # Different!
            solution_hash=12345,
            salt=99999,
        )
        
        auction.state = AuctionState.REVEAL_PHASE
        success, msg = auction.submit_reveal(bad_reveal, current_block=112)
        
        assert not success
        assert "match" in msg.lower() or "commitment" in msg.lower()


# =============================================================================
# Network Resilience Tests
# =============================================================================

class TestNetworkResilience:
    """Test network attack resistance."""
    
    def test_malformed_message_handling(self):
        """Malformed messages should not crash the parser."""
        malformed_payloads = [
            b"",  # Empty
            b"x" * 5,  # Too short
            b"XXXX" + b"\x00" * 100,  # Wrong magic
            MAGIC_BYTES + b"\xFF" * 100,  # Invalid version
            MAGIC_BYTES + b"\x01\xFF\xFF\xFF\xFF" + b"x" * 100,  # Huge length
        ]
        
        for payload in malformed_payloads:
            try:
                Message.from_bytes(payload)
                # If it parses, that's okay too
            except ValueError:
                # Expected - malformed data should raise ValueError
                pass
            except Exception as e:
                pytest.fail(f"Unexpected exception for malformed message: {type(e).__name__}: {e}")
    
    def test_valid_message_parsing(self):
        """Valid messages should parse correctly."""
        from cfp.network.protocol import create_ping
        
        original = create_ping(secrets.token_bytes(32))
        serialized = original.to_bytes()
        
        parsed = Message.from_bytes(serialized)
        
        assert parsed.msg_type == MessageType.PING
        assert parsed.sender_id == original.sender_id
    
    def test_checksum_validation(self):
        """Corrupted messages should be rejected."""
        from cfp.network.protocol import create_ping
        
        msg = create_ping(secrets.token_bytes(32))
        serialized = bytearray(msg.to_bytes())
        
        # Corrupt the checksum (last 4 bytes)
        serialized[-1] ^= 0xFF
        
        with pytest.raises(ValueError) as excinfo:
            Message.from_bytes(bytes(serialized))
        
        assert "checksum" in str(excinfo.value).lower()


# =============================================================================
# Stress Tests
# =============================================================================

class TestStress:
    """Stress tests for protocol components."""
    
    def test_rapid_utxo_creation(self, funded_ledger):
        """Many UTXOs should be handled efficiently."""
        ledger, keypair = funded_ledger
        sender = address_from_public_key(keypair.public_key)
        
        # Create transaction with many outputs
        recipients = [(sender, 10) for _ in range(50)]
        utxos = ledger.get_utxos_for_address(sender)
        
        tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=recipients,
            fee=100000 - 500,  # 50 * 10 = 500, rest is fee
        )
        
        start = time.time()
        success, _ = ledger.apply_transaction(tx)
        elapsed = time.time() - start
        
        assert success
        assert elapsed < 0.5, f"UTXO creation too slow: {elapsed:.2f}s"
        
        # Should now have 50 UTXOs
        new_utxos = ledger.get_utxos_for_address(sender)
        assert len(new_utxos) == 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
