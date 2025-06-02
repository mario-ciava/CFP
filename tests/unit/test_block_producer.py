"""
Unit tests for BlockProducer module.

Tests cover:
1. Block creation
2. Mempool management
3. Fee integration
4. Transaction ordering by priority
5. Block application
"""

import pytest
import secrets

from cfp.crypto import generate_keypair
from cfp.core.block_producer import BlockProducer, Block, Mempool
from cfp.core.state import (
    Ledger,
    Transaction,
    TxInput,
    TxOutput,
    address_from_public_key,
    create_transfer,
)
from cfp.core.tokenomics import FeeManager


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def keypair():
    """Generate a test keypair."""
    return generate_keypair()


@pytest.fixture
def second_keypair():
    """Generate a second test keypair."""
    return generate_keypair()


@pytest.fixture
def fee_manager():
    """Create a fee manager."""
    return FeeManager()


@pytest.fixture
def ledger(fee_manager):
    """Create a ledger with fee manager."""
    return Ledger(storage_manager=None, fee_manager=fee_manager)


@pytest.fixture
def funded_producer(keypair, fee_manager):
    """Create a block producer with funded ledger."""
    ledger = Ledger(storage_manager=None, fee_manager=fee_manager)
    address = address_from_public_key(keypair.public_key)
    ledger.create_genesis([(address, 10000)])
    producer = BlockProducer(ledger=ledger, fee_manager=fee_manager)
    return producer, keypair


# =============================================================================
# Mempool Tests
# =============================================================================


class TestMempool:
    """Tests for mempool operations."""
    
    def test_add_transaction(self, keypair):
        """Should add transaction to mempool."""
        mempool = Mempool()
        address = address_from_public_key(keypair.public_key)
        
        tx = Transaction(
            inputs=[],
            outputs=[TxOutput(value=100, owner=address)],
            fee=10,
        )
        tx.finalize()
        
        success, msg = mempool.add(tx)
        assert success, msg
        assert len(mempool) == 1
    
    def test_reject_duplicate(self, keypair):
        """Should reject duplicate transaction."""
        mempool = Mempool()
        address = address_from_public_key(keypair.public_key)
        
        tx = Transaction(
            inputs=[],
            outputs=[TxOutput(value=100, owner=address)],
            fee=10,
        )
        tx.finalize()
        
        mempool.add(tx)
        success, msg = mempool.add(tx)
        assert not success
        assert "already" in msg.lower()
    
    def test_max_size_enforcement(self, keypair):
        """Should reject when full."""
        mempool = Mempool(max_size=2)
        address = address_from_public_key(keypair.public_key)
        
        for i in range(2):
            tx = Transaction(
                inputs=[],
                outputs=[TxOutput(value=100, owner=address, salt=secrets.token_bytes(32))],
                fee=i,
            )
            tx.finalize()
            success, _ = mempool.add(tx)
            assert success
        
        # Third should fail
        tx = Transaction(
            inputs=[],
            outputs=[TxOutput(value=100, owner=address, salt=secrets.token_bytes(32))],
            fee=100,
        )
        tx.finalize()
        success, msg = mempool.add(tx)
        assert not success
        assert "full" in msg.lower()
    
    def test_priority_ordering(self, keypair):
        """Should order by fee priority."""
        mempool = Mempool()
        address = address_from_public_key(keypair.public_key)
        
        # Add low fee tx first
        tx_low = Transaction(
            inputs=[],
            outputs=[TxOutput(value=100, owner=address, salt=secrets.token_bytes(32))],
            fee=1,
        )
        tx_low.finalize()
        mempool.add(tx_low)
        
        # Add high fee tx second
        tx_high = Transaction(
            inputs=[],
            outputs=[TxOutput(value=100, owner=address, salt=secrets.token_bytes(32))],
            fee=100,
        )
        tx_high.finalize()
        mempool.add(tx_high)
        
        # High fee should come first
        ordered = mempool.get_prioritized(2)
        assert ordered[0].tx_hash == tx_high.tx_hash
        assert ordered[1].tx_hash == tx_low.tx_hash


# =============================================================================
# Block Tests
# =============================================================================


class TestBlock:
    """Tests for block structure."""
    
    def test_block_hash_deterministic(self, keypair):
        """Block hash should be deterministic."""
        address = address_from_public_key(keypair.public_key)
        tx = Transaction(
            inputs=[],
            outputs=[TxOutput(value=100, owner=address)],
            fee=0,
        )
        tx.finalize()
        
        block1 = Block(
            height=1,
            prev_state_root=bytes(32),
            state_root=bytes(32),
            transactions=[tx],
            timestamp=12345,
            producer=address,
        )
        block1.finalize()
        
        block2 = Block(
            height=1,
            prev_state_root=bytes(32),
            state_root=bytes(32),
            transactions=[tx],
            timestamp=12345,
            producer=address,
        )
        block2.finalize()
        
        assert block1.block_hash == block2.block_hash


# =============================================================================
# BlockProducer Tests
# =============================================================================


class TestBlockProducer:
    """Tests for block production."""
    
    def test_submit_valid_transaction(self, funded_producer, second_keypair):
        """Should accept valid transaction."""
        producer, keypair = funded_producer
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        utxos = producer.ledger.get_utxos_for_address(sender_addr)
        tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=[(recipient_addr, 9990)],
            fee=10,
        )
        
        success, msg = producer.submit_transaction(tx)
        assert success, msg
        assert len(producer.mempool) == 1
    
    def test_submit_invalid_transaction(self, funded_producer, second_keypair):
        """Should reject invalid transaction."""
        producer, keypair = funded_producer
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        # Create tx with non-existent input
        tx = Transaction(
            inputs=[TxInput(
                tx_hash=secrets.token_bytes(32),
                output_index=0,
                nullifier=secrets.token_bytes(32),
                signature=bytes(64),
            )],
            outputs=[TxOutput(value=100, owner=recipient_addr)],
            fee=10,
        )
        tx.finalize()
        
        success, msg = producer.submit_transaction(tx)
        assert not success
    
    def test_produce_block(self, funded_producer, second_keypair):
        """Should produce a valid block."""
        producer, keypair = funded_producer
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        # Submit a transaction
        utxos = producer.ledger.get_utxos_for_address(sender_addr)
        tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=[(recipient_addr, 9990)],
            fee=10,
        )
        producer.submit_transaction(tx)
        
        # Produce block
        block, msg = producer.produce_block(sequencer_address=sender_addr)
        
        assert block is not None, msg
        assert len(block.transactions) == 1
        assert block.height == 1
        assert block.total_fees == 10
        assert producer.ledger.block_height == 1
    
    def test_fee_distribution(self, funded_producer, second_keypair):
        """Should distribute fees through FeeManager."""
        producer, keypair = funded_producer
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        # Submit a transaction with fee
        utxos = producer.ledger.get_utxos_for_address(sender_addr)
        tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=[(recipient_addr, 9000)],
            fee=1000,
        )
        producer.submit_transaction(tx)
        
        # Produce block
        block, _ = producer.produce_block(sequencer_address=sender_addr)
        
        # Check fee manager stats
        stats = producer.fee_manager.stats()
        assert stats["total_collected"] == 1000
        assert stats["sequencer_share"] == 700  # 70%
        assert stats["total_burned"] == 100  # 10%
    
    def test_mempool_cleared_after_block(self, funded_producer, second_keypair):
        """Should remove included transactions from mempool."""
        producer, keypair = funded_producer
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        utxos = producer.ledger.get_utxos_for_address(sender_addr)
        tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=[(recipient_addr, 9990)],
            fee=10,
        )
        producer.submit_transaction(tx)
        assert len(producer.mempool) == 1
        
        producer.produce_block(sequencer_address=sender_addr)
        assert len(producer.mempool) == 0
    
    def test_stats(self, funded_producer, second_keypair):
        """Should track production statistics."""
        producer, keypair = funded_producer
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        utxos = producer.ledger.get_utxos_for_address(sender_addr)
        tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=[(recipient_addr, 9990)],
            fee=10,
        )
        producer.submit_transaction(tx)
        producer.produce_block(sequencer_address=sender_addr)
        
        stats = producer.stats()
        assert stats["blocks_produced"] == 1
        assert stats["total_tx_processed"] == 1
        assert stats["total_fees_collected"] == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
