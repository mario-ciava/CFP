"""
Unit tests for UTXO ledger, transactions, and Merkle tree.

Tests cover:
1. UTXO creation and commitment
2. Transaction validation
3. Balance conservation
4. Double-spend prevention
5. Merkle tree operations
6. Genesis and state transitions
"""

import pytest
import secrets

from cfp.crypto import generate_keypair
from cfp.core.state import (
    UTXO,
    Transaction,
    TxInput,
    TxOutput,
    Ledger,
    MerkleTree,
    address_from_public_key,
    create_transfer,
    create_mint,
)


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
def ledger():
    """Create an in-memory ledger."""
    return Ledger(data_dir=None)


@pytest.fixture
def funded_ledger(keypair):
    """Create a ledger with initial funding."""
    ledger = Ledger(data_dir=None)
    address = address_from_public_key(keypair.public_key)
    ledger.create_genesis([(address, 1000)])
    return ledger, keypair


# =============================================================================
# UTXO Tests
# =============================================================================


class TestUTXO:
    """Tests for UTXO operations."""
    
    def test_utxo_creation(self):
        """UTXO should be created with valid fields."""
        utxo = UTXO(
            tx_hash=bytes(32),
            output_index=0,
            value=100,
            owner=bytes(20),
            salt=bytes(32),
        )
        
        assert utxo.value == 100
        assert len(utxo.utxo_id) == 33
    
    def test_commitment_deterministic(self):
        """Same UTXO should produce same commitment."""
        utxo1 = UTXO(bytes(32), 0, 100, bytes(20), bytes(32))
        utxo2 = UTXO(bytes(32), 0, 100, bytes(20), bytes(32))
        
        assert utxo1.compute_commitment() == utxo2.compute_commitment()
    
    def test_commitment_differs_with_value(self):
        """Different values should produce different commitments."""
        utxo1 = UTXO(bytes(32), 0, 100, bytes(20), bytes(32))
        utxo2 = UTXO(bytes(32), 0, 200, bytes(20), bytes(32))
        
        assert utxo1.compute_commitment() != utxo2.compute_commitment()
    
    def test_nullifier_requires_private_key(self, keypair):
        """Nullifier computation should require private key."""
        address = address_from_public_key(keypair.public_key)
        utxo = UTXO(bytes(32), 0, 100, address, secrets.token_bytes(32))
        
        nullifier = utxo.compute_nullifier(keypair.private_key)
        assert len(nullifier) == 32
    
    def test_nullifier_differs_per_key(self, keypair, second_keypair):
        """Different keys should produce different nullifiers."""
        utxo = UTXO(bytes(32), 0, 100, bytes(20), bytes(32))
        
        n1 = utxo.compute_nullifier(keypair.private_key)
        n2 = utxo.compute_nullifier(second_keypair.private_key)
        
        assert n1 != n2
    
    def test_serialization_roundtrip(self):
        """UTXO should survive serialization."""
        original = UTXO(
            tx_hash=secrets.token_bytes(32),
            output_index=5,
            value=12345,
            owner=secrets.token_bytes(20),
            salt=secrets.token_bytes(32),
        )
        
        data = original.to_bytes()
        restored = UTXO.from_bytes(data)
        
        assert restored.tx_hash == original.tx_hash
        assert restored.output_index == original.output_index
        assert restored.value == original.value
        assert restored.owner == original.owner
        assert restored.salt == original.salt


# =============================================================================
# Merkle Tree Tests
# =============================================================================


class TestMerkleTree:
    """Tests for Merkle tree operations."""
    
    def test_empty_tree(self):
        """Empty tree should have empty root."""
        tree = MerkleTree()
        assert tree.root() == bytes(32)
    
    def test_single_leaf(self):
        """Single leaf should produce non-empty root."""
        tree = MerkleTree()
        leaf = secrets.token_bytes(32)
        tree.insert(leaf)
        
        # Root should be computed (not empty)
        assert tree.root() != bytes(32)
        assert len(tree.root()) == 32
    
    def test_deterministic_root(self):
        """Same leaves should produce same root."""
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        
        leaves = [secrets.token_bytes(32) for _ in range(5)]
        for leaf in leaves:
            tree1.insert(leaf)
            tree2.insert(leaf)
        
        assert tree1.root() == tree2.root()
    
    def test_different_order_different_root(self):
        """Different order should produce different root."""
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        
        leaves = [secrets.token_bytes(32) for _ in range(3)]
        
        for leaf in leaves:
            tree1.insert(leaf)
        for leaf in reversed(leaves):
            tree2.insert(leaf)
        
        assert tree1.root() != tree2.root()
    
    def test_proof_generation_and_verification(self):
        """Proofs should verify correctly."""
        tree = MerkleTree()
        leaves = [secrets.token_bytes(32) for _ in range(8)]
        
        for leaf in leaves:
            tree.insert(leaf)
        
        root = tree.root()
        
        # Verify each leaf
        for i, leaf in enumerate(leaves):
            proof = tree.prove(i)
            assert MerkleTree.verify(leaf, proof, root)
    
    def test_invalid_proof_fails(self):
        """Tampered proof should fail verification."""
        tree = MerkleTree()
        leaves = [secrets.token_bytes(32) for _ in range(4)]
        
        for leaf in leaves:
            tree.insert(leaf)
        
        proof = tree.prove(0)
        root = tree.root()
        
        # Tamper with leaf
        fake_leaf = secrets.token_bytes(32)
        assert not MerkleTree.verify(fake_leaf, proof, root)


# =============================================================================
# Transaction Tests
# =============================================================================


class TestTransaction:
    """Tests for transaction operations."""
    
    def test_mint_transaction(self):
        """Mint transaction should have no inputs."""
        address = bytes(20)
        tx = create_mint(address, 1000)
        
        assert len(tx.inputs) == 0
        assert len(tx.outputs) == 1
        assert tx.outputs[0].value == 1000
        assert tx.fee == 0
    
    def test_transfer_transaction(self, keypair, second_keypair):
        """Transfer should consume input and create output."""
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        # Create a UTXO to spend
        utxo = UTXO(
            tx_hash=secrets.token_bytes(32),
            output_index=0,
            value=100,
            owner=sender_addr,
            salt=secrets.token_bytes(32),
        )
        
        # Create transfer
        tx = create_transfer(
            inputs=[(utxo, keypair.private_key)],
            recipients=[(recipient_addr, 90)],
            fee=10,
        )
        
        assert len(tx.inputs) == 1
        assert len(tx.outputs) == 1
        assert tx.fee == 10
        assert tx.outputs[0].value == 90


# =============================================================================
# Ledger Tests
# =============================================================================


class TestLedger:
    """Tests for ledger operations."""
    
    def test_genesis_creation(self, keypair):
        """Genesis should create initial UTXOs."""
        ledger = Ledger(data_dir=None)
        address = address_from_public_key(keypair.public_key)
        
        ledger.create_genesis([(address, 1000)])
        
        assert ledger.get_balance(address) == 1000
        assert len(ledger.utxo_set) == 1
    
    def test_balance_after_transfer(self, funded_ledger, second_keypair):
        """Balance should update after transfer."""
        ledger, keypair = funded_ledger
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        # Get sender's UTXO
        utxos = ledger.get_utxos_for_address(sender_addr)
        assert len(utxos) == 1
        utxo = utxos[0]
        
        # Transfer 400, fee 10
        tx = create_transfer(
            inputs=[(utxo, keypair.private_key)],
            recipients=[
                (recipient_addr, 400),
                (sender_addr, 590),  # Change back
            ],
            fee=10,
        )
        
        success, msg = ledger.apply_transaction(tx)
        assert success, msg
        
        assert ledger.get_balance(sender_addr) == 590
        assert ledger.get_balance(recipient_addr) == 400
    
    def test_double_spend_rejected(self, funded_ledger, second_keypair):
        """Second spend of same UTXO should fail."""
        ledger, keypair = funded_ledger
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        utxos = ledger.get_utxos_for_address(sender_addr)
        utxo = utxos[0]
        
        # First transfer
        tx1 = create_transfer(
            inputs=[(utxo, keypair.private_key)],
            recipients=[(recipient_addr, 990)],
            fee=10,
        )
        success1, _ = ledger.apply_transaction(tx1)
        assert success1
        
        # Second transfer with same UTXO (double-spend attempt)
        tx2 = create_transfer(
            inputs=[(utxo, keypair.private_key)],
            recipients=[(recipient_addr, 990)],
            fee=10,
        )
        success2, msg = ledger.apply_transaction(tx2)
        assert not success2
        # UTXO is removed after first spend, so second fails at existence check
        assert "not found" in msg or "Double-spend" in msg
    
    def test_insufficient_funds_rejected(self, funded_ledger, second_keypair):
        """Transaction exceeding balance should fail."""
        ledger, keypair = funded_ledger
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        utxos = ledger.get_utxos_for_address(sender_addr)
        utxo = utxos[0]
        
        # Try to spend more than available
        tx = create_transfer(
            inputs=[(utxo, keypair.private_key)],
            recipients=[(recipient_addr, 2000)],  # More than 1000
            fee=10,
        )
        
        is_valid, msg = ledger.validate_transaction(tx)
        assert not is_valid
        assert "Balance mismatch" in msg
    
    def test_state_root_changes(self, funded_ledger, second_keypair):
        """State root should change after transaction."""
        ledger, keypair = funded_ledger
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        root_before = ledger.state_root
        
        utxos = ledger.get_utxos_for_address(sender_addr)
        tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=[(recipient_addr, 990)],
            fee=10,
        )
        ledger.apply_transaction(tx)
        
        root_after = ledger.state_root
        assert root_before != root_after
    
    def test_multiple_inputs(self, keypair, second_keypair):
        """Transaction can consume multiple inputs."""
        ledger = Ledger(data_dir=None)
        sender_addr = address_from_public_key(keypair.public_key)
        recipient_addr = address_from_public_key(second_keypair.public_key)
        
        # Genesis with two outputs to same address
        tx = Transaction(
            inputs=[],
            outputs=[
                TxOutput(value=500, owner=sender_addr),
                TxOutput(value=500, owner=sender_addr),
            ],
            fee=0,
        )
        tx.finalize()
        ledger.apply_transaction(tx, validate=False)
        
        # Get both UTXOs
        utxos = ledger.get_utxos_for_address(sender_addr)
        assert len(utxos) == 2
        
        # Spend both
        transfer = create_transfer(
            inputs=[(u, keypair.private_key) for u in utxos],
            recipients=[(recipient_addr, 990)],
            fee=10,
        )
        
        success, msg = ledger.apply_transaction(transfer)
        assert success, msg
        assert ledger.get_balance(recipient_addr) == 990
        assert ledger.get_balance(sender_addr) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
