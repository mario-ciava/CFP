"""
Security-focused unit tests for CFP.

Tests verify:
1. Signature verification rejects invalid signatures
2. Mint transactions rejected after genesis
3. Double-spend prevention
4. [NEW] apply_transaction checks signatures by default
5. [NEW] Block application is atomic with rollback
6. [NEW] Registry verifies UTXO ownership
7. [NEW] Nullifier includes UTXO ID for uniqueness
8. [NEW] Value bounds are enforced
"""

import pytest
import secrets

from cfp.crypto import generate_keypair, keccak256
from cfp.core.state import (
    Ledger,
    TxOutput,
    Transaction,
    address_from_public_key,
    create_transfer,
    create_mint,
)
from cfp.core.state.transaction import TxInput, MAX_VALUE


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def second_keypair():
    return generate_keypair()


@pytest.fixture
def funded_ledger(keypair):
    """Ledger with initial funds after genesis."""
    ledger = Ledger(storage_manager=None)
    address = address_from_public_key(keypair.public_key)
    ledger.create_genesis([(address, 1000)])
    return ledger, keypair


class TestMintAuthorization:
    """Tests for mint transaction restrictions."""
    
    def test_mint_allowed_at_genesis(self, keypair):
        """Mint should succeed during genesis (block 0)."""
        ledger = Ledger(storage_manager=None)
        address = address_from_public_key(keypair.public_key)
        
        # Genesis mint should work
        tx = ledger.create_genesis([(address, 1000)])
        assert tx is not None
        assert ledger.get_balance(address) == 1000
    
    def test_mint_rejected_after_genesis(self, funded_ledger, second_keypair):
        """Mint should fail after block 0."""
        ledger, _ = funded_ledger
        recipient = address_from_public_key(second_keypair.public_key)
        
        # Ledger is now past genesis (block 0)
        # Increment block height to simulate post-genesis
        ledger.block_height = 1
        
        # Attempt mint
        mint_tx = create_mint(recipient, 1000)
        success, msg = ledger.validate_transaction(mint_tx)
        
        assert not success
        assert "genesis" in msg.lower()


class TestSignatureVerification:
    """Tests for transaction signature verification."""
    
    def test_valid_signature_accepted(self, funded_ledger, second_keypair):
        """Transaction with valid signature should be accepted."""
        ledger, keypair = funded_ledger
        sender = address_from_public_key(keypair.public_key)
        recipient = address_from_public_key(second_keypair.public_key)
        
        utxos = ledger.get_utxos_for_address(sender)
        tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=[(recipient, 990)],
            fee=10,
        )
        
        # Should validate with signature checking enabled
        success, msg = ledger.validate_transaction(tx, check_signatures=True)
        assert success, f"Valid transaction rejected: {msg}"
    
    def test_wrong_key_signature_rejected(self, funded_ledger, second_keypair):
        """Transaction signed with wrong key should be rejected."""
        ledger, keypair = funded_ledger
        sender = address_from_public_key(keypair.public_key)
        recipient = address_from_public_key(second_keypair.public_key)
        
        utxos = ledger.get_utxos_for_address(sender)
        
        # Create transaction with correct UTXO but sign with WRONG key
        utxo = utxos[0]
        nullifier = utxo.compute_nullifier(second_keypair.private_key)  # Wrong key for nullifier too
        
        tx = Transaction(
            inputs=[TxInput(
                tx_hash=utxo.tx_hash,
                output_index=utxo.output_index,
                nullifier=nullifier,
                signature=bytes(64),
            )],
            outputs=[TxOutput(value=990, owner=recipient)],
            fee=10,
        )
        tx.sign_input(0, second_keypair.private_key)  # Sign with wrong key
        tx.finalize()
        
        # Should fail signature verification
        success, msg = ledger.validate_transaction(tx, check_signatures=True)
        assert not success
        assert "signature" in msg.lower() or "owner" in msg.lower()


class TestApplyTransactionSecurity:
    """Security tests for apply_transaction signature checking."""
    
    def test_apply_transaction_checks_signatures_by_default(self, funded_ledger, second_keypair):
        """apply_transaction should verify signatures by default."""
        ledger, keypair = funded_ledger
        sender = address_from_public_key(keypair.public_key)
        recipient = address_from_public_key(second_keypair.public_key)
        
        utxos = ledger.get_utxos_for_address(sender)
        utxo = utxos[0]
        
        # Create transaction signed with WRONG key (attacker's key)
        # This simulates an attacker trying to spend someone else's UTXO
        nullifier = utxo.compute_nullifier(second_keypair.private_key)
        
        tx = Transaction(
            inputs=[TxInput(
                tx_hash=utxo.tx_hash,
                output_index=utxo.output_index,
                nullifier=nullifier,
                signature=bytes(64),
            )],
            outputs=[TxOutput(value=990, owner=recipient)],
            fee=10,
        )
        tx.sign_input(0, second_keypair.private_key)
        tx.finalize()
        
        # SECURITY: apply_transaction should reject this by default
        success, msg = ledger.apply_transaction(tx)
        assert not success, "apply_transaction accepted unauthorized transaction!"
        assert "signature" in msg.lower() or "owner" in msg.lower()


class TestBlockAtomicity:
    """Tests for atomic block application with rollback."""
    
    def test_block_rollback_on_failure(self, funded_ledger, second_keypair):
        """Block with failing transaction should roll back all changes."""
        ledger, keypair = funded_ledger
        sender = address_from_public_key(keypair.public_key)
        recipient = address_from_public_key(second_keypair.public_key)
        
        utxos = ledger.get_utxos_for_address(sender)
        
        # Create a valid transaction
        valid_tx = create_transfer(
            inputs=[(utxos[0], keypair.private_key)],
            recipients=[(recipient, 500)],
            fee=10,
        )
        
        # Create an invalid transaction (referencing non-existent UTXO)
        invalid_tx = Transaction(
            inputs=[TxInput(
                tx_hash=secrets.token_bytes(32),  # Non-existent
                output_index=0,
                nullifier=secrets.token_bytes(32),
                signature=bytes(64),
            )],
            outputs=[TxOutput(value=100, owner=recipient)],
            fee=10,
        )
        invalid_tx.finalize()
        
        # Record state before block
        original_balance = ledger.get_balance(sender)
        original_utxo_count = len(ledger.utxo_set)
        original_block_height = ledger.block_height
        
        # Apply block with [valid, invalid] - should fail and rollback
        success, msg = ledger.apply_block([valid_tx, invalid_tx])
        assert not success
        
        # SECURITY: State should be rolled back
        assert ledger.get_balance(sender) == original_balance, "Balance changed after failed block!"
        assert len(ledger.utxo_set) == original_utxo_count, "UTXO set changed after failed block!"
        assert ledger.block_height == original_block_height, "Block height changed after failed block!"


class TestRegistryUTXOOwnership:
    """Tests for UTXO ownership verification in registry."""
    
    def test_registry_rejects_unowned_utxo_stake(self, funded_ledger, second_keypair):
        """Registry should reject staking with UTXOs not owned by solver."""
        from cfp.core.registry import SolverRegistry
        
        ledger, keypair = funded_ledger
        sender_address = address_from_public_key(keypair.public_key)
        
        # Attacker tries to register using victim's UTXO
        utxos = ledger.get_utxos_for_address(sender_address)
        attacker_utxo_ids = [utxos[0].utxo_id]
        
        registry = SolverRegistry(min_stake=100, ledger=ledger)
        
        # Attacker tries to register with victim's UTXO
        solver_id, msg = registry.register(
            public_key=second_keypair.public_key,  # Attacker's key
            initial_stake=0,
            utxo_ids=attacker_utxo_ids,  # Victim's UTXOs!
        )
        
        # SECURITY: Should be rejected
        assert solver_id is None, "Registry accepted stake from unowned UTXO!"
        assert "not owned" in msg.lower()


class TestNullifierUniqueness:
    """Tests for nullifier uniqueness including UTXO ID."""
    
    def test_same_commitment_different_nullifier(self, keypair):
        """UTXOs with same commitment should have different nullifiers."""
        from cfp.core.state.utxo import UTXO
        
        # Create two UTXOs with identical (value, owner, salt)
        # In the real world this could happen if same salt is reused
        common_salt = secrets.token_bytes(32)
        owner = keccak256(keypair.public_key)[-20:]
        
        utxo1 = UTXO(
            tx_hash=secrets.token_bytes(32),
            output_index=0,
            value=100,
            owner=owner,
            salt=common_salt,
        )
        
        utxo2 = UTXO(
            tx_hash=secrets.token_bytes(32),  # Different tx
            output_index=1,
            value=100,
            owner=owner,
            salt=common_salt,
        )
        
        # Commitments should be equal
        assert utxo1.compute_commitment() == utxo2.compute_commitment()
        
        # But nullifiers must be different!
        null1 = utxo1.compute_nullifier(keypair.private_key)
        null2 = utxo2.compute_nullifier(keypair.private_key)
        
        # SECURITY: Nullifiers must be unique
        assert null1 != null2, "Same nullifier for different UTXOs with same commitment!"


class TestValueBounds:
    """Tests for value overflow protection."""
    
    def test_output_value_exceeds_max_rejected(self, keypair):
        """Transaction with output value > MAX_VALUE should be rejected."""
        address = address_from_public_key(keypair.public_key)
        
        tx = Transaction(
            inputs=[],
            outputs=[TxOutput(value=MAX_VALUE + 1, owner=address)],
            fee=0,
        )
        
        success, msg = tx.validate_structure()
        assert not success, "Transaction with overflow value was accepted!"
        assert "maximum" in msg.lower() or "exceeds" in msg.lower()
    
    def test_fee_exceeds_max_rejected(self, keypair):
        """Transaction with fee > MAX_VALUE should be rejected."""
        address = address_from_public_key(keypair.public_key)
        
        tx = Transaction(
            inputs=[],
            outputs=[TxOutput(value=100, owner=address)],
            fee=MAX_VALUE + 1,
        )
        
        success, msg = tx.validate_structure()
        assert not success, "Transaction with overflow fee was accepted!"
        assert "maximum" in msg.lower() or "exceeds" in msg.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

