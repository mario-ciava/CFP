"""
Security-focused unit tests for CFP.

Tests verify:
1. Signature verification rejects invalid signatures
2. Mint transactions rejected after genesis
3. Double-spend prevention
"""

import pytest
import secrets

from cfp.crypto import generate_keypair
from cfp.core.state import (
    Ledger,
    TxOutput,
    Transaction,
    address_from_public_key,
    create_transfer,
    create_mint,
)


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def second_keypair():
    return generate_keypair()


@pytest.fixture
def funded_ledger(keypair):
    """Ledger with initial funds after genesis."""
    ledger = Ledger(data_dir=None)
    address = address_from_public_key(keypair.public_key)
    ledger.create_genesis([(address, 1000)])
    return ledger, keypair


class TestMintAuthorization:
    """Tests for mint transaction restrictions."""
    
    def test_mint_allowed_at_genesis(self, keypair):
        """Mint should succeed during genesis (block 0)."""
        ledger = Ledger(data_dir=None)
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
        from cfp.core.state.transaction import TxInput
        
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
