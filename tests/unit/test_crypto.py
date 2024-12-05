"""
Unit tests for cryptographic primitives.

Tests cover:
1. Key generation
2. Signing and verification
3. Public key recovery
4. Hashing functions
5. Address derivation
"""

import pytest
import secrets

from cfp.crypto import (
    generate_keypair,
    sign,
    verify,
    recover_public_key,
    sha256,
    keccak256,
    double_sha256,
    private_key_to_public_key,
    bytes_to_hex,
    hex_to_bytes,
    is_valid_address,
    SECP256K1_ORDER,
)


class TestKeyGeneration:
    """Tests for key generation."""
    
    def test_keypair_generation_produces_valid_lengths(self):
        """KeyPair should have correct field lengths."""
        kp = generate_keypair()
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 64
    
    def test_keypair_address_format(self):
        """Address should be 0x-prefixed 40 hex chars."""
        kp = generate_keypair()
        assert kp.address.startswith("0x")
        assert len(kp.address) == 42
        assert is_valid_address(kp.address)
    
    def test_keypairs_are_unique(self):
        """Each keypair should be different."""
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.private_key != kp2.private_key
        assert kp1.public_key != kp2.public_key
    
    def test_derive_public_key_from_private(self):
        """Should derive correct public key from private key."""
        kp = generate_keypair()
        derived = private_key_to_public_key(kp.private_key)
        assert derived == kp.public_key


class TestSigning:
    """Tests for ECDSA signing."""
    
    def test_sign_produces_valid_signature(self):
        """Signature should be 64 bytes."""
        kp = generate_keypair()
        msg_hash = sha256(b"test message")
        sig = sign(msg_hash, kp.private_key)
        assert len(sig) == 64
    
    def test_verify_valid_signature(self):
        """Valid signature should verify."""
        kp = generate_keypair()
        msg_hash = sha256(b"test message")
        sig = sign(msg_hash, kp.private_key)
        assert verify(msg_hash, sig, kp.public_key)
    
    def test_verify_wrong_message_fails(self):
        """Signature should fail for different message."""
        kp = generate_keypair()
        msg1 = sha256(b"message 1")
        msg2 = sha256(b"message 2")
        sig = sign(msg1, kp.private_key)
        assert not verify(msg2, sig, kp.public_key)
    
    def test_verify_wrong_key_fails(self):
        """Signature should fail with wrong public key."""
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        msg = sha256(b"test")
        sig = sign(msg, kp1.private_key)
        assert not verify(msg, sig, kp2.public_key)


class TestPublicKeyRecovery:
    """Tests for public key recovery from signature."""
    
    def test_recover_correct_key(self):
        """Should recover original public key from signature."""
        kp = generate_keypair()
        msg = sha256(b"recovery test")
        sig = sign(msg, kp.private_key)
        
        # Try both recovery IDs
        recovered = None
        for rid in (0, 1):
            r = recover_public_key(msg, sig, rid)
            if r == kp.public_key:
                recovered = r
                break
        
        assert recovered == kp.public_key


class TestHashing:
    """Tests for hashing functions."""
    
    def test_sha256_length(self):
        """SHA256 should produce 32 bytes."""
        h = sha256(b"test")
        assert len(h) == 32
    
    def test_sha256_deterministic(self):
        """Same input should produce same hash."""
        assert sha256(b"hello") == sha256(b"hello")
    
    def test_sha256_different_inputs(self):
        """Different inputs should produce different hashes."""
        assert sha256(b"a") != sha256(b"b")
    
    def test_keccak256_length(self):
        """Keccak256 should produce 32 bytes."""
        h = keccak256(b"test")
        assert len(h) == 32
    
    def test_double_sha256(self):
        """Double SHA256 should hash twice."""
        h = double_sha256(b"test")
        expected = sha256(sha256(b"test"))
        assert h == expected


class TestUtility:
    """Tests for utility functions."""
    
    def test_bytes_to_hex(self):
        """Should convert to 0x-prefixed hex."""
        result = bytes_to_hex(bytes([0xde, 0xad, 0xbe, 0xef]))
        assert result == "0xdeadbeef"
    
    def test_hex_to_bytes(self):
        """Should handle both 0x prefix and plain hex."""
        assert hex_to_bytes("0xdeadbeef") == bytes([0xde, 0xad, 0xbe, 0xef])
        assert hex_to_bytes("deadbeef") == bytes([0xde, 0xad, 0xbe, 0xef])
    
    def test_is_valid_address(self):
        """Should validate address format."""
        assert is_valid_address("0x" + "a" * 40)
        assert not is_valid_address("0x" + "a" * 39)  # Too short
        assert not is_valid_address("a" * 40)  # No 0x
        assert not is_valid_address("0x" + "g" * 40)  # Invalid hex


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
