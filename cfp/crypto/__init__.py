"""
Cryptographic primitives for CFP.

This module provides:
- Hashing functions (SHA-256, Keccak-256, Poseidon)
- Key generation and management
- Digital signatures (ECDSA on secp256k1)
- ZK-friendly primitives (Poseidon hash for circuits)

Design Notes:
-------------
We use secp256k1 (same as Bitcoin/Ethereum) for familiarity and tooling compatibility.
For ZK-friendly operations, we use Poseidon hash which is optimized for arithmetic circuits.

Poseidon is used for:
- Intent IDs (deterministic, ZK-provable)
- Solver commitments (sealed bids)
- UTXO commitments (when ZK-verified)
- Transcript leaves (auction binding)
- Nullifiers (when ZK-verified)

SHA-256/Keccak are retained for:
- Backward compatibility
- Non-ZK operations (vertex IDs, etc.)
- Address derivation (Ethereum compatibility)
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from Crypto.Hash import keccak
from py_ecc.secp256k1 import secp256k1


# =============================================================================
# Constants
# =============================================================================

# secp256k1 curve order (number of points on the curve)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# =============================================================================
# Hashing
# =============================================================================


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash.
    
    Used for: vertex IDs, Merkle trees, general content addressing.
    """
    return hashlib.sha256(data).digest()


def keccak256(data: bytes) -> bytes:
    """
    Compute Keccak-256 hash (Ethereum-style).
    
    Used for: address derivation, compatibility with EVM conventions.
    """
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def double_sha256(data: bytes) -> bytes:
    """
    Compute SHA-256(SHA-256(data)).
    
    Used for: extra security where needed (Bitcoin convention).
    """
    return sha256(sha256(data))


# =============================================================================
# Key Generation
# =============================================================================


@dataclass
class KeyPair:
    """
    An ECDSA keypair on secp256k1.
    
    Attributes:
        private_key: 32-byte secret key (integer in [1, order-1])
        public_key: 64-byte uncompressed public key (x || y coordinates)
    """
    private_key: bytes  # 32 bytes
    public_key: bytes   # 64 bytes (uncompressed, no 0x04 prefix)
    
    @property
    def address(self) -> str:
        """
        Derive address from public key (Ethereum-style).
        
        Address = last 20 bytes of keccak256(public_key), hex-encoded with 0x prefix.
        """
        hash_bytes = keccak256(self.public_key)
        return "0x" + hash_bytes[-20:].hex()
    
    @property
    def private_key_hex(self) -> str:
        """Return private key as hex string."""
        return self.private_key.hex()
    
    @property
    def public_key_hex(self) -> str:
        """Return public key as hex string."""
        return self.public_key.hex()


def generate_keypair() -> KeyPair:
    """
    Generate a new random keypair.
    
    Uses cryptographically secure random number generator.
    """
    # Generate 32-byte private key in valid range [1, order-1]
    while True:
        private_key_int = secrets.randbelow(SECP256K1_ORDER - 1) + 1
        private_key = private_key_int.to_bytes(32, byteorder="big")
        break
    
    # Derive public key: P = k * G (scalar multiplication on curve)
    public_key_point = secp256k1.privtopub(private_key)
    
    # public_key_point is (x, y) tuple of integers
    # Convert to 64-byte representation (32 bytes x, 32 bytes y)
    x_bytes = public_key_point[0].to_bytes(32, byteorder="big")
    y_bytes = public_key_point[1].to_bytes(32, byteorder="big")
    public_key = x_bytes + y_bytes
    
    return KeyPair(private_key=private_key, public_key=public_key)


def private_key_to_public_key(private_key: bytes) -> bytes:
    """
    Derive public key from private key.
    
    Args:
        private_key: 32-byte private key
        
    Returns:
        64-byte uncompressed public key
    """
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")
    
    public_key_point = secp256k1.privtopub(private_key)
    x_bytes = public_key_point[0].to_bytes(32, byteorder="big")
    y_bytes = public_key_point[1].to_bytes(32, byteorder="big")
    return x_bytes + y_bytes


# =============================================================================
# Digital Signatures (ECDSA)
# =============================================================================


def sign(message_hash: bytes, private_key: bytes) -> bytes:
    """
    Sign a message hash using ECDSA on secp256k1.
    
    Args:
        message_hash: 32-byte hash of the message to sign
        private_key: 32-byte private key
        
    Returns:
        64-byte signature (r || s, each 32 bytes)
        
    Note: This is a deterministic signature (RFC 6979 style).
    """
    if len(message_hash) != 32:
        raise ValueError("Message hash must be 32 bytes")
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")
    
    # py_ecc.secp256k1.ecdsa_raw_sign returns (v, r, s)
    v, r, s = secp256k1.ecdsa_raw_sign(message_hash, private_key)
    
    # Normalize s to lower half of curve order (BIP 62 / EIP-2)
    # This prevents signature malleability
    if s > SECP256K1_ORDER // 2:
        s = SECP256K1_ORDER - s
    
    r_bytes = r.to_bytes(32, byteorder="big")
    s_bytes = s.to_bytes(32, byteorder="big")
    
    return r_bytes + s_bytes


def verify(message_hash: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an ECDSA signature.
    
    Args:
        message_hash: 32-byte hash of the signed message
        signature: 64-byte signature (r || s)
        public_key: 64-byte public key (x || y)
        
    Returns:
        True if signature is valid, False otherwise
    """
    if len(message_hash) != 32:
        return False
    if len(signature) != 64:
        return False
    if len(public_key) != 64:
        return False
    
    try:
        # Parse signature components
        r = int.from_bytes(signature[:32], byteorder="big")
        s = int.from_bytes(signature[32:], byteorder="big")
        
        # Parse public key
        x = int.from_bytes(public_key[:32], byteorder="big")
        y = int.from_bytes(public_key[32:], byteorder="big")
        public_key_point = (x, y)
        
        # Verify signature
        # py_ecc expects (v, r, s) but we don't have v, so we try both
        # Actually ecdsa_raw_recover needs v, but ecdsa_raw_verify works differently
        # We need to manually verify using the raw ECDSA verification
        
        # Verify r, s are in valid range
        if r < 1 or r >= SECP256K1_ORDER:
            return False
        if s < 1 or s >= SECP256K1_ORDER:
            return False
        
        # Use ecdsa_raw_recover to get the public key, then compare
        # Try v=27 and v=28 (Ethereum convention)
        for v in (27, 28):
            try:
                recovered = secp256k1.ecdsa_raw_recover(message_hash, (v, r, s))
                if recovered == public_key_point:
                    return True
            except Exception:
                continue
        
        return False
        
    except Exception:
        return False


def recover_public_key(message_hash: bytes, signature: bytes, recovery_id: int) -> Optional[bytes]:
    """
    Recover public key from signature (for verification without knowing signer).
    
    Args:
        message_hash: 32-byte hash
        signature: 64-byte signature (r || s)
        recovery_id: 0 or 1 (which of two possible public keys)
        
    Returns:
        64-byte public key, or None if recovery fails
    """
    if len(message_hash) != 32 or len(signature) != 64:
        return None
    
    try:
        r = int.from_bytes(signature[:32], byteorder="big")
        s = int.from_bytes(signature[32:], byteorder="big")
        
        # v is 27 + recovery_id (Ethereum convention)
        v = 27 + recovery_id
        
        recovered = secp256k1.ecdsa_raw_recover(message_hash, (v, r, s))
        
        x_bytes = recovered[0].to_bytes(32, byteorder="big")
        y_bytes = recovered[1].to_bytes(32, byteorder="big")
        
        return x_bytes + y_bytes
        
    except Exception:
        return None


# =============================================================================
# Utility Functions
# =============================================================================


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string with 0x prefix."""
    return "0x" + data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with or without 0x prefix) to bytes."""
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def is_valid_address(address: str) -> bool:
    """Check if string is a valid address format."""
    if not address.startswith("0x"):
        return False
    if len(address) != 42:  # 0x + 40 hex chars
        return False
    try:
        int(address, 16)
        return True
    except ValueError:
        return False


# =============================================================================
# Poseidon Hash (ZK-friendly)
# =============================================================================

# Import Poseidon functions for ZK-friendly hashing
# These are used for intent IDs, commitments, nullifiers etc.
from cfp.crypto.poseidon import (
    # Core hash functions
    poseidon_hash,
    poseidon1,
    poseidon2,
    poseidon_bytes,
    poseidon_bytes_to_bytes,
    # Field element conversion
    int_to_bytes32,
    bytes32_to_int,
    FIELD_PRIME,
    # CFP-specific hash functions
    hash_intent_id,
    hash_solver_commit,
    hash_nullifier,
    hash_utxo_commitment,
    hash_transcript_leaf,
    hash_tie_break,
    # Domain separators
    DOMAIN_INTENT_ID,
    DOMAIN_SOLVER_COMMIT,
    DOMAIN_NULLIFIER,
    DOMAIN_UTXO_COMMITMENT,
    DOMAIN_TRANSCRIPT_LEAF,
    DOMAIN_TIE_BREAK,
)
