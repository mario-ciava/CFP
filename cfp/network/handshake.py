"""
Signed challenge-response handshake for CFP peer authentication.

A peer's identity is its public key: ``peer_id = sha256(pubkey)``. To authenticate,
a peer signs a fresh random nonce chosen by the other side, proving control of the
private key behind the claimed ``peer_id``. Fresh nonces make it replay-resistant.

Wire framing lives in ``protocol.py``; this module is pure crypto and needs no sockets.

Flow (mutual):
1. Initiator -> HELLO {pubkey_i, nonce_i}
2. Responder -> HELLO_ACK {pubkey_r, nonce_r, sig_r = sign(nonce_i)}
3. Initiator verifies sig_r, then -> HELLO_CONFIRM {sig_i = sign(nonce_r)}
4. Responder verifies sig_i. Both sides are authenticated.
"""

import secrets

from cfp.crypto import sha256, sign, verify

# Domain separation so a handshake signature can never be reused as any other
# signature in the system.
HANDSHAKE_DOMAIN = b"CFP-handshake-v1"


def new_nonce() -> bytes:
    """A fresh 32-byte challenge nonce."""
    return secrets.token_bytes(32)


def peer_id_from_pubkey(pubkey: bytes) -> bytes:
    """Derive the canonical peer id from a public key."""
    return sha256(pubkey)


def _challenge_digest(nonce: bytes) -> bytes:
    return sha256(HANDSHAKE_DOMAIN + nonce)


def sign_challenge(nonce: bytes, private_key: bytes) -> bytes:
    """Sign a peer-provided nonce, proving control of ``private_key``."""
    return sign(_challenge_digest(nonce), private_key)


def verify_challenge(nonce: bytes, signature: bytes, pubkey: bytes) -> bool:
    """Verify a signature over ``nonce`` against ``pubkey``."""
    if len(signature) != 64 or len(pubkey) != 64:
        return False
    return verify(_challenge_digest(nonce), signature, pubkey)
