"""Unit tests for the signed challenge-response handshake crypto."""

from cfp.crypto import generate_keypair
from cfp.network.handshake import (
    new_nonce,
    peer_id_from_pubkey,
    sign_challenge,
    verify_challenge,
)


class TestHandshakeCrypto:
    def test_sign_and_verify_roundtrip(self):
        kp = generate_keypair()
        nonce = new_nonce()
        sig = sign_challenge(nonce, kp.private_key)
        assert verify_challenge(nonce, sig, kp.public_key)

    def test_wrong_nonce_rejected(self):
        kp = generate_keypair()
        sig = sign_challenge(new_nonce(), kp.private_key)
        assert not verify_challenge(new_nonce(), sig, kp.public_key)

    def test_wrong_key_rejected(self):
        kp, other = generate_keypair(), generate_keypair()
        nonce = new_nonce()
        sig = sign_challenge(nonce, kp.private_key)
        assert not verify_challenge(nonce, sig, other.public_key)

    def test_tampered_signature_rejected(self):
        kp = generate_keypair()
        nonce = new_nonce()
        sig = bytearray(sign_challenge(nonce, kp.private_key))
        sig[0] ^= 0xFF
        assert not verify_challenge(nonce, bytes(sig), kp.public_key)

    def test_peer_id_binds_to_pubkey(self):
        a, b = generate_keypair(), generate_keypair()
        assert peer_id_from_pubkey(a.public_key) != peer_id_from_pubkey(b.public_key)
        assert peer_id_from_pubkey(a.public_key) == peer_id_from_pubkey(a.public_key)
