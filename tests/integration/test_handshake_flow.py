"""
Drives the full signed handshake between two NetworkNodes without sockets.

A peer is authenticated only after it signs a fresh nonce chosen by the other
side; a self-declared id (e.g. in a PONG) is never sufficient.
"""

from cfp.crypto import generate_keypair
from cfp.network.node import NetworkNode
from cfp.network.peer import PeerInfo
from cfp.network.protocol import MessageType, create_vertex_message


class FakePeer:
    """Captures messages the node tries to send; carries handshake state."""

    def __init__(self, host="peer", port=1):
        self.info = PeerInfo(host=host, port=port)
        self.sent = []

    async def send(self, msg):
        self.sent.append(msg)
        return True


async def _run_handshake(A: NetworkNode, B: NetworkNode):
    """Returns (peerAB, peerBA) after driving HELLO/ACK/CONFIRM A<->B."""
    peerAB, peerBA = FakePeer(), FakePeer()
    await A._send_hello(peerAB)
    await B._handle_hello(peerAB.sent.pop(), peerBA)
    await A._handle_hello_ack(peerBA.sent.pop(), peerAB)
    await B._handle_hello_confirm(peerAB.sent.pop(), peerBA)
    return peerAB, peerBA


async def test_mutual_signed_handshake_authenticates_both():
    A = NetworkNode(node_key=generate_keypair())
    B = NetworkNode(node_key=generate_keypair())

    await _run_handshake(A, B)

    # Each side authenticated the other's *key-derived* id.
    assert B.node_id in A.authenticated_peers
    assert A.node_id in B.authenticated_peers


async def test_tampered_ack_is_not_authenticated():
    A = NetworkNode(node_key=generate_keypair())
    B = NetworkNode(node_key=generate_keypair())

    peerAB, peerBA = FakePeer(), FakePeer()
    await A._send_hello(peerAB)
    await B._handle_hello(peerAB.sent.pop(), peerBA)

    ack = peerBA.sent.pop()
    forged = bytearray(ack.payload)
    forged[-1] ^= 0xFF  # break the signature
    ack.payload = bytes(forged)

    await A._handle_hello_ack(ack, peerAB)
    assert B.node_id not in A.authenticated_peers
    assert not peerAB.sent  # A must not send a CONFIRM


async def test_spoofed_pong_does_not_authenticate():
    """A PONG carrying a victim's id must NOT authenticate the sender."""
    A = NetworkNode(node_key=generate_keypair())
    victim = generate_keypair()
    from cfp.network.protocol import create_pong

    peer = FakePeer()
    # Attacker sends a PONG claiming to be the victim.
    await A._handle_pong(create_pong(A.node_id, 0), peer)
    from cfp.network.handshake import peer_id_from_pubkey
    assert peer_id_from_pubkey(victim.public_key) not in A.authenticated_peers
    assert peer.info.peer_id is None


async def test_unauthenticated_peer_message_dropped():
    A = NetworkNode(node_key=generate_keypair())
    called = {"hit": False}

    async def handler(msg, p):
        called["hit"] = True

    A._message_handlers[MessageType.VERTEX] = handler
    # Peer never completed the handshake -> peer_id is None -> message dropped.
    await A._on_message(create_vertex_message(b"x" * 32, b"data"), FakePeer())
    assert called["hit"] is False
