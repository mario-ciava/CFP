"""
CFP Network Module - P2P networking for Convergent Flow Protocol.

Provides peer-to-peer communication for vertex propagation and state sync.
"""

from cfp.network.protocol import (
    Message,
    MessageType,
    create_ping,
    create_pong,
    create_vertex_message,
    create_sync_request,
)
from cfp.network.peer import Peer, PeerInfo, PeerState, create_peer
from cfp.network.node import NetworkNode, NodeConfig
from cfp.network.gossip import GossipManager

__all__ = [
    "Message",
    "MessageType",
    "create_ping",
    "create_pong",
    "create_vertex_message",
    "create_sync_request",
    "Peer",
    "PeerInfo",
    "PeerState",
    "create_peer",
    "NetworkNode",
    "NodeConfig",
    "GossipManager",
]
