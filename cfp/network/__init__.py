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
from cfp.network.sync import SyncManager, create_sync_response, parse_sync_response
from cfp.network.discovery import (
    PeerDiscovery,
    DiscoveryConfig,
    BOOTSTRAP_NODES,
    create_peer_list_request,
    create_peer_list_response,
    parse_peer_list,
)

__all__ = [
    # Protocol
    "Message",
    "MessageType",
    "create_ping",
    "create_pong",
    "create_vertex_message",
    "create_sync_request",
    # Peer
    "Peer",
    "PeerInfo",
    "PeerState",
    "create_peer",
    # Node
    "NetworkNode",
    "NodeConfig",
    "GossipManager",
    # Sync
    "SyncManager",
    "create_sync_response",
    "parse_sync_response",
    # Discovery
    "PeerDiscovery",
    "DiscoveryConfig",
    "BOOTSTRAP_NODES",
    "create_peer_list_request",
    "create_peer_list_response",
    "parse_peer_list",
]

