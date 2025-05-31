"""
Peer Discovery - Automatic peer finding for CFP network.

Handles:
- Bootstrap node connections
- Peer list exchange
- Maintaining target peer count

Protocol:
1. On startup, connect to bootstrap nodes
2. Request peer lists from connected peers
3. Periodically refresh peer lists
4. Maintain target peer count (disconnect/connect as needed)
"""

import asyncio
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple, TYPE_CHECKING

from cfp.network.protocol import Message, MessageType
from cfp.utils.logger import get_logger

if TYPE_CHECKING:
    from cfp.network.node import NetworkNode
    from cfp.network.peer import Peer, PeerInfo

logger = get_logger("discovery")


# =============================================================================
# Bootstrap Nodes
# =============================================================================

# Default bootstrap nodes (placeholder - replace with real nodes in production)
BOOTSTRAP_NODES: List[Tuple[str, int]] = [
    ("127.0.0.1", 9001),  # Local development
    ("127.0.0.1", 9002),  # Local development
]


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class DiscoveryConfig:
    """Configuration for peer discovery."""
    bootstrap_nodes: List[Tuple[str, int]] = field(default_factory=lambda: BOOTSTRAP_NODES.copy())
    target_peers: int = 8
    max_peers: int = 20
    min_peers: int = 3
    refresh_interval: int = 60  # seconds
    connection_timeout: int = 10  # seconds


# =============================================================================
# Peer Discovery
# =============================================================================

class PeerDiscovery:
    """
    Discovers and maintains peer connections.
    
    Automatically connects to bootstrap nodes and discovers
    additional peers through peer list exchange.
    """
    
    def __init__(
        self,
        node: "NetworkNode",
        config: Optional[DiscoveryConfig] = None,
    ):
        self.node = node
        self.config = config or DiscoveryConfig()
        self._known_peers: Set[Tuple[str, int]] = set()
        self._running = False
        self._refresh_task: Optional[asyncio.Task] = None
        
        # Add bootstrap nodes to known peers
        for addr in self.config.bootstrap_nodes:
            self._known_peers.add(addr)
    
    async def start(self) -> None:
        """Start the discovery service."""
        self._running = True
        logger.info("Peer discovery started")
        
        # Connect to bootstrap nodes
        await self.bootstrap()
        
        # Start background refresh
        self._refresh_task = asyncio.create_task(self._refresh_loop())
    
    async def stop(self) -> None:
        """Stop the discovery service."""
        self._running = False
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
        logger.info("Peer discovery stopped")
    
    async def bootstrap(self) -> int:
        """
        Connect to bootstrap nodes.
        
        Returns:
            Number of successful connections
        """
        connected = 0
        
        for host, port in self.config.bootstrap_nodes:
            if self.node.peer_count >= self.config.max_peers:
                break
            
            try:
                success = await asyncio.wait_for(
                    self.node.connect_to_peer(host, port),
                    timeout=self.config.connection_timeout,
                )
                if success:
                    connected += 1
                    logger.info(f"Connected to bootstrap node {host}:{port}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout connecting to {host}:{port}")
            except Exception as e:
                logger.debug(f"Failed to connect to {host}:{port}: {e}")
        
        logger.info(f"Bootstrap complete: {connected} connections")
        return connected
    
    async def request_peers(self, peer: "Peer") -> bool:
        """
        Request peer list from a connected peer.
        
        Args:
            peer: Peer to request from
            
        Returns:
            True if request was sent
        """
        msg = create_peer_list_request(self.node.node_id)
        return await peer.send(msg)
    
    async def handle_peer_list_request(
        self,
        message: Message,
        peer: "Peer",
    ) -> None:
        """Handle incoming peer list request."""
        # Gather our known peers
        peer_infos = self.node.get_peer_info()
        
        # Send response
        response = create_peer_list_response(
            self.node.node_id,
            [(p.host, p.port) for p in peer_infos[:20]],  # Max 20 peers
        )
        await peer.send(response)
    
    async def handle_peer_list_response(
        self,
        message: Message,
        peer: "Peer",
    ) -> None:
        """Handle incoming peer list response."""
        peers = parse_peer_list(message.payload)
        
        added = 0
        for host, port in peers:
            if (host, port) not in self._known_peers:
                self._known_peers.add((host, port))
                added += 1
        
        logger.debug(f"Received {len(peers)} peers, {added} new")
        
        # Try to connect to new peers if below target
        if self.node.peer_count < self.config.target_peers:
            await self._connect_to_known_peers()
    
    async def _refresh_loop(self) -> None:
        """Periodically refresh peer connections."""
        while self._running:
            await asyncio.sleep(self.config.refresh_interval)
            
            # Check peer count
            current = self.node.peer_count
            
            if current < self.config.min_peers:
                logger.warning(f"Low peer count ({current}), attempting recovery")
                await self.bootstrap()
                await self._connect_to_known_peers()
            
            elif current < self.config.target_peers:
                # Request more peers from existing connections
                for peer in list(self.node.peers.values()):
                    if peer.is_connected:
                        await self.request_peers(peer)
                
                await self._connect_to_known_peers()
    
    async def _connect_to_known_peers(self) -> int:
        """Try to connect to known but unconnected peers."""
        connected = 0
        
        # Get currently connected addresses
        connected_addrs = {
            (p.info.host, p.info.port) 
            for p in self.node.peers.values()
        }
        
        # Try unconnected known peers
        for host, port in self._known_peers:
            if (host, port) in connected_addrs:
                continue
            
            if self.node.peer_count >= self.config.target_peers:
                break
            
            try:
                success = await asyncio.wait_for(
                    self.node.connect_to_peer(host, port),
                    timeout=self.config.connection_timeout,
                )
                if success:
                    connected += 1
            except Exception:
                pass
        
        return connected
    
    def add_known_peer(self, host: str, port: int) -> None:
        """Add a peer to the known peers set."""
        self._known_peers.add((host, port))
    
    @property
    def known_peer_count(self) -> int:
        """Number of known peer addresses."""
        return len(self._known_peers)


# =============================================================================
# Protocol Helpers
# =============================================================================

def create_peer_list_request(sender_id: bytes) -> Message:
    """Create a PEER_LIST request message."""
    return Message(
        msg_type=MessageType.PEER_LIST,
        payload=b"\x00",  # Request marker
        sender_id=sender_id,
    )


def create_peer_list_response(
    sender_id: bytes,
    peers: List[Tuple[str, int]],
) -> Message:
    """
    Create a PEER_LIST response message.
    
    Payload format:
        response_marker (1) | num_peers (2) | [host_len (1) | host | port (2)]...
    """
    parts = [
        b"\x01",  # Response marker
        struct.pack(">H", len(peers)),
    ]
    
    for host, port in peers:
        host_bytes = host.encode("utf-8")[:255]
        parts.append(struct.pack(">B", len(host_bytes)))
        parts.append(host_bytes)
        parts.append(struct.pack(">H", port))
    
    return Message(
        msg_type=MessageType.PEER_LIST,
        payload=b"".join(parts),
        sender_id=sender_id,
    )


def parse_peer_list(payload: bytes) -> List[Tuple[str, int]]:
    """
    Parse a PEER_LIST response payload.
    
    Returns:
        List of (host, port) tuples
    """
    if len(payload) < 3 or payload[0] != 0x01:
        return []
    
    num_peers = struct.unpack(">H", payload[1:3])[0]
    peers = []
    offset = 3
    
    for _ in range(num_peers):
        if offset >= len(payload):
            break
        
        host_len = payload[offset]
        offset += 1
        
        if offset + host_len + 2 > len(payload):
            break
        
        host = payload[offset:offset+host_len].decode("utf-8")
        offset += host_len
        
        port = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2
        
        peers.append((host, port))
    
    return peers
