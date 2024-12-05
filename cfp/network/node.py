"""
Node - Main network node for CFP P2P.

Manages peer connections and message routing.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Optional

from cfp.crypto import sha256
from cfp.network.protocol import (
    Message,
    MessageType,
    create_ping,
    create_pong,
    create_vertex_message,
)
from cfp.network.peer import Peer, PeerInfo, PeerState
from cfp.utils.logger import get_logger


logger = get_logger("node")


@dataclass
class NodeConfig:
    """Configuration for a network node."""
    host: str = "0.0.0.0"
    port: int = 9000
    max_peers: int = 10
    ping_interval: int = 30  # seconds


class NetworkNode:
    """
    A CFP network node that manages peer connections.
    
    Handles:
    - Listening for incoming connections
    - Connecting to peers
    - Message routing and broadcasting
    - Peer authentication via PING/PONG handshake
    """
    
    def __init__(self, config: Optional[NodeConfig] = None):
        self.config = config or NodeConfig()
        self.node_id = sha256(f"{self.config.host}:{self.config.port}:{time.time()}".encode())
        self.peers: Dict[bytes, Peer] = {}  # peer_id -> Peer
        self.authenticated_peers: set = set()  # Set of authenticated peer_ids
        self.server: Optional[asyncio.Server] = None
        self._running = False
        self._message_handlers: Dict[MessageType, Callable] = {}
        
        # Register default handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self) -> None:
        """Register built-in message handlers."""
        self._message_handlers[MessageType.PING] = self._handle_ping
        self._message_handlers[MessageType.PONG] = self._handle_pong
    
    async def start(self) -> None:
        """Start the network node (listener + peer management)."""
        self._running = True
        
        # Start TCP server
        self.server = await asyncio.start_server(
            self._handle_connection,
            self.config.host,
            self.config.port,
        )
        
        logger.info(f"Node started on {self.config.host}:{self.config.port}")
        logger.info(f"Node ID: {self.node_id.hex()[:16]}...")
        
        # Start background tasks
        asyncio.create_task(self._ping_loop())
    
    async def stop(self) -> None:
        """Stop the network node."""
        self._running = False
        
        # Disconnect all peers
        for peer in list(self.peers.values()):
            await peer.disconnect()
        self.peers.clear()
        
        # Stop server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        logger.info("Node stopped")
    
    async def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer."""
        if len(self.peers) >= self.config.max_peers:
            logger.warning("Max peers reached")
            return False
        
        peer = Peer(info=PeerInfo(host=host, port=port))
        if await peer.connect():
            # Send ping to get peer ID
            await peer.send(create_ping(self.node_id))
            
            # Start receiving
            peer.start_receiving(self._on_message)
            
            # Use temporary ID until we get PONG
            temp_id = sha256(f"{host}:{port}".encode())
            self.peers[temp_id] = peer
            
            return True
        return False
    
    async def broadcast(self, message: Message, exclude: Optional[bytes] = None) -> int:
        """
        Broadcast a message to all connected peers.
        
        Returns:
            Number of peers message was sent to
        """
        count = 0
        for peer_id, peer in self.peers.items():
            if peer_id != exclude and peer.is_connected:
                if await peer.send(message):
                    count += 1
        return count
    
    async def broadcast_vertex(self, vertex_bytes: bytes) -> int:
        """Broadcast a new vertex to all peers."""
        msg = create_vertex_message(self.node_id, vertex_bytes)
        return await self.broadcast(msg)
    
    def register_handler(self, msg_type: MessageType, handler: Callable) -> None:
        """Register a custom message handler."""
        self._message_handlers[msg_type] = handler
    
    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming peer connection."""
        addr = writer.get_extra_info("peername")
        logger.info(f"Incoming connection from {addr}")
        
        peer = Peer(
            info=PeerInfo(host=addr[0], port=addr[1]),
            state=PeerState.CONNECTED,
            reader=reader,
            writer=writer,
        )
        
        # Temporary ID
        temp_id = sha256(f"{addr[0]}:{addr[1]}".encode())
        self.peers[temp_id] = peer
        
        # Start receiving
        peer.start_receiving(self._on_message)
    
    async def _on_message(self, message: Message, peer: Peer) -> None:
        """Route received message to appropriate handler."""
        # PING/PONG always allowed for handshake
        if message.msg_type not in (MessageType.PING, MessageType.PONG):
            # Check if peer is authenticated
            if peer.info.peer_id not in self.authenticated_peers:
                logger.warning(f"Dropping message from unauthenticated peer {peer.info.host}")
                return
        
        handler = self._message_handlers.get(message.msg_type)
        if handler:
            await handler(message, peer)
        else:
            logger.debug(f"No handler for message type: {message.msg_type}")
    
    async def _handle_ping(self, message: Message, peer: Peer) -> None:
        """Handle PING message."""
        pong = create_pong(self.node_id, message.timestamp)
        await peer.send(pong)
        
        # Update peer ID if we have sender
        if message.sender_id:
            peer.info.peer_id = message.sender_id
    
    async def _handle_pong(self, message: Message, peer: Peer) -> None:
        """Handle PONG message and authenticate peer."""
        import struct
        ping_time = struct.unpack(">Q", message.payload)[0]
        latency = int((time.time() - ping_time) * 1000)
        
        peer.info.latency_ms = latency
        peer.info.last_seen = int(time.time())
        
        if message.sender_id:
            peer.info.peer_id = message.sender_id
            # Mark peer as authenticated after successful PONG
            self.authenticated_peers.add(message.sender_id)
            logger.info(f"Peer authenticated: {message.sender_id.hex()[:16]}...")
        
        logger.debug(f"Pong from {peer.info.host}: {latency}ms")
    
    async def _ping_loop(self) -> None:
        """Periodically ping all peers."""
        while self._running:
            await asyncio.sleep(self.config.ping_interval)
            
            for peer in list(self.peers.values()):
                if peer.is_connected:
                    await peer.send(create_ping(self.node_id))
    
    @property
    def peer_count(self) -> int:
        return len([p for p in self.peers.values() if p.is_connected])
    
    def get_peer_info(self) -> List[PeerInfo]:
        return [p.info for p in self.peers.values()]
