"""
Node - Main network node for CFP P2P.

Manages peer connections and message routing.
"""

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from cfp.crypto import KeyPair, generate_keypair
from cfp.network.handshake import (
    new_nonce,
    peer_id_from_pubkey,
    sign_challenge,
    verify_challenge,
)
from cfp.network.peer import Peer, PeerInfo, PeerState
from cfp.network.protocol import (
    Message,
    MessageType,
    create_hello,
    create_hello_ack,
    create_hello_confirm,
    create_ping,
    create_pong,
    create_vertex_message,
    parse_hello,
    parse_hello_ack,
    parse_hello_confirm,
)
from cfp.utils.logger import get_logger

if TYPE_CHECKING:
    from cfp.network.discovery import PeerDiscovery
    from cfp.network.sync import SyncManager

logger = get_logger("node")


@dataclass
class NodeConfig:
    """Configuration for a network node."""
    host: str = "0.0.0.0"
    port: int = 9000
    max_peers: int = 10
    ping_interval: int = 30  # seconds
    enable_discovery: bool = True
    enable_sync: bool = True


class NetworkNode:
    """
    A CFP network node that manages peer connections.

    Handles:
    - Listening for incoming connections
    - Connecting to peers
    - Message routing and broadcasting
    - Peer authentication via PING/PONG handshake
    - State synchronization (via SyncManager)
    - Peer discovery (via PeerDiscovery)
    """

    def __init__(self, config: Optional[NodeConfig] = None, node_key: Optional[KeyPair] = None):
        self.config = config or NodeConfig()
        # Identity is a keypair; the node id is derived from the public key so
        # peers can bind it to a signature (see network/handshake.py).
        self.node_key = node_key or generate_keypair()
        self.node_id = peer_id_from_pubkey(self.node_key.public_key)
        self.peers: Dict[bytes, Peer] = {}  # peer_id -> Peer
        self.authenticated_peers: set = set()  # Set of authenticated peer_ids
        self.server: Optional[asyncio.Server] = None
        self._running = False
        self._message_handlers: Dict[MessageType, Callable] = {}

        # Optional components (lazy initialization)
        self.sync_manager: Optional["SyncManager"] = None
        self.discovery: Optional["PeerDiscovery"] = None

        # Register default handlers
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register built-in message handlers."""
        self._message_handlers[MessageType.PING] = self._handle_ping
        self._message_handlers[MessageType.PONG] = self._handle_pong
        self._message_handlers[MessageType.HELLO] = self._handle_hello
        self._message_handlers[MessageType.HELLO_ACK] = self._handle_hello_ack
        self._message_handlers[MessageType.HELLO_CONFIRM] = self._handle_hello_confirm
        self._message_handlers[MessageType.SYNC_REQUEST] = self._handle_sync_request
        self._message_handlers[MessageType.SYNC_RESPONSE] = self._handle_sync_response
        self._message_handlers[MessageType.PEER_LIST] = self._handle_peer_list

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

        # Start discovery if enabled
        if self.config.enable_discovery:
            await self._start_discovery()

    async def _start_discovery(self) -> None:
        """Initialize and start peer discovery."""
        from cfp.network.discovery import PeerDiscovery
        self.discovery = PeerDiscovery(self)
        await self.discovery.start()

    async def stop(self) -> None:
        """Stop the network node."""
        self._running = False

        # Stop discovery
        if self.discovery:
            await self.discovery.stop()

        # Disconnect all peers
        for peer in list(self.peers.values()):
            await peer.disconnect()
        self.peers.clear()

        # Stop server
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        logger.info("Node stopped")

    def set_sync_manager(self, sync_manager: "SyncManager") -> None:
        """Attach a sync manager to handle state synchronization."""
        self.sync_manager = sync_manager

    async def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer."""
        if len(self.peers) >= self.config.max_peers:
            logger.warning("Max peers reached")
            return False

        peer = Peer(info=PeerInfo(host=host, port=port))
        if await peer.connect():
            # Start receiving, then initiate the signed handshake.
            peer.start_receiving(self._on_message)

            # Use temporary ID until the handshake yields the real peer_id.
            temp_id = peer_id_from_pubkey(f"tmp:{host}:{port}".encode())
            self.peers[temp_id] = peer

            await self._send_hello(peer)
            return True
        return False

    async def _send_hello(self, peer: Peer) -> None:
        """Initiate the handshake: present our key and a fresh challenge nonce."""
        nonce = new_nonce()
        peer.info.challenge = nonce  # the responder must sign this in HELLO_ACK
        await peer.send(create_hello(self.node_id, self.node_key.public_key, nonce))

    def _authenticate(self, peer: Peer, pubkey: bytes) -> None:
        """Bind a verified public key to the peer and mark it authenticated."""
        peer_id = peer_id_from_pubkey(pubkey)
        peer.info.pubkey = pubkey
        peer.info.peer_id = peer_id
        peer.info.last_seen = int(time.time())
        self.authenticated_peers.add(peer_id)
        # Re-key the peer under its real id if it was stored under a temp id.
        for k in [k for k, v in self.peers.items() if v is peer and k != peer_id]:
            del self.peers[k]
        self.peers[peer_id] = peer
        logger.info(f"Peer authenticated (signed handshake): {peer_id.hex()[:16]}...")

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

        # Temporary id until the signed handshake yields the real peer_id.
        temp_id = peer_id_from_pubkey(f"tmp:{addr[0]}:{addr[1]}".encode())
        self.peers[temp_id] = peer

        # Start receiving (responder waits for the initiator's HELLO).
        peer.start_receiving(self._on_message)

    # Messages allowed before authentication completes.
    _PREAUTH_TYPES = frozenset({
        MessageType.PING,
        MessageType.PONG,
        MessageType.HELLO,
        MessageType.HELLO_ACK,
        MessageType.HELLO_CONFIRM,
    })

    async def _on_message(self, message: Message, peer: Peer) -> None:
        """Route received message to appropriate handler."""
        if message.msg_type not in self._PREAUTH_TYPES:
            # Everything else requires a completed signed handshake.
            if peer.info.peer_id not in self.authenticated_peers:
                logger.warning(f"Dropping message from unauthenticated peer {peer.info.host}")
                return

        handler = self._message_handlers.get(message.msg_type)
        if handler:
            await handler(message, peer)
        else:
            logger.debug(f"No handler for message type: {message.msg_type}")

    async def _handle_hello(self, message: Message, peer: Peer) -> None:
        """Responder: sign the initiator's nonce, send our key + our own nonce."""
        try:
            pubkey_i, nonce_i = parse_hello(message.payload)
        except ValueError:
            logger.warning(f"Malformed HELLO from {peer.info.host}")
            return
        peer.info.pubkey = pubkey_i
        our_nonce = new_nonce()
        peer.info.challenge = our_nonce  # initiator must sign this in HELLO_CONFIRM
        sig = sign_challenge(nonce_i, self.node_key.private_key)
        await peer.send(create_hello_ack(self.node_id, self.node_key.public_key, our_nonce, sig))

    async def _handle_hello_ack(self, message: Message, peer: Peer) -> None:
        """Initiator: verify the responder signed our nonce, then confirm."""
        try:
            pubkey_r, nonce_r, sig_r = parse_hello_ack(message.payload)
        except ValueError:
            logger.warning(f"Malformed HELLO_ACK from {peer.info.host}")
            return
        if peer.info.challenge is None or not verify_challenge(peer.info.challenge, sig_r, pubkey_r):
            logger.warning(f"HELLO_ACK signature invalid from {peer.info.host}; not authenticating")
            return
        # Responder proved control of pubkey_r -> authenticate it.
        self._authenticate(peer, pubkey_r)
        sig_i = sign_challenge(nonce_r, self.node_key.private_key)
        await peer.send(create_hello_confirm(self.node_id, sig_i))

    async def _handle_hello_confirm(self, message: Message, peer: Peer) -> None:
        """Responder: verify the initiator signed our nonce -> authenticate it."""
        try:
            sig_i = parse_hello_confirm(message.payload)
        except ValueError:
            logger.warning(f"Malformed HELLO_CONFIRM from {peer.info.host}")
            return
        if (
            peer.info.challenge is None
            or peer.info.pubkey is None
            or not verify_challenge(peer.info.challenge, sig_i, peer.info.pubkey)
        ):
            logger.warning(f"HELLO_CONFIRM signature invalid from {peer.info.host}; not authenticating")
            return
        self._authenticate(peer, peer.info.pubkey)

    async def _handle_ping(self, message: Message, peer: Peer) -> None:
        """Reply to a PING. Liveness only; authentication is via the handshake."""
        # sender_id is self-declared, so PING/PONG never set peer_id or authenticate.
        pong = create_pong(self.node_id, message.timestamp)
        await peer.send(pong)

    async def _handle_pong(self, message: Message, peer: Peer) -> None:
        """Record latency from a PONG. Does not authenticate."""
        import struct
        ping_time = struct.unpack(">Q", message.payload)[0]
        latency = int((time.time() - ping_time) * 1000)

        peer.info.latency_ms = latency
        peer.info.last_seen = int(time.time())
        logger.debug(f"Pong from {peer.info.host}: {latency}ms")

    async def _handle_sync_request(self, message: Message, peer: Peer) -> None:
        """Handle SYNC_REQUEST message."""
        if self.sync_manager:
            await self.sync_manager.handle_sync_request(message, peer)
        else:
            logger.debug("No sync manager configured, ignoring sync request")

    async def _handle_sync_response(self, message: Message, peer: Peer) -> None:
        """Handle SYNC_RESPONSE message."""
        if self.sync_manager:
            await self.sync_manager.handle_sync_response(message, peer)
        else:
            logger.debug("No sync manager configured, ignoring sync response")

    async def _handle_peer_list(self, message: Message, peer: Peer) -> None:
        """Handle PEER_LIST message (request or response)."""
        if self.discovery:
            # Check if request (payload starts with 0x00) or response (0x01)
            if message.payload and message.payload[0] == 0x00:
                await self.discovery.handle_peer_list_request(message, peer)
            else:
                await self.discovery.handle_peer_list_response(message, peer)
        else:
            logger.debug("No discovery configured, ignoring peer list message")

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

