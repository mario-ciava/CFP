"""
Peer - Single peer connection management for CFP P2P.

Handles async TCP connection to a single peer.
"""

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional
from enum import Enum

from cfp.network.protocol import Message, MAGIC_BYTES, MAX_MESSAGE_SIZE
from cfp.utils.logger import get_logger


logger = get_logger("peer")


class PeerState(Enum):
    """Connection state of a peer."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    HANDSHAKING = "handshaking"


@dataclass
class PeerInfo:
    """Information about a peer."""
    host: str
    port: int
    peer_id: Optional[bytes] = None
    last_seen: int = 0
    latency_ms: int = 0


@dataclass
class Peer:
    """
    Represents a connection to a single peer.
    
    Attributes:
        info: Peer connection info
        state: Current connection state
        reader: Async stream reader
        writer: Async stream writer
    """
    info: PeerInfo
    state: PeerState = PeerState.DISCONNECTED
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    _message_handler: Optional[Callable] = None
    _receive_task: Optional[asyncio.Task] = None
    
    async def connect(self, timeout: float = 10.0) -> bool:
        """
        Establish connection to the peer.
        
        Returns:
            True if connected successfully
        """
        if self.state == PeerState.CONNECTED:
            return True
        
        self.state = PeerState.CONNECTING
        
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.info.host, self.info.port),
                timeout=timeout,
            )
            self.state = PeerState.CONNECTED
            logger.info(f"Connected to peer {self.info.host}:{self.info.port}")
            return True
            
        except asyncio.TimeoutError:
            logger.warning(f"Connection timeout to {self.info.host}:{self.info.port}")
            self.state = PeerState.DISCONNECTED
            return False
            
        except Exception as e:
            logger.error(f"Connection error to {self.info.host}:{self.info.port}: {e}")
            self.state = PeerState.DISCONNECTED
            return False
    
    async def disconnect(self) -> None:
        """Close the connection."""
        if self._receive_task:
            self._receive_task.cancel()
            self._receive_task = None
        
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
        
        self.reader = None
        self.writer = None
        self.state = PeerState.DISCONNECTED
        logger.info(f"Disconnected from {self.info.host}:{self.info.port}")
    
    async def send(self, message: Message) -> bool:
        """
        Send a message to the peer.
        
        Returns:
            True if sent successfully
        """
        if self.state != PeerState.CONNECTED or not self.writer:
            return False
        
        try:
            data = message.to_bytes()
            self.writer.write(data)
            await self.writer.drain()
            return True
            
        except Exception as e:
            logger.error(f"Send error to {self.info.host}:{self.info.port}: {e}")
            await self.disconnect()
            return False
    
    async def receive(self) -> Optional[Message]:
        """
        Receive a single message from the peer.
        
        Returns:
            Message if received, None on error/disconnect
        """
        if self.state != PeerState.CONNECTED or not self.reader:
            return None
        
        try:
            # Read header first (10 bytes)
            header = await self.reader.readexactly(10)
            
            # Parse to get payload length
            magic, version, msg_type, payload_len = struct.unpack(">4sBBI", header)
            
            if magic != MAGIC_BYTES:
                logger.warning(f"Invalid magic from {self.info.host}")
                await self.disconnect()
                return None
            
            if payload_len > MAX_MESSAGE_SIZE:
                logger.warning(f"Message too large from {self.info.host}: {payload_len}")
                await self.disconnect()
                return None
            
            # Read payload + checksum (4 bytes)
            remainder = await self.reader.readexactly(payload_len + 4)
            
            # Parse full message
            full_data = header + remainder
            return Message.from_bytes(full_data)
            
        except asyncio.IncompleteReadError:
            logger.info(f"Peer disconnected: {self.info.host}:{self.info.port}")
            await self.disconnect()
            return None
            
        except Exception as e:
            logger.error(f"Receive error from {self.info.host}:{self.info.port}: {e}")
            await self.disconnect()
            return None
    
    def start_receiving(self, handler: Callable[[Message], None]) -> None:
        """Start background task to receive messages."""
        self._message_handler = handler
        self._receive_task = asyncio.create_task(self._receive_loop())
    
    async def _receive_loop(self) -> None:
        """Background loop to receive and handle messages."""
        while self.state == PeerState.CONNECTED:
            message = await self.receive()
            if message and self._message_handler:
                try:
                    await self._message_handler(message, self)
                except Exception as e:
                    logger.error(f"Message handler error: {e}")
    
    @property
    def is_connected(self) -> bool:
        return self.state == PeerState.CONNECTED


async def create_peer(host: str, port: int) -> Peer:
    """Create and connect to a peer."""
    peer = Peer(info=PeerInfo(host=host, port=port))
    await peer.connect()
    return peer
