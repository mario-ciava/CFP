"""
Network Protocol - Message types and serialization for CFP P2P.

Defines the wire protocol for peer communication.
"""

import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from cfp.crypto import sha256


class MessageType(IntEnum):
    """Types of messages in the P2P protocol."""
    PING = 0
    PONG = 1
    VERTEX = 2
    TX = 3
    INTENT = 4
    SYNC_REQUEST = 5
    SYNC_RESPONSE = 6
    PEER_LIST = 7


# Protocol constants
PROTOCOL_VERSION = 1
MAGIC_BYTES = b"CFP1"  # 4 bytes, identifies CFP protocol
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB max message


@dataclass
class Message:
    """
    A P2P protocol message.
    
    Wire format:
        magic (4) | version (1) | type (1) | payload_len (4) | payload (n) | checksum (4)
    """
    msg_type: MessageType
    payload: bytes
    sender_id: Optional[bytes] = None  # 32-byte peer ID
    timestamp: int = 0
    
    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = int(time.time())
    
    def to_bytes(self) -> bytes:
        """Serialize message to wire format."""
        # Build payload with metadata
        meta = struct.pack(
            ">Q32s",  # timestamp (8) + sender_id (32)
            self.timestamp,
            self.sender_id or bytes(32),
        )
        full_payload = meta + self.payload
        
        # Build header
        header = struct.pack(
            ">4sBBI",  # magic (4) + version (1) + type (1) + length (4)
            MAGIC_BYTES,
            PROTOCOL_VERSION,
            self.msg_type,
            len(full_payload),
        )
        
        # Checksum (first 4 bytes of SHA256)
        checksum = sha256(header + full_payload)[:4]
        
        return header + full_payload + checksum
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        """Deserialize message from wire format."""
        if len(data) < 14:  # Minimum: header (10) + checksum (4)
            raise ValueError("Message too short")
        
        # Parse header
        magic, version, msg_type, payload_len = struct.unpack(">4sBBI", data[:10])
        
        if magic != MAGIC_BYTES:
            raise ValueError(f"Invalid magic bytes: {magic}")
        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")
        
        # Extract payload and checksum
        full_payload = data[10:10 + payload_len]
        checksum = data[10 + payload_len:10 + payload_len + 4]
        
        # Verify checksum
        expected_checksum = sha256(data[:10] + full_payload)[:4]
        if checksum != expected_checksum:
            raise ValueError("Checksum mismatch")
        
        # Parse metadata from payload
        timestamp, sender_id = struct.unpack(">Q32s", full_payload[:40])
        payload = full_payload[40:]
        
        return cls(
            msg_type=MessageType(msg_type),
            payload=payload,
            sender_id=sender_id if sender_id != bytes(32) else None,
            timestamp=timestamp,
        )


def create_ping(sender_id: bytes) -> Message:
    """Create a PING message."""
    return Message(
        msg_type=MessageType.PING,
        payload=b"",
        sender_id=sender_id,
    )


def create_pong(sender_id: bytes, ping_timestamp: int) -> Message:
    """Create a PONG response to a PING."""
    return Message(
        msg_type=MessageType.PONG,
        payload=struct.pack(">Q", ping_timestamp),
        sender_id=sender_id,
    )


def create_vertex_message(sender_id: bytes, vertex_bytes: bytes) -> Message:
    """Create a VERTEX propagation message."""
    return Message(
        msg_type=MessageType.VERTEX,
        payload=vertex_bytes,
        sender_id=sender_id,
    )


def create_sync_request(sender_id: bytes, from_vertex_id: bytes) -> Message:
    """Request DAG sync starting from a vertex."""
    return Message(
        msg_type=MessageType.SYNC_REQUEST,
        payload=from_vertex_id,
        sender_id=sender_id,
    )
