"""
Unit tests for CFP network module.

Tests cover:
1. Protocol message serialization/deserialization
2. Checksum verification
3. Message type handling
"""

import pytest
import time

from cfp.network.protocol import (
    Message,
    MessageType,
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    create_ping,
    create_pong,
    create_vertex_message,
    create_sync_request,
)
from cfp.crypto import sha256


# =============================================================================
# Protocol Tests
# =============================================================================


class TestMessage:
    """Tests for Message serialization and deserialization."""
    
    def test_create_ping(self):
        """PING message should serialize correctly."""
        sender = sha256(b"test_sender")
        msg = create_ping(sender)
        
        assert msg.msg_type == MessageType.PING
        assert msg.sender_id == sender
        assert msg.payload == b""
    
    def test_create_pong(self):
        """PONG message should include ping timestamp."""
        sender = sha256(b"test_sender")
        ping_time = 1234567890
        msg = create_pong(sender, ping_time)
        
        assert msg.msg_type == MessageType.PONG
        assert len(msg.payload) == 8  # Timestamp is 8 bytes
    
    def test_create_vertex_message(self):
        """VERTEX message should contain vertex bytes."""
        sender = sha256(b"test_sender")
        vertex_data = b"test_vertex_data_here"
        msg = create_vertex_message(sender, vertex_data)
        
        assert msg.msg_type == MessageType.VERTEX
        assert msg.payload == vertex_data
    
    def test_create_sync_request(self):
        """SYNC_REQUEST should contain vertex ID."""
        sender = sha256(b"test_sender")
        from_vertex = sha256(b"vertex_id")
        msg = create_sync_request(sender, from_vertex)
        
        assert msg.msg_type == MessageType.SYNC_REQUEST
        assert msg.payload == from_vertex

    def test_serialization_roundtrip(self):
        """Message should survive serialization and deserialization."""
        sender = sha256(b"test_sender")
        original = Message(
            msg_type=MessageType.VERTEX,
            payload=b"test_payload_data",
            sender_id=sender,
            timestamp=int(time.time()),
        )
        
        # Serialize
        data = original.to_bytes()
        
        # Deserialize
        restored = Message.from_bytes(data)
        
        # Verify
        assert restored.msg_type == original.msg_type
        assert restored.payload == original.payload
        assert restored.sender_id == original.sender_id
        assert restored.timestamp == original.timestamp
    
    def test_checksum_validation(self):
        """Corrupted message should fail checksum."""
        sender = sha256(b"test_sender")
        msg = Message(
            msg_type=MessageType.PING,
            payload=b"",
            sender_id=sender,
        )
        
        data = bytearray(msg.to_bytes())
        
        # Corrupt a byte in the middle
        data[20] = (data[20] + 1) % 256
        
        with pytest.raises(ValueError, match="Checksum mismatch"):
            Message.from_bytes(bytes(data))
    
    def test_invalid_magic_bytes(self):
        """Invalid magic bytes should raise error."""
        data = b"XXXX" + b"\x00" * 50  # Wrong magic
        
        with pytest.raises(ValueError, match="Invalid magic bytes"):
            Message.from_bytes(data)
    
    def test_message_types(self):
        """All message types should be valid."""
        assert MessageType.PING == 0
        assert MessageType.PONG == 1
        assert MessageType.VERTEX == 2
        assert MessageType.TX == 3
        assert MessageType.INTENT == 4
        assert MessageType.SYNC_REQUEST == 5
    
    def test_wire_format_structure(self):
        """Wire format should follow specification."""
        sender = sha256(b"test")
        msg = create_ping(sender)
        data = msg.to_bytes()
        
        # Check magic bytes at start
        assert data[:4] == MAGIC_BYTES
        
        # Check version
        assert data[4] == PROTOCOL_VERSION
        
        # Check message type
        assert data[5] == MessageType.PING


class TestMessageIntegration:
    """Integration tests for message handling."""
    
    def test_multiple_message_types(self):
        """Different message types should all roundtrip correctly."""
        sender = sha256(b"sender")
        
        messages = [
            create_ping(sender),
            create_pong(sender, 12345),
            create_vertex_message(sender, b"vertex_data"),
            create_sync_request(sender, sha256(b"vertex")),
        ]
        
        for original in messages:
            data = original.to_bytes()
            restored = Message.from_bytes(data)
            assert restored.msg_type == original.msg_type
            assert restored.payload == original.payload
    
    def test_large_payload(self):
        """Large payloads should work correctly."""
        sender = sha256(b"sender")
        large_payload = b"x" * 100000  # 100KB
        
        msg = create_vertex_message(sender, large_payload)
        data = msg.to_bytes()
        restored = Message.from_bytes(data)
        
        assert restored.payload == large_payload


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
