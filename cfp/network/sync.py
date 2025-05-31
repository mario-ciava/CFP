"""
Sync Manager - State synchronization for CFP nodes.

Handles synchronization of:
- DAG vertices (historical and new)
- UTXO set snapshots
- Nullifier set

Protocol:
1. New node sends SYNC_REQUEST with highest known vertex
2. Peer responds with SYNC_RESPONSE containing missing vertices
3. Node validates and applies vertices incrementally
4. Optionally requests full state snapshot for fresh nodes
"""

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable, TYPE_CHECKING
from enum import IntEnum

from cfp.crypto import sha256
from cfp.network.protocol import (
    Message,
    MessageType,
    create_sync_request,
)
from cfp.utils.logger import get_logger

if TYPE_CHECKING:
    from cfp.network.peer import Peer
    from cfp.core.dag import DAGSequencer
    from cfp.core.state import Ledger

logger = get_logger("sync")


class SyncState(IntEnum):
    """Synchronization state."""
    IDLE = 0
    SYNCING_DAG = 1
    SYNCING_STATE = 2
    COMPLETE = 3


@dataclass
class SyncProgress:
    """Tracks sync progress."""
    state: SyncState = SyncState.IDLE
    vertices_received: int = 0
    vertices_total: int = 0
    state_root_target: Optional[bytes] = None
    last_update: int = 0
    
    @property
    def progress_percent(self) -> float:
        if self.vertices_total == 0:
            return 0.0
        return (self.vertices_received / self.vertices_total) * 100


class SyncManager:
    """
    Manages state synchronization between nodes.
    
    Coordinates DAG sync for vertices and state sync for UTXO snapshots.
    """
    
    # Maximum vertices per response message
    MAX_VERTICES_PER_BATCH = 100
    
    # Sync timeout in seconds
    SYNC_TIMEOUT = 300
    
    def __init__(
        self,
        dag: Optional["DAGSequencer"] = None,
        ledger: Optional["Ledger"] = None,
    ):
        self.dag = dag
        self.ledger = ledger
        self.progress = SyncProgress()
        self._pending_requests: Dict[bytes, asyncio.Future] = {}
        
    def get_highest_vertex(self) -> Optional[bytes]:
        """Get the highest known vertex ID (tip of DAG)."""
        if self.dag is None:
            return None
        tips = self.dag.get_tips()
        return tips[0] if tips else None
    
    def get_state_root(self) -> Optional[bytes]:
        """Get current state root."""
        if self.ledger is None:
            return None
        return self.ledger.state_root
    
    async def request_sync(
        self,
        peer: "Peer",
        from_vertex: Optional[bytes] = None,
    ) -> bool:
        """
        Request synchronization from a peer.
        
        Args:
            peer: Peer to sync from
            from_vertex: Start sync from this vertex (None = from genesis)
            
        Returns:
            True if sync request was sent
        """
        if self.progress.state != SyncState.IDLE:
            logger.warning("Sync already in progress")
            return False
        
        self.progress.state = SyncState.SYNCING_DAG
        
        # Use genesis marker if no starting point
        start_vertex = from_vertex or bytes(32)
        
        msg = create_sync_request(
            sender_id=bytes(32),  # Will be set by node
            from_vertex_id=start_vertex,
        )
        
        success = await peer.send(msg)
        if success:
            logger.info(f"Sync request sent to {peer.info.host}")
        
        return success
    
    async def handle_sync_request(
        self,
        message: Message,
        peer: "Peer",
    ) -> None:
        """
        Handle incoming sync request.
        
        Responds with vertices after the requested starting point.
        """
        if self.dag is None:
            logger.warning("Cannot handle sync: no DAG")
            return
        
        from_vertex_id = message.payload
        
        # Get vertices after this point
        vertices_to_send = self._get_vertices_after(from_vertex_id)
        
        # Send response
        response = create_sync_response(
            sender_id=bytes(32),
            vertices=vertices_to_send,
            has_more=len(vertices_to_send) >= self.MAX_VERTICES_PER_BATCH,
            state_root=self.get_state_root() or bytes(32),
        )
        
        await peer.send(response)
        logger.info(f"Sent {len(vertices_to_send)} vertices to {peer.info.host}")
    
    async def handle_sync_response(
        self,
        message: Message,
        peer: "Peer",
    ) -> None:
        """
        Handle sync response with vertices.
        
        Validates and applies received vertices.
        """
        if self.dag is None:
            logger.warning("Cannot apply sync: no DAG")
            return
        
        # Parse response
        vertices, has_more, state_root = parse_sync_response(message.payload)
        
        self.progress.vertices_received += len(vertices)
        self.progress.state_root_target = state_root
        
        # Apply vertices
        applied = 0
        for vertex_bytes in vertices:
            try:
                from cfp.core.dag import Vertex
                vertex = Vertex.from_bytes(vertex_bytes)
                
                # Check if we already have it
                if not self.dag.has_vertex(vertex.vertex_id):
                    success, _ = self.dag.add_vertex(vertex)
                    if success:
                        applied += 1
            except Exception as e:
                logger.warning(f"Failed to apply vertex: {e}")
        
        logger.info(f"Applied {applied}/{len(vertices)} vertices from sync")
        
        # Request more if needed
        if has_more:
            await self.request_sync(peer, self.get_highest_vertex())
        else:
            self.progress.state = SyncState.COMPLETE
            logger.info("DAG sync complete")
    
    def _get_vertices_after(self, from_vertex_id: bytes) -> List[bytes]:
        """Get serialized vertices after a given vertex."""
        if self.dag is None:
            return []
        
        vertices = []
        
        # If from_vertex is zeros, start from genesis
        if from_vertex_id == bytes(32):
            # Get all vertices in order
            for v in self.dag.linearize():
                vertices.append(v.to_bytes())
                if len(vertices) >= self.MAX_VERTICES_PER_BATCH:
                    break
        else:
            # Get vertices after this one
            order = self.dag.linearize()
            found = False
            for v in order:
                if found:
                    vertices.append(v.to_bytes())
                    if len(vertices) >= self.MAX_VERTICES_PER_BATCH:
                        break
                elif v.vertex_id == from_vertex_id:
                    found = True
        
        return vertices
    
    def is_synced(self) -> bool:
        """Check if node is fully synced."""
        return self.progress.state == SyncState.COMPLETE


# =============================================================================
# Protocol Helpers
# =============================================================================


def create_sync_response(
    sender_id: bytes,
    vertices: List[bytes],
    has_more: bool,
    state_root: bytes,
) -> Message:
    """
    Create a SYNC_RESPONSE message.
    
    Payload format:
        has_more (1) | state_root (32) | num_vertices (4) | [len (4) | vertex_bytes]...
    """
    parts = [
        struct.pack(">B", 1 if has_more else 0),
        state_root[:32].ljust(32, b'\x00'),
        struct.pack(">I", len(vertices)),
    ]
    
    for v in vertices:
        parts.append(struct.pack(">I", len(v)))
        parts.append(v)
    
    payload = b"".join(parts)
    
    return Message(
        msg_type=MessageType.SYNC_RESPONSE,
        payload=payload,
        sender_id=sender_id,
    )


def parse_sync_response(payload: bytes) -> Tuple[List[bytes], bool, bytes]:
    """
    Parse a SYNC_RESPONSE payload.
    
    Returns:
        (vertices, has_more, state_root)
    """
    if len(payload) < 37:
        return [], False, bytes(32)
    
    has_more = struct.unpack(">B", payload[0:1])[0] == 1
    state_root = payload[1:33]
    num_vertices = struct.unpack(">I", payload[33:37])[0]
    
    vertices = []
    offset = 37
    
    for _ in range(num_vertices):
        if offset + 4 > len(payload):
            break
        v_len = struct.unpack(">I", payload[offset:offset+4])[0]
        offset += 4
        
        if offset + v_len > len(payload):
            break
        vertices.append(payload[offset:offset+v_len])
        offset += v_len
    
    return vertices, has_more, state_root
