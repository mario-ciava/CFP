"""
Gossip - Vertex propagation protocol for CFP.

Handles gossiping new vertices to peers and deduplication.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Set, Optional, Callable

from cfp.network.protocol import MessageType, create_vertex_message
from cfp.network.node import NetworkNode
from cfp.core.dag import Vertex
from cfp.utils.logger import get_logger


logger = get_logger("gossip")


# Maximum age for seen vertex cache (seconds)
SEEN_CACHE_TTL = 300  # 5 minutes


@dataclass
class GossipManager:
    """
    Manages vertex gossip protocol.
    
    Features:
    - Deduplication (don't re-gossip seen vertices)
    - Propagation to all connected peers
    - Integration with DAG sequencer
    """
    node: NetworkNode
    _seen_vertices: Dict[bytes, int] = field(default_factory=dict)  # vertex_id -> timestamp
    _on_new_vertex: Optional[Callable[[Vertex], None]] = None
    
    def __post_init__(self):
        # Register handler for incoming vertices
        self.node.register_handler(MessageType.VERTEX, self._handle_vertex)
    
    def set_vertex_handler(self, handler: Callable[[Vertex], None]) -> None:
        """Set callback for when new vertices are received."""
        self._on_new_vertex = handler
    
    async def gossip_vertex(self, vertex: Vertex) -> int:
        """
        Gossip a vertex to all peers.
        
        Returns:
            Number of peers it was sent to
        """
        # Mark as seen to prevent echo
        self._seen_vertices[vertex.vertex_id] = int(time.time())
        
        # Broadcast to peers
        msg = create_vertex_message(self.node.node_id, vertex.to_bytes())
        count = await self.node.broadcast(msg)
        
        logger.debug(f"Gossiped vertex {vertex.vertex_id.hex()[:8]} to {count} peers")
        return count
    
    async def _handle_vertex(self, message, peer) -> None:
        """Handle incoming vertex from a peer."""
        vertex_bytes = message.payload
        
        try:
            vertex = Vertex.from_bytes(vertex_bytes)
        except Exception as e:
            logger.warning(f"Invalid vertex from peer: {e}")
            return
        
        # Check if already seen
        if vertex.vertex_id in self._seen_vertices:
            logger.debug(f"Ignoring duplicate vertex {vertex.vertex_id.hex()[:8]}")
            return
        
        # Mark as seen
        self._seen_vertices[vertex.vertex_id] = int(time.time())
        
        logger.info(f"Received new vertex {vertex.vertex_id.hex()[:8]} from peer")
        
        # Notify handler
        if self._on_new_vertex:
            self._on_new_vertex(vertex)
        
        # Re-gossip to other peers (exclude sender)
        sender_id = message.sender_id
        msg = create_vertex_message(self.node.node_id, vertex_bytes)
        await self.node.broadcast(msg, exclude=sender_id)
    
    def cleanup_seen_cache(self) -> int:
        """Remove old entries from seen cache."""
        now = int(time.time())
        old_count = len(self._seen_vertices)
        
        self._seen_vertices = {
            vid: ts for vid, ts in self._seen_vertices.items()
            if now - ts < SEEN_CACHE_TTL
        }
        
        removed = old_count - len(self._seen_vertices)
        if removed:
            logger.debug(f"Cleaned {removed} old entries from seen cache")
        return removed
