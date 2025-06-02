"""
DAG Sequencer - The core DAG engine for Convergent Flow Protocol.

Conceptual Background:
---------------------
The DAGSequencer maintains the DAG structure and provides operations for:

1. **Vertex Insertion**: Add new vertices with validation
2. **Topological Ordering**: Deterministic linearization of the DAG
3. **Tip Management**: Track frontier vertices for new vertex creation
4. **Orphan Handling**: Queue vertices whose parents haven't arrived yet

Key Invariants:
--------------
- **Acyclicity**: The graph is always a DAG (no cycles)
- **Determinism**: All nodes produce the same linearization
- **Parent Existence**: A vertex can only be inserted if all parents exist (or queued as orphan)
- **Uniqueness**: Each vertex_id appears exactly once

Linearization Algorithm:
-----------------------
We use Kahn's algorithm (BFS-based topological sort) with deterministic tie-breaking:
1. Start with vertices of in-degree 0 (genesis)
2. Among ready vertices, pick the one with lowest vertex_id (lexicographic)
3. Remove it, decrease in-degree of children
4. Repeat until all vertices processed

This ensures all nodes, given the same DAG, produce identical linear order.

Orphan Pool:
-----------
In a network environment, messages can arrive out of order:
- Vertex V2 references V1 as parent
- V2 arrives before V1
- V2 is "orphaned" - we can't add it yet

The orphan pool queues such vertices and automatically processes them when parents arrive.
"""

import time
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from cfp.core.dag.vertex import Vertex, PayloadType, GENESIS_VERTEX_ID
from cfp.core.storage.storage_manager import StorageManager
from cfp.utils.logger import get_logger

logger = get_logger("dag")


# =============================================================================
# Orphan Pool
# =============================================================================

# Maximum orphan pool size to prevent memory exhaustion
MAX_ORPHAN_POOL_SIZE = 10000


@dataclass
class OrphanPool:
    """
    Pool for vertices waiting on missing parents.
    
    When a vertex arrives but its parent(s) are not yet in the DAG,
    it's placed in the orphan pool. When the missing parent arrives,
    we attempt to process orphans again.
    
    SECURITY: Pool is bounded to MAX_ORPHAN_POOL_SIZE to prevent DoS.
    When full, oldest orphan (by timestamp) is evicted.
    
    Structure:
        orphans: vertex_id -> Vertex (orphaned vertices)
        waiting_on: missing_parent_id -> [vertex_ids waiting for it]
    """
    orphans: Dict[bytes, Vertex] = field(default_factory=dict)
    waiting_on: Dict[bytes, Set[bytes]] = field(default_factory=lambda: defaultdict(set))
    max_size: int = MAX_ORPHAN_POOL_SIZE
    
    def add(self, vertex: Vertex, missing_parents: List[bytes]) -> None:
        """
        Add a vertex to the orphan pool.
        
        SECURITY: If pool is at capacity, evicts oldest orphan first.
        
        Args:
            vertex: The orphaned vertex
            missing_parents: List of parent IDs that are missing
        """
        # SECURITY: Evict oldest orphan if at capacity
        if len(self.orphans) >= self.max_size:
            self._evict_oldest()
        
        self.orphans[vertex.vertex_id] = vertex
        for parent_id in missing_parents:
            self.waiting_on[parent_id].add(vertex.vertex_id)
        logger.debug(f"Orphaned vertex {vertex.vertex_id.hex()[:8]}... waiting on {len(missing_parents)} parents")
    
    def _evict_oldest(self) -> None:
        """Evict the oldest orphan by timestamp."""
        if not self.orphans:
            return
        
        oldest = min(self.orphans.values(), key=lambda v: v.timestamp)
        oldest_id = oldest.vertex_id
        
        # Remove from orphans
        del self.orphans[oldest_id]
        
        # Clean up waiting_on references
        for parent_id in list(self.waiting_on.keys()):
            self.waiting_on[parent_id].discard(oldest_id)
            if not self.waiting_on[parent_id]:
                del self.waiting_on[parent_id]
        
        logger.warning(f"Evicted oldest orphan {oldest_id.hex()[:8]}... (pool at capacity)")
    
    def get_ready(self, arrived_parent_id: bytes) -> List[Vertex]:
        """
        Get orphans that may now be ready after a parent arrived.
        
        Args:
            arrived_parent_id: ID of the vertex that just arrived
            
        Returns:
            List of vertices to re-attempt (may still have other missing parents)
        """
        waiting = self.waiting_on.pop(arrived_parent_id, set())
        ready = []
        for vertex_id in waiting:
            if vertex_id in self.orphans:
                ready.append(self.orphans[vertex_id])
        return ready
    
    def remove(self, vertex_id: bytes) -> None:
        """Remove a vertex from the orphan pool (after successful insertion)."""
        if vertex_id in self.orphans:
            del self.orphans[vertex_id]
    
    def __len__(self) -> int:
        return len(self.orphans)


# =============================================================================
# DAG Sequencer
# =============================================================================


class DAGSequencer:
    """
    Core DAG engine for CFP.
    
    Maintains the DAG structure using networkx.DiGraph internally.
    Provides vertex insertion, validation, linearization, and persistence.
    
    Attributes:
        graph: networkx DiGraph (edges go from parent to child)
        vertices: Mapping of vertex_id to Vertex objects
        tips: Set of current tip vertex IDs (no children)
        orphan_pool: Pool of vertices waiting for missing parents
        genesis_id: ID of the genesis vertex (None until initialized)
    """
    
    def __init__(self, storage_manager: Optional[StorageManager] = None):
        """
        Initialize the DAG sequencer.
        
        Args:
            storage_manager: Shared Persistence manager. None = in-memory only.
        """
        self.graph = nx.DiGraph()
        self.vertices: Dict[bytes, Vertex] = {}
        self.tips: Set[bytes] = set()
        self.orphan_pool = OrphanPool()
        self.genesis_id: Optional[bytes] = None
        
        # Persistence
        self.storage_manager = storage_manager
        
        if storage_manager:
            self._load_from_storage()
    
    # =========================================================================
    # Vertex Operations
    # =========================================================================
    
    def add_vertex(self, vertex: Vertex) -> Tuple[bool, str]:
        """
        Add a vertex to the DAG.
        
        Validation steps:
        1. Check vertex not already in DAG
        2. Validate vertex structure (signature, timestamp, etc.)
        3. Check all parents exist (or orphan the vertex)
        4. Verify no cycle would be created (implicit: parents are ancestors)
        5. Verify timestamp >= max(parent timestamps)
        6. Add to DAG and update tips
        
        Args:
            vertex: The vertex to add
            
        Returns:
            (success, message)
        """
        # Check for duplicate
        if vertex.vertex_id in self.vertices:
            return False, "Duplicate vertex"
        
        # Validate structure
        is_valid, error = vertex.validate_structure()
        if not is_valid:
            return False, f"Invalid structure: {error}"
        
        # Genesis handling
        if vertex.is_genesis():
            return self._add_genesis(vertex)
        
        # Check parents exist
        missing_parents = [p for p in vertex.parents if p not in self.vertices]
        if missing_parents:
            # Orphan this vertex
            self.orphan_pool.add(vertex, missing_parents)
            return True, f"Orphaned, waiting for {len(missing_parents)} parent(s)"
        
        # Validate timestamp ordering
        max_parent_ts = max(self.vertices[p].timestamp for p in vertex.parents)
        if vertex.timestamp < max_parent_ts:
            return False, f"Timestamp {vertex.timestamp} < parent timestamp {max_parent_ts}"
        
        # Add to DAG
        self._insert_vertex(vertex)
        
        # Process any orphans that were waiting for this vertex
        self._process_orphans(vertex.vertex_id)
        
        logger.info(f"Added vertex {vertex.vertex_id.hex()[:8]}... with {len(vertex.parents)} parent(s)")
        return True, "Added successfully"
    
    def _add_genesis(self, vertex: Vertex) -> Tuple[bool, str]:
        """Add the genesis vertex (special case: no parents allowed only once)."""
        if self.genesis_id is not None:
            return False, "Genesis already exists"
        
        self._insert_vertex(vertex)
        self.genesis_id = vertex.vertex_id
        logger.info(f"Added genesis vertex {vertex.vertex_id.hex()[:8]}...")
        return True, "Genesis added"
    
    def _insert_vertex(self, vertex: Vertex) -> None:
        """Internal: insert vertex into graph and update tips."""
        # Add to vertices dict
        self.vertices[vertex.vertex_id] = vertex
        
        # Add node to graph
        self.graph.add_node(vertex.vertex_id)
        
        # Add edges from parents
        for parent_id in vertex.parents:
            self.graph.add_edge(parent_id, vertex.vertex_id)
            # Parent is no longer a tip
            self.tips.discard(parent_id)
        
        # New vertex is a tip (no children yet)
        self.tips.add(vertex.vertex_id)
        
        # Persist
        if self.storage_manager:
            self.storage_manager.persist_vertex(vertex, vertex.to_bytes())
    
    def _process_orphans(self, arrived_id: bytes) -> None:
        """Process orphans that were waiting for this vertex."""
        ready = self.orphan_pool.get_ready(arrived_id)
        for orphan in ready:
            # Check if all parents now exist
            missing = [p for p in orphan.parents if p not in self.vertices]
            if not missing:
                # Can now insert
                self.orphan_pool.remove(orphan.vertex_id)
                success, msg = self.add_vertex(orphan)
                logger.debug(f"Processed orphan {orphan.vertex_id.hex()[:8]}...: {msg}")
    
    # =========================================================================
    # Query Operations
    # =========================================================================
    
    def get_vertex(self, vertex_id: bytes) -> Optional[Vertex]:
        """Get a vertex by ID."""
        return self.vertices.get(vertex_id)
    
    def get_tips(self) -> List[bytes]:
        """
        Get current tip vertex IDs (vertices with no children).
        
        These are the vertices a new vertex should reference as parents.
        """
        return list(self.tips)
    
    def get_parents(self, vertex_id: bytes) -> List[bytes]:
        """Get parent IDs of a vertex."""
        vertex = self.vertices.get(vertex_id)
        return vertex.parents if vertex else []
    
    def get_children(self, vertex_id: bytes) -> List[bytes]:
        """Get child IDs of a vertex."""
        if vertex_id in self.graph:
            return list(self.graph.successors(vertex_id))
        return []
    
    def is_ancestor(self, potential_ancestor: bytes, vertex: bytes) -> bool:
        """
        Check if `potential_ancestor` is an ancestor of `vertex`.
        
        Uses networkx's has_path which does BFS/DFS.
        """
        if potential_ancestor not in self.graph or vertex not in self.graph:
            return False
        return nx.has_path(self.graph, potential_ancestor, vertex)
    
    def vertex_count(self) -> int:
        """Total number of vertices in DAG."""
        return len(self.vertices)
    
    def orphan_count(self) -> int:
        """Number of orphaned vertices waiting."""
        return len(self.orphan_pool)
    
    # =========================================================================
    # Linearization (Topological Sort)
    # =========================================================================
    
    def linearize(self) -> List[bytes]:
        """
        Produce a deterministic linear order of all vertices.
        
        Uses Kahn's algorithm with lexicographic tie-breaking on vertex_id.
        
        Returns:
            List of vertex IDs in linear order (genesis first)
        """
        if not self.vertices:
            return []
        
        # Calculate in-degrees
        in_degree = {v: 0 for v in self.graph.nodes()}
        for u, v in self.graph.edges():
            in_degree[v] += 1
        
        # Start with nodes of in-degree 0
        ready = [v for v, deg in in_degree.items() if deg == 0]
        result = []
        
        while ready:
            # Sort for determinism: lowest vertex_id first
            ready.sort()
            current = ready.pop(0)
            result.append(current)
            
            # Decrease in-degree of children
            for child in self.graph.successors(current):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    ready.append(child)
        
        return result
    
    def linearize_from(self, start_vertex: bytes) -> List[bytes]:
        """
        Linearize only the subgraph reachable from start_vertex.
        
        Useful for partial execution or verification.
        """
        if start_vertex not in self.graph:
            return []
        
        # Get descendants
        descendants = nx.descendants(self.graph, start_vertex)
        descendants.add(start_vertex)
        
        # Filter to subgraph and linearize
        subgraph = self.graph.subgraph(descendants)
        
        # Same algorithm on subgraph
        in_degree = {v: 0 for v in subgraph.nodes()}
        for u, v in subgraph.edges():
            in_degree[v] += 1
        
        ready = [v for v, deg in in_degree.items() if deg == 0]
        result = []
        
        while ready:
            ready.sort()
            current = ready.pop(0)
            result.append(current)
            
            for child in subgraph.successors(current):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    ready.append(child)
        
        return result
    
    # =========================================================================
    # Persistence
    # =========================================================================
    
    def _load_from_storage(self) -> None:
        """Load DAG from StorageManager."""
        if not self.storage_manager:
            return
        
        # Load vertices
        # Optimized loading: Get all vertices ordered by timestamp
        vertex_data_list = self.storage_manager.load_dag_vertices()
        
        for data in vertex_data_list:
            vertex = Vertex.from_bytes(data)
            self.vertices[vertex.vertex_id] = vertex
            self.graph.add_node(vertex.vertex_id)
            if vertex.is_genesis():
                self.genesis_id = vertex.vertex_id
        
        # Load edges
        edges = self.storage_manager.load_dag_edges()
        for parent_id, child_id in edges:
            self.graph.add_edge(parent_id, child_id)
        
        # Rebuild tips
        self.tips = set()
        for vertex_id in self.graph.nodes():
            if self.graph.out_degree(vertex_id) == 0:
                self.tips.add(vertex_id)
        
        logger.info(f"Loaded {len(self.vertices)} vertices from storage")
    
    def close(self) -> None:
        """Cleanup resources."""
        # Storage manager lifecycle is handled by Node
        pass
    
    # =========================================================================
    # Utility
    # =========================================================================
    
    def __repr__(self) -> str:
        return f"DAGSequencer(vertices={len(self.vertices)}, tips={len(self.tips)}, orphans={len(self.orphan_pool)})"
    
    def to_dict(self) -> dict:
        """Export DAG structure as dictionary (for debugging/visualization)."""
        return {
            "vertex_count": len(self.vertices),
            "edge_count": self.graph.number_of_edges(),
            "tips": [vid.hex()[:8] for vid in self.tips],
            "orphans": len(self.orphan_pool),
            "genesis": self.genesis_id.hex()[:8] if self.genesis_id else None,
        }
