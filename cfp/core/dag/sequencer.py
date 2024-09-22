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
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from cfp.core.dag.vertex import Vertex, PayloadType, GENESIS_VERTEX_ID
from cfp.utils.logger import get_logger

logger = get_logger("dag")


# =============================================================================
# Orphan Pool
# =============================================================================


@dataclass
class OrphanPool:
    """
    Pool for vertices waiting on missing parents.
    
    When a vertex arrives but its parent(s) are not yet in the DAG,
    it's placed in the orphan pool. When the missing parent arrives,
    we attempt to process orphans again.
    
    Structure:
        orphans: vertex_id -> Vertex (orphaned vertices)
        waiting_on: missing_parent_id -> [vertex_ids waiting for it]
    """
    orphans: Dict[bytes, Vertex] = field(default_factory=dict)
    waiting_on: Dict[bytes, Set[bytes]] = field(default_factory=lambda: defaultdict(set))
    
    def add(self, vertex: Vertex, missing_parents: List[bytes]) -> None:
        """
        Add a vertex to the orphan pool.
        
        Args:
            vertex: The orphaned vertex
            missing_parents: List of parent IDs that are missing
        """
        self.orphans[vertex.vertex_id] = vertex
        for parent_id in missing_parents:
            self.waiting_on[parent_id].add(vertex.vertex_id)
        logger.debug(f"Orphaned vertex {vertex.vertex_id.hex()[:8]}... waiting on {len(missing_parents)} parents")
    
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
    
    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialize the DAG sequencer.
        
        Args:
            data_dir: Directory for persistence (SQLite). None = in-memory only.
        """
        self.graph = nx.DiGraph()
        self.vertices: Dict[bytes, Vertex] = {}
        self.tips: Set[bytes] = set()
        self.orphan_pool = OrphanPool()
        self.genesis_id: Optional[bytes] = None
        
        # Persistence
        self.data_dir = data_dir
        self._db: Optional[sqlite3.Connection] = None
        
        if data_dir:
            self._init_persistence()
    
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
        if self._db:
            self._persist_vertex(vertex)
    
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
    
    def _init_persistence(self) -> None:
        """Initialize SQLite database for persistence."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        db_path = self.data_dir / "dag.db"
        self._db = sqlite3.connect(str(db_path))
        
        # Create tables
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS vertices (
                vertex_id BLOB PRIMARY KEY,
                data BLOB NOT NULL,
                timestamp INTEGER NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS edges (
                parent_id BLOB NOT NULL,
                child_id BLOB NOT NULL,
                PRIMARY KEY (parent_id, child_id)
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value BLOB
            )
        """)
        self._db.commit()
        
        # Load existing data
        self._load_from_db()
    
    def _persist_vertex(self, vertex: Vertex) -> None:
        """Persist a vertex to SQLite."""
        if not self._db:
            return
        
        self._db.execute(
            "INSERT OR REPLACE INTO vertices (vertex_id, data, timestamp) VALUES (?, ?, ?)",
            (vertex.vertex_id, vertex.to_bytes(), vertex.timestamp)
        )
        for parent_id in vertex.parents:
            self._db.execute(
                "INSERT OR REPLACE INTO edges (parent_id, child_id) VALUES (?, ?)",
                (parent_id, vertex.vertex_id)
            )
        self._db.commit()
    
    def _load_from_db(self) -> None:
        """Load DAG from SQLite."""
        if not self._db:
            return
        
        # Load vertices
        cursor = self._db.execute("SELECT data FROM vertices ORDER BY timestamp")
        for (data,) in cursor:
            vertex = Vertex.from_bytes(data)
            self.vertices[vertex.vertex_id] = vertex
            self.graph.add_node(vertex.vertex_id)
            if vertex.is_genesis():
                self.genesis_id = vertex.vertex_id
        
        # Load edges
        cursor = self._db.execute("SELECT parent_id, child_id FROM edges")
        for parent_id, child_id in cursor:
            self.graph.add_edge(parent_id, child_id)
        
        # Rebuild tips
        self.tips = set()
        for vertex_id in self.graph.nodes():
            if self.graph.out_degree(vertex_id) == 0:
                self.tips.add(vertex_id)
        
        logger.info(f"Loaded {len(self.vertices)} vertices from database")
    
    def close(self) -> None:
        """Close the database connection."""
        if self._db:
            self._db.close()
            self._db = None
    
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
