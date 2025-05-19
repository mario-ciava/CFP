from pathlib import Path
from typing import Optional, List, overload

from cfp.core.storage.sqlite_adapter import SQLiteAdapter
from cfp.utils.logger import get_logger

logger = get_logger("storage.manager")


class StorageManager:
    """
    Manages persistent storage for the node.
    
    Coordinates data persistence using SQLite adapter.
    Handles:
    - Block/Transaction storage (KV Store)
    - Global State Persistence (Commitments & Nullifiers)
    - Metadata (Chain Tip)
    """

    def __init__(self, data_dir: Path, db_name: str = "node.db"):
        self.data_dir = data_dir
        self.db_path = data_dir / db_name
        self.adapter = SQLiteAdapter(self.db_path)
        
        logger.info(f"StorageManager initialized at {self.db_path}")

    # =========================================================================
    # Chain State (Metadata)
    # =========================================================================

    def save_tip(self, block_hash: str, height: int):
        """Save the latest block hash and height."""
        self.adapter.set_chain_meta("latest_block_hash", block_hash)
        self.adapter.set_chain_meta("latest_block_height", str(height))

    def get_tip(self) -> Optional[tuple[str, int]]:
        """Get the latest block hash and height."""
        h = self.adapter.get_chain_meta("latest_block_hash")
        n = self.adapter.get_chain_meta("latest_block_height")
        if h and n:
            return h, int(n)
        return None

    # =========================================================================
    # Blocks & Vertices (Content Addressable)
    # =========================================================================

    def save_block(self, block_hash: str, block_data: bytes):
        """Save raw block data."""
        key = bytes.fromhex(block_hash)
        self.adapter.put(key, block_data, bucket="blocks")

    def get_block(self, block_hash: str) -> Optional[bytes]:
        """Get raw block data."""
        key = bytes.fromhex(block_hash)
        return self.adapter.get(key)
        
    def has_block(self, block_hash: str) -> bool:
        return self.get_block(block_hash) is not None

    # =========================================================================
    # ZK / Ledger State
    # =========================================================================

    def persist_commitment(self, index: int, commitment: bytes, tx_hash: bytes):
        """Persist a new Merkle Tree leaf."""
        self.adapter.save_commitment(index, commitment, tx_hash)

    def persist_nullifier(self, nullifier: bytes, tx_hash: bytes):
        """Persist a spent nullifier."""
        self.adapter.save_nullifier(nullifier, tx_hash)

    def get_commitment(self, index: int) -> Optional[bytes]:
        return self.adapter.get_commitment(index)

    def is_nullifier_spent(self, nullifier: bytes) -> bool:
        return self.adapter.is_nullifier_spent(nullifier)
    
    def get_commitment_count(self) -> int:
        return self.adapter.get_commitments_count()

    # =========================================================================
    # DAG / Sequencer Support
    # =========================================================================

    def persist_vertex(self, vertex, vertex_bytes: bytes):
        """Persist vertex topology and data."""
        # vertex object is passed for properties (id, timestamp, parents)
        # vertex_bytes is the serialized data
        self.adapter.save_vertex(vertex.vertex_id, vertex_bytes, vertex.timestamp)
        
        edges = [(p, vertex.vertex_id) for p in vertex.parents]
        if edges:
            self.adapter.save_edges(edges)

    def load_dag_vertices(self) -> List[bytes]:
        """Load all vertices ordered by timestamp."""
        return self.adapter.get_all_vertices_ordered()

    def load_dag_edges(self) -> List[Any]:
        """Load all parent->child edges."""
        return self.adapter.get_edges()

    # =========================================================================
    # Ledger Support
    # =========================================================================

    def persist_transaction(self, tx_hash: bytes, data: bytes, height: int):
        self.adapter.save_transaction(tx_hash, data, height)

    def persist_utxo(self, utxo_id: bytes, data: bytes):
        self.adapter.save_utxo(utxo_id, data)

    def remove_utxo(self, utxo_id: bytes):
        self.adapter.delete_utxo(utxo_id)
        
    def persist_snapshot(self, height: int, root: bytes, null_count: int, utxo_count: int):
        self.adapter.save_snapshot(height, root, null_count, utxo_count)
        
    def load_ledger_state(self) -> Tuple[List, List, List]:
        """
        Load full ledger state.
        
        Returns:
            (utxos, nullifiers, snapshots)
            utxos: List[(id, data)]
            nullifiers: List[bytes]
            snapshots: List[tuple]
        """
        utxos = self.adapter.get_all_utxos()
        nullifiers = self.adapter.get_all_nullifiers()
        snapshots = self.adapter.get_all_snapshots()
        return utxos, nullifiers, snapshots

    def persist_ledger_update(
        self,
        tx_hash: bytes,
        tx_data: bytes,
        height: int,
        spent_utxo_ids: List[bytes],
        new_nullifiers: List[bytes],
        new_utxos: List[Tuple[bytes, bytes]]
    ):
        """Atomically persist ledger update."""
        self.adapter.persist_ledger_update(
            tx_hash, tx_data, height, spent_utxo_ids, new_nullifiers, new_utxos
        )
