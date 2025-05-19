import sqlite3
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any, Union

from cfp.utils.logger import get_logger

logger = get_logger("storage.sqlite")


class SQLiteAdapter:
    """
    SQLite backend for persistent storage.
    
    Provides:
    1. Key-Value store for arbitrary binary data (Blocks, Transactions).
    2. Zero-Knowledge State Storage:
       - Commitments (Merkle Tree leaves)
       - Nullifiers (Spent set)
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn_local = threading.local()
        
        # Ensure directory exists
        if not db_path.parent.exists():
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create connection for current thread."""
        if not hasattr(self._conn_local, "conn"):
            self._conn_local.conn = sqlite3.connect(
                self.db_path, 
                timeout=30.0,
                check_same_thread=False
            )
            self._conn_local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrency
            self._conn_local.conn.execute("PRAGMA journal_mode=WAL;")
            self._conn_local.conn.execute("PRAGMA synchronous=NORMAL;")
        return self._conn_local.conn

    def _init_schema(self):
        """Initialize database schema."""
        conn = self._get_conn()
        with conn:
            # 1. KV Store
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kv_store (
                    key BLOB PRIMARY KEY,
                    value BLOB NOT NULL,
                    bucket TEXT NOT NULL DEFAULT 'default'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_kv_bucket ON kv_store(bucket);")

            # 2. Computable State: Commitments (Output of transactions)
            # Represents the global Merkle Tree state
            conn.execute("""
                CREATE TABLE IF NOT EXISTS commitments (
                    merkle_index INTEGER PRIMARY KEY,
                    commitment BLOB NOT NULL,
                    tx_hash BLOB NOT NULL
                )
            """)
            
            # 3. Nullifier Set (Spent Inputs)
            # Prevents double-spending
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nullifiers (
                    nullifier BLOB PRIMARY KEY,
                    tx_hash BLOB NOT NULL
                )
            """)
            
            # 4. Chain State (Metadata)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chain_state (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            # 5. DAG Topology (Vertices & Edges)
            # vertices: id, data, timestamp (for ordering)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vertices (
                    vertex_id BLOB PRIMARY KEY,
                    data BLOB NOT NULL,
                    timestamp INTEGER NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vertex_ts ON vertices(timestamp);")
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS edges (
                    parent_id BLOB NOT NULL,
                    child_id BLOB NOT NULL,
                    PRIMARY KEY (parent_id, child_id)
                )
            """)

            # 6. Ledger State
            
            # UTXOs (id -> data)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS utxos (
                    utxo_id BLOB PRIMARY KEY,
                    data BLOB NOT NULL
                )
            """)
            
            # Transactions (hash -> data, height)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    tx_hash BLOB PRIMARY KEY,
                    data BLOB NOT NULL,
                    block_height INTEGER
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_height ON transactions(block_height);")
            
            # Snapshots (height -> metadata)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    block_height INTEGER PRIMARY KEY,
                    state_root BLOB,
                    nullifier_count INTEGER,
                    utxo_count INTEGER
                )
            """)

    # =========================================================================
    # Key-Value Operations
    # =========================================================================

    def put(self, key: bytes, value: bytes, bucket: str = "default"):
        """Save a key-value pair."""
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv_store (key, value, bucket) VALUES (?, ?, ?)",
                (key, value, bucket)
            )

    def get(self, key: bytes) -> Optional[bytes]:
        """Get value by key."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT value FROM kv_store WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else None

    # =========================================================================
    # ZK State Operations
    # =========================================================================

    def save_commitment(self, index: int, commitment: bytes, tx_hash: bytes):
        """Save a new commitment at merkle index."""
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO commitments (merkle_index, commitment, tx_hash) VALUES (?, ?, ?)",
                (index, commitment, tx_hash)
            )

    def get_commitment(self, index: int) -> Optional[bytes]:
        """Get commitment by merkle index."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT commitment FROM commitments WHERE merkle_index = ?", (index,))
        row = cursor.fetchone()
        return row['commitment'] if row else None

    def save_nullifier(self, nullifier: bytes, tx_hash: bytes):
        """Mark a nullifier as spent."""
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO nullifiers (nullifier, tx_hash) VALUES (?, ?)",
                (nullifier, tx_hash)
            )

    def is_nullifier_spent(self, nullifier: bytes) -> bool:
        """Check if nullifier is spent."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT 1 FROM nullifiers WHERE nullifier = ?", (nullifier,))
        return cursor.fetchone() is not None

    def get_commitments_count(self) -> int:
        """Get total number of commitments (leaves)."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM commitments")
        return cursor.fetchone()['cnt']

    # =========================================================================
    # Chain State Operations
    # =========================================================================

    def set_chain_meta(self, key: str, value: str):
        conn = self._get_conn()
        with conn:
            conn.execute("INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)", (key, value))

    def get_chain_meta(self, key: str) -> Optional[str]:
        conn = self._get_conn()
        cursor = conn.execute("SELECT value FROM chain_state WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else None

    # =========================================================================
    # DAG Operations
    # =========================================================================

    def save_vertex(self, vertex_id: bytes, data: bytes, timestamp: int):
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO vertices (vertex_id, data, timestamp) VALUES (?, ?, ?)",
                (vertex_id, data, timestamp)
            )

    def save_edges(self, edges: List[Any]):
        """Save parent->child edges. edges = [(parent, child), ...]"""
        conn = self._get_conn()
        with conn:
            conn.executemany(
                "INSERT OR REPLACE INTO edges (parent_id, child_id) VALUES (?, ?)",
                edges
            )

    def get_all_vertices_ordered(self) -> List[bytes]:
        """Get all vertex data ordered by timestamp (ASC)."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT data FROM vertices ORDER BY timestamp ASC")
        return [row['data'] for row in cursor]

    def get_edges(self) -> List[Any]:
        """Get all edges (parent, child)."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT parent_id, child_id FROM edges")
        return [(row['parent_id'], row['child_id']) for row in cursor]

    # =========================================================================
    # Ledger Operations
    # =========================================================================

    def save_utxo(self, utxo_id: bytes, data: bytes):
        conn = self._get_conn()
        with conn:
            conn.execute("INSERT OR REPLACE INTO utxos (utxo_id, data) VALUES (?, ?)", (utxo_id, data))

    def delete_utxo(self, utxo_id: bytes):
        conn = self._get_conn()
        with conn:
            conn.execute("DELETE FROM utxos WHERE utxo_id = ?", (utxo_id,))

    def get_all_utxos(self) -> List[Tuple[bytes, bytes]]:
        """Get all (utxo_id, data)."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT utxo_id, data FROM utxos")
        return [(row['utxo_id'], row['data']) for row in cursor]

    def save_transaction(self, tx_hash: bytes, data: bytes, block_height: int):
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO transactions (tx_hash, data, block_height) VALUES (?, ?, ?)",
                (tx_hash, data, block_height)
            )

    def get_all_nullifiers(self) -> List[bytes]:
        """Get all spent nullifiers."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT nullifier FROM nullifiers")
        return [row['nullifier'] for row in cursor]

    def save_snapshot(self, height: int, root: bytes, null_count: int, utxo_count: int):
        conn = self._get_conn()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO snapshots (block_height, state_root, nullifier_count, utxo_count) VALUES (?, ?, ?, ?)",
                (height, root, null_count, utxo_count)
            )

    def get_all_snapshots(self) -> List[Tuple]:
        """Get all snapshots ordered by height."""
        conn = self._get_conn()
        cursor = conn.execute("SELECT * FROM snapshots ORDER BY block_height ASC")
        return [tuple(row) for row in cursor]

    def persist_ledger_update(
        self,
        tx_hash: bytes,
        tx_data: bytes,
        height: int,
        spent_utxo_ids: List[bytes],
        new_nullifiers: List[bytes],
        new_utxos: List[Tuple[bytes, bytes]]
    ):
        """
        Atomically update ledger state for a transaction.
        
        Args:
            tx_hash: Transaction hash
            tx_data: Serialized transaction
            height: Block height
            spent_utxo_ids: List of UTXO IDs consumed
            new_nullifiers: List of nullifiers to add
            new_utxos: List of (id, data) to add
        """
        conn = self._get_conn()
        with conn:
            # Save Transaction
            conn.execute(
                "INSERT OR REPLACE INTO transactions (tx_hash, data, block_height) VALUES (?, ?, ?)",
                (tx_hash, tx_data, height)
            )
            
            # Remove spent UTXOs
            for uid in spent_utxo_ids:
                conn.execute("DELETE FROM utxos WHERE utxo_id = ?", (uid,))
                
            # Add nullifiers
            for nullifier in new_nullifiers:
                conn.execute("INSERT OR REPLACE INTO nullifiers (nullifier) VALUES (?)", (nullifier,))
                
            # Add new UTXOs
            for uid, data in new_utxos:
                conn.execute("INSERT OR REPLACE INTO utxos (utxo_id, data) VALUES (?, ?)", (uid, data))
