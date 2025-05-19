"""
Persistent Storage Module.

Provides SQLite-backed persistence for:
- Blocks and Transactions (KV Store)
- ZK State (Commitments, Nullifiers)
- Chain Metadata
"""

from cfp.core.storage.sqlite_adapter import SQLiteAdapter
from cfp.core.storage.storage_manager import StorageManager

__all__ = ["SQLiteAdapter", "StorageManager"]
