"""
Tiered Storage - Pruning and archival for CFP.

Manages storage lifecycle:
1. Active data: Full block/vertex data in SQLite
2. Pruning: Remove old data after N blocks
3. Archival: Optional remote storage for pruned data

For prototype, we implement mock archival (local directory).
"""

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from cfp.crypto import sha256, bytes_to_hex
from cfp.utils.logger import get_logger

logger = get_logger("storage")


@dataclass
class StorageStats:
    """Storage statistics."""
    active_blocks: int
    pruned_blocks: int
    archived_blocks: int
    total_bytes: int


@dataclass
class ArchivedBlock:
    """Metadata for an archived block."""
    block_height: int
    state_root: bytes
    vertex_count: int
    archived_at: int
    archive_path: str


class PruningManager:
    """
    Manages automatic pruning of old block data.
    
    Keeps recent blocks in active storage, prunes old ones.
    """
    
    def __init__(
        self,
        max_blocks: int = 1000,
        data_dir: Optional[Path] = None,
    ):
        """
        Args:
            max_blocks: Maximum blocks to keep in active storage
            data_dir: Directory for data storage
        """
        self.max_blocks = max_blocks
        self.data_dir = data_dir or Path("data")
        
        # Track pruned blocks
        self.pruned_heights: List[int] = []
    
    def should_prune(self, current_height: int) -> bool:
        """Check if pruning is needed."""
        return current_height > self.max_blocks
    
    def get_prune_height(self, current_height: int) -> int:
        """Get the height below which to prune."""
        return max(0, current_height - self.max_blocks)
    
    def prune(
        self,
        current_height: int,
        delete_callback=None,
    ) -> List[int]:
        """
        Prune old blocks.
        
        Args:
            current_height: Current block height
            delete_callback: Function to call for each pruned height
            
        Returns:
            List of pruned block heights
        """
        prune_below = self.get_prune_height(current_height)
        pruned = []
        
        for height in range(prune_below):
            if height not in self.pruned_heights:
                if delete_callback:
                    delete_callback(height)
                self.pruned_heights.append(height)
                pruned.append(height)
        
        if pruned:
            logger.info(f"Pruned {len(pruned)} blocks below height {prune_below}")
        
        return pruned


class MockArchivalNode:
    """
    Mock archival node for testing.
    
    Stores "archived" data in a local directory.
    In production, this would use IPFS, S3, etc.
    """
    
    def __init__(self, archive_dir: Optional[Path] = None):
        self.archive_dir = archive_dir or Path("data/archive")
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        
        self.archived_blocks: Dict[int, ArchivedBlock] = {}
    
    def archive_block(
        self,
        block_height: int,
        state_root: bytes,
        data: bytes,
    ) -> ArchivedBlock:
        """
        Archive a block.
        
        Args:
            block_height: Block height
            state_root: State root at this block
            data: Serialized block data
            
        Returns:
            ArchivedBlock metadata
        """
        # Write data to file
        filename = f"block_{block_height}.dat"
        path = self.archive_dir / filename
        path.write_bytes(data)
        
        # Create metadata
        archived = ArchivedBlock(
            block_height=block_height,
            state_root=state_root,
            vertex_count=0,  # Could parse from data
            archived_at=int(time.time()),
            archive_path=str(path),
        )
        
        self.archived_blocks[block_height] = archived
        logger.debug(f"Archived block {block_height}")
        
        return archived
    
    def fetch_block(self, block_height: int) -> Optional[bytes]:
        """
        Fetch archived block data.
        
        Args:
            block_height: Block to fetch
            
        Returns:
            Block data, or None if not found
        """
        archived = self.archived_blocks.get(block_height)
        if not archived:
            return None
        
        path = Path(archived.archive_path)
        if not path.exists():
            return None
        
        return path.read_bytes()
    
    def verify_archive(self, block_height: int, expected_hash: bytes) -> bool:
        """
        Verify archived data integrity.
        
        Args:
            block_height: Block to verify
            expected_hash: Expected hash of data
            
        Returns:
            True if data matches hash
        """
        data = self.fetch_block(block_height)
        if data is None:
            return False
        
        return sha256(data) == expected_hash
    
    def stats(self) -> dict:
        """Get archive statistics."""
        total_bytes = 0
        for height, meta in self.archived_blocks.items():
            path = Path(meta.archive_path)
            if path.exists():
                total_bytes += path.stat().st_size
        
        return {
            "archived_blocks": len(self.archived_blocks),
            "total_bytes": total_bytes,
        }


class StorageManager:
    """
    Combined storage management.
    
    Coordinates pruning and archival.
    """
    
    def __init__(
        self,
        max_active_blocks: int = 1000,
        enable_archival: bool = True,
        data_dir: Optional[Path] = None,
    ):
        self.data_dir = data_dir or Path("data")
        
        self.pruning = PruningManager(max_blocks=max_active_blocks, data_dir=self.data_dir)
        self.archival = MockArchivalNode(self.data_dir / "archive") if enable_archival else None
    
    def process_new_block(
        self,
        block_height: int,
        state_root: bytes,
        block_data: bytes,
    ) -> StorageStats:
        """
        Process a new block for storage.
        
        Archives old blocks if needed, then prunes.
        
        Returns:
            Current storage statistics
        """
        # Check if pruning needed
        if self.pruning.should_prune(block_height):
            prune_below = self.pruning.get_prune_height(block_height)
            
            # Archive before pruning
            for height in range(prune_below):
                if height not in self.pruning.pruned_heights:
                    if self.archival:
                        # In real impl, would fetch block data here
                        self.archival.archive_block(height, state_root, b"mock_data")
            
            # Prune
            self.pruning.prune(block_height)
        
        return StorageStats(
            active_blocks=block_height - len(self.pruning.pruned_heights),
            pruned_blocks=len(self.pruning.pruned_heights),
            archived_blocks=len(self.archival.archived_blocks) if self.archival else 0,
            total_bytes=0,
        )
