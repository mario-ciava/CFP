"""
BlockProducer - Orchestrates block creation for CFP.

This module ties together all components needed for block production:
- Collects pending transactions
- Validates and orders them
- Applies to ledger atomically
- Distributes fees via FeeManager
- Creates block rewards

The BlockProducer is the coordinator that makes CFP a functioning blockchain.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
import time

from cfp.core.state.ledger import Ledger
from cfp.core.state.transaction import Transaction, TxOutput, create_mint
from cfp.core.tokenomics import FeeManager, TokenomicsConfig
from cfp.core.dag import DAGSequencer, Vertex, PayloadType
from cfp.crypto import sha256, bytes_to_hex
from cfp.utils.logger import get_logger

logger = get_logger("block_producer")


# =============================================================================
# Block Structure
# =============================================================================

@dataclass
class Block:
    """
    A block of transactions.
    
    In CFP's DAG model, a block is a Vertex containing multiple transactions.
    This provides a convenient wrapper for block creation and validation.
    """
    height: int
    prev_state_root: bytes
    state_root: bytes
    transactions: List[Transaction]
    timestamp: int = field(default_factory=lambda: int(time.time()))
    producer: bytes = b""  # Sequencer/producer address
    total_fees: int = 0
    block_hash: bytes = b""
    
    def compute_hash(self) -> bytes:
        """Compute block hash."""
        content = (
            self.height.to_bytes(8, "big") +
            self.prev_state_root +
            self.state_root +
            self.timestamp.to_bytes(8, "big") +
            self.producer +
            len(self.transactions).to_bytes(4, "big")
        )
        for tx in self.transactions:
            content += tx.tx_hash if tx.tx_hash else tx.compute_tx_hash()
        return sha256(content)
    
    def finalize(self) -> None:
        """Compute and set block hash."""
        self.block_hash = self.compute_hash()


# =============================================================================
# Mempool
# =============================================================================

class Mempool:
    """
    Pending transaction pool.
    
    Stores transactions waiting to be included in blocks.
    """
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.pending: Dict[bytes, Transaction] = {}  # tx_hash -> Transaction
        self._priority: Dict[bytes, int] = {}  # tx_hash -> priority (fee/size)
    
    def add(self, tx: Transaction) -> Tuple[bool, str]:
        """Add a transaction to the mempool."""
        if not tx.tx_hash:
            tx.finalize()
        
        if tx.tx_hash in self.pending:
            return False, "Transaction already in mempool"
        
        if len(self.pending) >= self.max_size:
            return False, "Mempool full"
        
        self.pending[tx.tx_hash] = tx
        # Priority based on fee per byte
        tx_size = len(tx.to_bytes())
        self._priority[tx.tx_hash] = tx.fee * 1000 // max(tx_size, 1)
        
        return True, ""
    
    def remove(self, tx_hash: bytes) -> None:
        """Remove a transaction from the mempool."""
        self.pending.pop(tx_hash, None)
        self._priority.pop(tx_hash, None)
    
    def get_prioritized(self, max_count: int) -> List[Transaction]:
        """Get transactions ordered by priority (highest fee/size first)."""
        sorted_hashes = sorted(
            self.pending.keys(),
            key=lambda h: self._priority.get(h, 0),
            reverse=True
        )
        return [self.pending[h] for h in sorted_hashes[:max_count]]
    
    def clear(self) -> None:
        """Clear all pending transactions."""
        self.pending.clear()
        self._priority.clear()
    
    def __len__(self) -> int:
        return len(self.pending)


# =============================================================================
# Block Producer
# =============================================================================

class BlockProducer:
    """
    Orchestrates block production.
    
    Responsibilities:
    - Collect transactions from mempool
    - Validate and order transactions
    - Create block with fees and rewards
    - Apply block to ledger atomically
    - Emit block for network propagation
    """
    
    # Maximum transactions per block
    MAX_TRANSACTIONS_PER_BLOCK = 100
    
    def __init__(
        self,
        ledger: Ledger,
        fee_manager: Optional[FeeManager] = None,
        dag: Optional[DAGSequencer] = None,
        config: Optional[TokenomicsConfig] = None,
    ):
        """
        Initialize block producer.
        
        Args:
            ledger: UTXO ledger for state management
            fee_manager: Fee distribution manager
            dag: DAG sequencer for vertex creation
            config: Tokenomics configuration
        """
        self.ledger = ledger
        self.fee_manager = fee_manager or FeeManager()
        self.dag = dag
        self.config = config or TokenomicsConfig()
        
        # Connect fee manager to ledger if not already connected
        if self.ledger.fee_manager is None:
            self.ledger.fee_manager = self.fee_manager
        
        # Mempool for pending transactions
        self.mempool = Mempool()
        
        # Block production stats
        self.blocks_produced = 0
        self.total_tx_processed = 0
        self.total_fees_collected = 0
        
        logger.info("BlockProducer initialized")
    
    def submit_transaction(self, tx: Transaction) -> Tuple[bool, str]:
        """
        Submit a transaction for inclusion in a future block.
        
        Validates the transaction and adds to mempool if valid.
        
        Args:
            tx: Transaction to submit
            
        Returns:
            (success, error_message)
        """
        # Pre-validate against current state
        is_valid, error = self.ledger.validate_transaction(tx)
        if not is_valid:
            return False, f"Validation failed: {error}"
        
        # Add to mempool
        return self.mempool.add(tx)
    
    def produce_block(
        self,
        sequencer_address: bytes,
        max_transactions: Optional[int] = None,
    ) -> Tuple[Optional[Block], str]:
        """
        Create a new block from pending transactions.
        
        Args:
            sequencer_address: Address of block producer (receives fees)
            max_transactions: Maximum transactions to include
            
        Returns:
            (Block, error_message) - Block is None on failure
        """
        max_tx = max_transactions or self.MAX_TRANSACTIONS_PER_BLOCK
        
        # Get prioritized transactions
        candidates = self.mempool.get_prioritized(max_tx * 2)  # Get extra for validation failures
        
        if not candidates:
            return None, "No pending transactions"
        
        # Capture state before block
        prev_state_root = self.ledger.state_root
        prev_height = self.ledger.block_height
        
        # Select valid transactions
        valid_txs: List[Transaction] = []
        total_fees = 0
        
        for tx in candidates:
            if len(valid_txs) >= max_tx:
                break
            
            # Re-validate against current state (may have changed)
            is_valid, _ = self.ledger.validate_transaction(tx)
            if is_valid:
                valid_txs.append(tx)
                total_fees += tx.fee
        
        if not valid_txs:
            return None, "No valid transactions after validation"
        
        # Apply transactions to ledger
        success, msg = self.ledger.apply_block(valid_txs)
        if not success:
            return None, f"Block application failed: {msg}"
        
        # Remove included transactions from mempool
        for tx in valid_txs:
            self.mempool.remove(tx.tx_hash)
        
        # Create block
        block = Block(
            height=self.ledger.block_height,
            prev_state_root=prev_state_root,
            state_root=self.ledger.state_root,
            transactions=valid_txs,
            producer=sequencer_address,
            total_fees=total_fees,
        )
        block.finalize()
        
        # Update stats
        self.blocks_produced += 1
        self.total_tx_processed += len(valid_txs)
        self.total_fees_collected += total_fees
        
        # Create DAG vertex if dag is connected
        if self.dag:
            vertex = self._create_block_vertex(block)
            self.dag.add_vertex(vertex)
        
        logger.info(
            f"Produced block {block.height}: {len(valid_txs)} txs, "
            f"fees={total_fees}, hash={bytes_to_hex(block.block_hash)[:10]}..."
        )
        
        return block, ""
    
    def _create_block_vertex(self, block: Block) -> Vertex:
        """Create a DAG vertex from a block."""
        # Use current tips as parents
        parents = self.dag.get_tips() if self.dag else []
        
        # Serialize block for vertex payload
        payload = block.block_hash + block.state_root
        
        vertex = Vertex(
            payload_type=PayloadType.BLOCK,
            payload=payload,
            parents=parents,
            timestamp=block.timestamp,
        )
        return vertex
    
    def apply_external_block(self, block: Block) -> Tuple[bool, str]:
        """
        Apply a block received from the network.
        
        Validates and applies the block to the ledger.
        
        Args:
            block: Block to apply
            
        Returns:
            (success, error_message)
        """
        # Verify block height
        expected_height = self.ledger.block_height + 1
        if block.height != expected_height:
            return False, f"Wrong block height: expected {expected_height}, got {block.height}"
        
        # Verify previous state root
        if block.prev_state_root != self.ledger.state_root:
            return False, "Previous state root mismatch"
        
        # Apply transactions
        success, msg = self.ledger.apply_block(block.transactions)
        if not success:
            return False, msg
        
        # Verify resulting state root
        if block.state_root != self.ledger.state_root:
            return False, "State root mismatch after application"
        
        # Remove included transactions from our mempool
        for tx in block.transactions:
            self.mempool.remove(tx.tx_hash)
        
        return True, ""
    
    def stats(self) -> dict:
        """Get block producer statistics."""
        return {
            "blocks_produced": self.blocks_produced,
            "total_tx_processed": self.total_tx_processed,
            "total_fees_collected": self.total_fees_collected,
            "mempool_size": len(self.mempool),
            "ledger_height": self.ledger.block_height,
            "fee_stats": self.fee_manager.stats(),
        }


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "BlockProducer",
    "Block",
    "Mempool",
]
