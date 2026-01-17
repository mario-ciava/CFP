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

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from cfp.core.dag import DAGSequencer, PayloadType, Vertex
from cfp.core.dag.vertex import MAX_PARENTS
from cfp.core.escape_hatch import EscapeHatchValidator
from cfp.core.state.ledger import Ledger
from cfp.core.state.transaction import Transaction
from cfp.core.tokenomics import FeeManager, TokenomicsConfig
from cfp.crypto import KeyPair, bytes_to_hex, sha256
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

class TxClass(str, Enum):
    """
    Transaction class for escape-hatch accounting.

    RAW    - ordinary user transactions (guaranteed a minimum block quota).
    INTENT - transactions produced by / on behalf of the intent auction.
    """
    RAW = "raw"
    INTENT = "intent"


class Mempool:
    """
    Pending transaction pool.

    Stores transactions waiting to be included in blocks, along with their
    escape-hatch class (raw vs intent) and fee-per-byte priority.
    """

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.pending: Dict[bytes, Transaction] = {}  # tx_hash -> Transaction
        self._priority: Dict[bytes, int] = {}  # tx_hash -> priority (fee/byte)
        self._tx_class: Dict[bytes, TxClass] = {}  # tx_hash -> class

    def add(self, tx: Transaction, tx_class: TxClass = TxClass.RAW) -> Tuple[bool, str]:
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
        self._tx_class[tx.tx_hash] = tx_class

        return True, ""

    def remove(self, tx_hash: bytes) -> None:
        """Remove a transaction from the mempool."""
        self.pending.pop(tx_hash, None)
        self._priority.pop(tx_hash, None)
        self._tx_class.pop(tx_hash, None)

    def get_prioritized(self, max_count: int) -> List[Transaction]:
        """Get transactions ordered by priority (highest fee/byte first)."""
        sorted_hashes = sorted(
            self.pending.keys(),
            key=lambda h: self._priority.get(h, 0),
            reverse=True
        )
        return [self.pending[h] for h in sorted_hashes[:max_count]]

    def get_prioritized_split(self) -> Tuple[
        List[Tuple[Transaction, int]], List[Tuple[Transaction, int]]
    ]:
        """
        Return ``(raw, intent)`` lists of ``(tx, priority)`` pairs for the escape
        hatch, each ordered by fee-per-byte (highest first).
        """
        raw: List[Tuple[Transaction, int]] = []
        intent: List[Tuple[Transaction, int]] = []
        for h, tx in self.pending.items():
            pair = (tx, self._priority.get(h, 0))
            if self._tx_class.get(h, TxClass.RAW) == TxClass.INTENT:
                intent.append(pair)
            else:
                raw.append(pair)
        raw.sort(key=lambda x: x[1], reverse=True)
        intent.sort(key=lambda x: x[1], reverse=True)
        return raw, intent

    def clear(self) -> None:
        """Clear all pending transactions."""
        self.pending.clear()
        self._priority.clear()
        self._tx_class.clear()

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
        producer_key: Optional[KeyPair] = None,
        escape_hatch: Optional[EscapeHatchValidator] = None,
    ):
        """
        Initialize block producer.

        Args:
            ledger: UTXO ledger for state management
            fee_manager: Fee distribution manager
            dag: DAG sequencer for vertex creation
            config: Tokenomics configuration
            producer_key: Keypair used to sign block vertices. Required when
                ``dag`` is provided (DAG vertices must carry a valid creator and
                signature); ignored otherwise.
            escape_hatch: Enforces the raw-transaction quota during block
                assembly (defaults to a 10% quota).
        """
        if dag is not None and producer_key is None:
            raise ValueError("producer_key is required when a dag is provided (block vertices must be signed)")

        self.ledger = ledger
        self.fee_manager = fee_manager or FeeManager()
        self.dag = dag
        self.producer_key = producer_key
        self.config = config or TokenomicsConfig()
        self.escape_hatch = escape_hatch or EscapeHatchValidator()

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

    def submit_transaction(
        self,
        tx: Transaction,
        tx_class: TxClass = TxClass.RAW,
    ) -> Tuple[bool, str]:
        """
        Submit a transaction for inclusion in a future block.

        Validates the transaction and adds to mempool if valid.

        Args:
            tx: Transaction to submit
            tx_class: RAW (ordinary user tx, protected by the escape-hatch quota)
                or INTENT (auction-derived).

        Returns:
            (success, error_message)
        """
        # Pre-validate against current state
        is_valid, error = self.ledger.validate_transaction(tx)
        if not is_valid:
            return False, f"Validation failed: {error}"

        # Add to mempool
        return self.mempool.add(tx, tx_class)

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

        # Escape hatch: reserve a minimum share of the block for raw (user) txs
        # so intent-derived txs cannot crowd them out. Beyond the reserved quota,
        # slots are filled by global fee-per-byte priority.
        raw, intent = self.mempool.get_prioritized_split()
        candidates = self.escape_hatch.select_transactions(raw, intent, max_tx)

        if not candidates:
            return None, "No pending transactions"

        # Capture state before block
        prev_state_root = self.ledger.state_root

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
            ok, vmsg = self.dag.add_vertex(vertex)
            if not ok:
                logger.error(f"Block {block.height} vertex rejected by DAG: {vmsg}")
                return None, f"DAG vertex rejected: {vmsg}"

        logger.info(
            f"Produced block {block.height}: {len(valid_txs)} txs, "
            f"fees={total_fees}, hash={bytes_to_hex(block.block_hash)[:10]}..."
        )

        return block, ""

    def _create_block_vertex(self, block: Block) -> Vertex:
        """
        Create a signed DAG vertex carrying a produced block.

        The vertex references current tips as parents (capped at MAX_PARENTS),
        carries the block hash + state root as payload, and is signed by the
        producer key so it passes the DAG's mandatory signature check.
        """
        # Only reached when a DAG is attached, which the constructor guarantees
        # implies a producer_key.
        assert self.dag is not None and self.producer_key is not None

        # Current tips as parents, bounded to the DAG's MAX_PARENTS.
        tips = self.dag.get_tips()
        parents = tips[:MAX_PARENTS]

        # Timestamp must be >= max(parent timestamps) for a non-genesis vertex.
        timestamp = block.timestamp
        parent_vertices = [self.dag.get_vertex(p) for p in parents]
        parent_ts = [v.timestamp for v in parent_vertices if v is not None]
        if parent_ts:
            timestamp = max(timestamp, max(parent_ts))

        payload = block.block_hash + block.state_root

        vertex = Vertex(
            payload_type=PayloadType.BLOCK,
            payload=payload,
            parents=parents,
            timestamp=timestamp,
            creator=self.producer_key.public_key,
        )
        vertex.sign(self.producer_key.private_key)
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
    "TxClass",
]
