"""
Ledger - UTXO state management for CFP.

Conceptual Background:
---------------------
The Ledger maintains the global state of the CFP chain:

1. **UTXO Set**: All unspent outputs (as a Merkle tree of commitments)
2. **Nullifier Set**: All nullifiers ever published (marks spent UTXOs)
3. **State Root**: Merkle root of the UTXO set

Transaction Processing:
----------------------
1. Validate transaction structure
2. Check balance: sum(inputs) = sum(outputs) + fee
3. Check nullifiers: none in nullifier set (no double-spend)
4. Apply: add nullifiers, create new UTXOs, update state root

Snapshot:
--------
We store state snapshots at each block height for:
- Verification of historical states
- Rollback if needed
- ZK proving against specific state roots
"""

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cfp.core.state.utxo import UTXO, address_from_public_key
from cfp.core.state.transaction import Transaction, TxOutput, create_mint
from cfp.core.state.merkle import MerkleTree
from cfp.utils.logger import get_logger
from cfp.crypto import sha256, bytes_to_hex

logger = get_logger("ledger")


# =============================================================================
# Ledger State
# =============================================================================


@dataclass
class LedgerSnapshot:
    """
    Snapshot of ledger state at a specific block height.
    
    Used for historical verification and rollback.
    """
    block_height: int
    state_root: bytes
    nullifier_count: int
    utxo_count: int


class Ledger:
    """
    UTXO-based ledger with nullifier set.
    
    Manages the global state of the CFP chain, processing transactions
    and maintaining state consistency.
    
    Attributes:
        utxo_set: Mapping of UTXO ID to UTXO objects
        utxo_tree: Merkle tree of UTXO commitments
        nullifier_set: Set of all published nullifiers
        block_height: Current block height
    """
    
    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialize the ledger.
        
        Args:
            data_dir: Directory for persistence. None = in-memory only.
        """
        # UTXO storage
        self.utxo_set: Dict[bytes, UTXO] = {}  # utxo_id -> UTXO
        self.utxo_tree = MerkleTree()
        
        # Nullifier tracking
        self.nullifier_set: Set[bytes] = set()
        
        # State tracking
        self.block_height = 0
        self.snapshots: List[LedgerSnapshot] = []
        
        # Persistence
        self.data_dir = data_dir
        self._db: Optional[sqlite3.Connection] = None
        
        if data_dir:
            self._init_persistence()
    
    # =========================================================================
    # State Access
    # =========================================================================
    
    @property
    def state_root(self) -> bytes:
        """Current Merkle root of UTXO set."""
        return self.utxo_tree.root()
    
    def get_utxo(self, utxo_id: bytes) -> Optional[UTXO]:
        """Get a UTXO by its ID."""
        return self.utxo_set.get(utxo_id)
    
    def get_utxo_by_ref(self, tx_hash: bytes, output_index: int) -> Optional[UTXO]:
        """Get a UTXO by transaction hash and output index."""
        utxo_id = tx_hash + output_index.to_bytes(1, byteorder="big")
        return self.get_utxo(utxo_id)
    
    def get_balance(self, address: bytes) -> int:
        """Get total balance for an address."""
        return sum(
            utxo.value
            for utxo in self.utxo_set.values()
            if utxo.owner == address
        )
    
    def get_utxos_for_address(self, address: bytes) -> List[UTXO]:
        """Get all UTXOs owned by an address."""
        return [
            utxo
            for utxo in self.utxo_set.values()
            if utxo.owner == address
        ]
    
    def is_spent(self, nullifier: bytes) -> bool:
        """Check if a nullifier has been used (UTXO spent)."""
        return nullifier in self.nullifier_set
    
    # =========================================================================
    # Transaction Validation
    # =========================================================================
    
    def validate_transaction(
        self,
        tx: Transaction,
        check_signatures: bool = True,
    ) -> Tuple[bool, str]:
        """
        Validate a transaction against current state.
        
        Checks:
        1. Structure validity
        2. All inputs exist (UTXOs are present)
        3. No double-spend (nullifiers not used)
        4. Balance: sum(inputs) = sum(outputs) + fee
        5. Signatures (if enabled)
        
        Args:
            tx: Transaction to validate
            check_signatures: Whether to verify signatures
            
        Returns:
            (is_valid, error_message)
        """
        # Structure check
        is_valid, error = tx.validate_structure()
        if not is_valid:
            return False, f"Structure: {error}"
        
        # Special case: mint transaction (no inputs)
        if len(tx.inputs) == 0:
            # SECURITY: Mint only allowed at genesis (block 0)
            if self.block_height > 0:
                return False, "Mint transactions only allowed at genesis"
            return True, ""
        
        # Check all inputs exist
        input_utxos = []
        for i, inp in enumerate(tx.inputs):
            utxo = self.get_utxo(inp.utxo_id)
            if utxo is None:
                return False, f"Input {i}: UTXO not found"
            input_utxos.append(utxo)
        
        # Check no double-spend
        for i, inp in enumerate(tx.inputs):
            if inp.nullifier in self.nullifier_set:
                return False, f"Input {i}: Double-spend (nullifier already used)"
        
        # Check balance
        input_sum = sum(utxo.value for utxo in input_utxos)
        output_sum = sum(out.value for out in tx.outputs)
        if input_sum != output_sum + tx.fee:
            return False, f"Balance mismatch: {input_sum} != {output_sum} + {tx.fee}"
        
        # Check signatures (each input must be signed by owner)
        if check_signatures:
            from cfp.crypto import recover_public_key, keccak256
            signing_hash = tx.compute_signing_hash()
            
            for i, (inp, utxo) in enumerate(zip(tx.inputs, input_utxos)):
                # Recover public key from signature and verify it matches owner
                owner_verified = False
                for recovery_id in (0, 1):
                    recovered_pub = recover_public_key(signing_hash, inp.signature, recovery_id)
                    if recovered_pub and keccak256(recovered_pub)[-20:] == utxo.owner:
                        owner_verified = True
                        break
                
                if not owner_verified:
                    return False, f"Input {i}: Invalid signature or owner mismatch"
        
        return True, ""
    
    # =========================================================================
    # Transaction Application
    # =========================================================================
    
    def apply_transaction(
        self,
        tx: Transaction,
        validate: bool = True,
    ) -> Tuple[bool, str]:
        """
        Apply a transaction to the ledger state.
        
        This:
        1. Validates the transaction (if enabled)
        2. Adds nullifiers to nullifier set
        3. Removes spent UTXOs from set (logically via nullifier)
        4. Creates new UTXOs from outputs
        5. Updates Merkle tree
        
        Args:
            tx: Transaction to apply
            validate: Whether to validate first
            
        Returns:
            (success, message)
        """
        if validate:
            is_valid, error = self.validate_transaction(tx, check_signatures=False)
            if not is_valid:
                return False, error
        
        # Ensure tx_hash is set
        if not tx.tx_hash:
            tx.finalize()
        
        # Add nullifiers
        for inp in tx.inputs:
            self.nullifier_set.add(inp.nullifier)
            # Remove from active UTXO set
            if inp.utxo_id in self.utxo_set:
                del self.utxo_set[inp.utxo_id]
        
        # Create new UTXOs
        for i, out in enumerate(tx.outputs):
            utxo = out.to_utxo(tx.tx_hash, i)
            self.utxo_set[utxo.utxo_id] = utxo
            
            # Add to Merkle tree
            commitment = utxo.compute_commitment()
            self.utxo_tree.insert(commitment)
        
        # Persist if enabled
        if self._db:
            self._persist_transaction(tx)
        
        logger.debug(f"Applied tx {bytes_to_hex(tx.tx_hash)[:10]}... ({len(tx.inputs)} in, {len(tx.outputs)} out)")
        return True, "Applied successfully"
    
    def apply_block(self, transactions: List[Transaction]) -> Tuple[bool, str]:
        """
        Apply a block of transactions and create snapshot.
        
        Args:
            transactions: Ordered list of transactions
            
        Returns:
            (success, message)
        """
        # Apply all transactions
        for i, tx in enumerate(transactions):
            success, error = self.apply_transaction(tx)
            if not success:
                return False, f"Transaction {i}: {error}"
        
        # Increment block height
        self.block_height += 1
        
        # Create snapshot
        snapshot = LedgerSnapshot(
            block_height=self.block_height,
            state_root=self.state_root,
            nullifier_count=len(self.nullifier_set),
            utxo_count=len(self.utxo_set),
        )
        self.snapshots.append(snapshot)
        
        logger.info(f"Applied block {self.block_height}: {len(transactions)} txs, root={bytes_to_hex(self.state_root)[:10]}...")
        return True, f"Block {self.block_height} applied"
    
    # =========================================================================
    # Genesis
    # =========================================================================
    
    def create_genesis(self, initial_allocations: List[Tuple[bytes, int]]) -> Transaction:
        """
        Create genesis state with initial token allocations.
        
        Args:
            initial_allocations: List of (address, value) tuples
            
        Returns:
            Genesis mint transaction
        """
        if self.block_height > 0:
            raise RuntimeError("Genesis already created")
        
        # Create mint transaction with all initial allocations
        outputs = [TxOutput(value=value, owner=address) for address, value in initial_allocations]
        tx = Transaction(inputs=[], outputs=outputs, fee=0)
        tx.finalize()
        
        # Apply it
        self.apply_transaction(tx, validate=False)
        self.block_height = 0
        
        logger.info(f"Genesis created: {len(initial_allocations)} allocations, {sum(v for _, v in initial_allocations)} total tokens")
        return tx
    
    # =========================================================================
    # Persistence
    # =========================================================================
    
    def _init_persistence(self) -> None:
        """Initialize SQLite database."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        db_path = self.data_dir / "ledger.db"
        self._db = sqlite3.connect(str(db_path))
        
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS utxos (
                utxo_id BLOB PRIMARY KEY,
                data BLOB NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS nullifiers (
                nullifier BLOB PRIMARY KEY
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash BLOB PRIMARY KEY,
                data BLOB NOT NULL,
                block_height INTEGER
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                block_height INTEGER PRIMARY KEY,
                state_root BLOB,
                nullifier_count INTEGER,
                utxo_count INTEGER
            )
        """)
        self._db.commit()
        
        self._load_from_db()
    
    def _persist_transaction(self, tx: Transaction) -> None:
        """Persist a transaction."""
        if not self._db:
            return
        
        self._db.execute(
            "INSERT OR REPLACE INTO transactions (tx_hash, data, block_height) VALUES (?, ?, ?)",
            (tx.tx_hash, tx.to_bytes(), self.block_height)
        )
        
        # Update UTXOs
        for inp in tx.inputs:
            self._db.execute("DELETE FROM utxos WHERE utxo_id = ?", (inp.utxo_id,))
            self._db.execute(
                "INSERT OR REPLACE INTO nullifiers (nullifier) VALUES (?)",
                (inp.nullifier,)
            )
        
        for i, out in enumerate(tx.outputs):
            utxo = out.to_utxo(tx.tx_hash, i)
            self._db.execute(
                "INSERT OR REPLACE INTO utxos (utxo_id, data) VALUES (?, ?)",
                (utxo.utxo_id, utxo.to_bytes())
            )
        
        self._db.commit()
    
    def _load_from_db(self) -> None:
        """Load state from database."""
        if not self._db:
            return
        
        # Load UTXOs
        for (utxo_id, data) in self._db.execute("SELECT utxo_id, data FROM utxos"):
            utxo = UTXO.from_bytes(data)
            self.utxo_set[utxo_id] = utxo
            self.utxo_tree.insert(utxo.compute_commitment())
        
        # Load nullifiers
        for (nullifier,) in self._db.execute("SELECT nullifier FROM nullifiers"):
            self.nullifier_set.add(nullifier)
        
        # Load snapshots
        for row in self._db.execute("SELECT block_height, state_root, nullifier_count, utxo_count FROM snapshots"):
            self.snapshots.append(LedgerSnapshot(*row))
        
        if self.snapshots:
            self.block_height = self.snapshots[-1].block_height
        
        logger.info(f"Loaded ledger: {len(self.utxo_set)} UTXOs, {len(self.nullifier_set)} nullifiers")
    
    def close(self) -> None:
        """Close database connection."""
        if self._db:
            self._db.close()
            self._db = None
    
    # =========================================================================
    # Utility
    # =========================================================================
    
    def __repr__(self) -> str:
        return f"Ledger(height={self.block_height}, utxos={len(self.utxo_set)}, nullifiers={len(self.nullifier_set)})"
    
    def stats(self) -> dict:
        """Get ledger statistics."""
        return {
            "block_height": self.block_height,
            "utxo_count": len(self.utxo_set),
            "nullifier_count": len(self.nullifier_set),
            "state_root": bytes_to_hex(self.state_root),
            "total_value": sum(u.value for u in self.utxo_set.values()),
        }
