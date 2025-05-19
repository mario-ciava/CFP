import pytest
import shutil
from pathlib import Path

from cfp.core.storage.storage_manager import StorageManager
from cfp.core.dag import DAGSequencer, create_genesis_vertex, create_vertex, PayloadType
from cfp.crypto import generate_keypair

@pytest.fixture
def temp_node_dir(tmp_path):
    """Create a temporary directory for node data."""
    data_dir = tmp_path / "node_data"
    data_dir.mkdir()
    return data_dir

def test_dag_persistence(temp_node_dir):
    """Test that DAG state is preserved across restarts."""
    # 1. Start Node A
    storage_a = StorageManager(data_dir=temp_node_dir)
    dag_a = DAGSequencer(storage_manager=storage_a)
    
    kp = generate_keypair()
    
    # Create Genesis
    genesis = create_genesis_vertex(kp)
    dag_a.add_vertex(genesis)
    
    # Create some vertices
    v1 = create_vertex([genesis.vertex_id], b"tx1", PayloadType.TRANSACTION, kp)
    dag_a.add_vertex(v1)
    
    v2 = create_vertex([v1.vertex_id], b"tx2", PayloadType.TRANSACTION, kp)
    dag_a.add_vertex(v2)
    
    # Verify state in Node A
    assert dag_a.vertex_count() == 3
    assert dag_a.get_tips() == [v2.vertex_id]
    
    # 2. Stop Node A (Close DB)
    # DAGSequencer doesn't have close(), but StorageManager might?
    # SQLiteAdapter uses threading.local, logic is robust to GC?
    # We'll just drop references.
    del dag_a
    del storage_a
    
    # 3. Start Node B (Same DB)
    storage_b = StorageManager(data_dir=temp_node_dir)
    dag_b = DAGSequencer(storage_manager=storage_b)
    
    # Verify State loaded
    assert dag_b.vertex_count() == 3
    assert dag_b.get_vertex(genesis.vertex_id) == genesis
    assert dag_b.get_vertex(v1.vertex_id) == v1
    assert dag_b.get_vertex(v2.vertex_id) == v2
    
    # Check edges/topology
    assert dag_b.get_children(genesis.vertex_id) == [v1.vertex_id]
    assert dag_b.get_tips() == [v2.vertex_id]
    
    # 4. Continue chain
    v3 = create_vertex([v2.vertex_id], b"tx3", PayloadType.TRANSACTION, kp)
    dag_b.add_vertex(v3)
    
    assert dag_b.vertex_count() == 4
    
    # 5. Check metadata persistence (StorageManager direct check)
    storage_b.save_tip(v3.vertex_id.hex(), 3)
    
    del dag_b
    del storage_b
    
    storage_c = StorageManager(data_dir=temp_node_dir)
    tip_hash, height = storage_c.get_tip()
    assert tip_hash == v3.vertex_id.hex()
    assert height == 3

def test_zk_state_persistence(temp_node_dir):
    """Test persisting ZK commitments and nullifiers."""
    storage = StorageManager(data_dir=temp_node_dir)
    
    # Save generic commitment
    comm = b"commitment_1" * 3  # 36 bytes?
    comm = comm[:32]
    tx_hash = b"tx_hash" * 4
    tx_hash = tx_hash[:32]
    
    storage.persist_commitment(0, comm, tx_hash)
    
    # check
    assert storage.get_commitment(0) == comm
    assert storage.get_commitment_count() == 1
    
    # Save nullifier
    nullifier = b"nullifier" * 3
    nullifier = nullifier[:32]
    
    assert not storage.is_nullifier_spent(nullifier)
    storage.persist_nullifier(nullifier, tx_hash)
    assert storage.is_nullifier_spent(nullifier)
    
    # Restart
    del storage
    storage_new = StorageManager(data_dir=temp_node_dir)
    
    assert storage_new.is_nullifier_spent(nullifier)
    assert storage_new.get_commitment(0) == comm

def test_ledger_persistence(temp_node_dir):
    """Test full Ledger state persistence."""
    from cfp.core.state.ledger import Ledger
    from cfp.core.state import create_mint, address_from_public_key
    from cfp.crypto import generate_keypair
    
    storage = StorageManager(data_dir=temp_node_dir)
    ledger = Ledger(storage_manager=storage)
    
    kp = generate_keypair()
    addr = address_from_public_key(kp.public_key)
    
    # Create Genesis (Mint)
    # This creates transactions and UTXOs in DB
    ledger.create_genesis([(addr, 1000)])
    
    assert ledger.block_height == 0
    assert len(ledger.utxo_set) == 1
    genesis_balance = ledger.get_balance(addr)
    assert genesis_balance == 1000
    
    # Force snapshot persistence (Ledger does this on apply_block, but genesis calls apply_transaction)
    # create_genesis calls apply_transaction(validate=False) but doesn't create snapshots/block explicitly?
    # Ledger.create_genesis sets block_height=0.
    # It doesn't call apply_block. So no snapshot is saved for genesis by default?
    # Let's check Ledger.create_genesis impl.
    # It just applies tx.
    # Let's verify if `apply_transaction` saves tx/utxos. Yes.
    
    # Close and Reopen
    del ledger
    del storage
    
    storage_b = StorageManager(data_dir=temp_node_dir)
    ledger_b = Ledger(storage_manager=storage_b)
    
    # Verify State
    # block_height logic in `_load_from_storage` depends on snapshots.
    # Since genesis didn't create a snapshot, block_height might be 0 (default).
    # But UTXOs should be loaded.
    
    assert len(ledger_b.utxo_set) == 1
    assert ledger_b.get_balance(addr) == 1000
    
    # Check transaction persistence
    # Ledger doesn't expose get_transaction API directly?
    # SQLiteAdapter has `transactions` table but `Ledger` class mainly loads UTXOs.
    # We can check storage directly.
    # Wait, Ledger doesn't load transactions into memory. It only loads UTXOs and Nullifiers.
    # Transactions are archival.
    # So `ledger_b.utxo_set` is the proof.
    
    assert ledger_b.nullifier_set == set() # Genesis mint has no inputs -> no nullifiers
    
