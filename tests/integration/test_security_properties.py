"""
Security-property tests for the core protocol.

Covers: unsigned/tampered DAG vertices are rejected; deep orphan chains are
processed without unbounded recursion; ledger state survives persist/reload;
block production inserts a signed block vertex; the escape-hatch quota reserves
raw-tx slots; and DAG sync rebuilds an identical graph across the wire.
"""

import inspect
import logging
import sys
import tempfile
from pathlib import Path

import pytest

from cfp.core.block_producer import BlockProducer, TxClass
from cfp.core.dag import DAGSequencer, PayloadType, Vertex
from cfp.core.escape_hatch import EscapeHatchValidator
from cfp.core.state.ledger import Ledger
from cfp.core.state.transaction import create_transfer
from cfp.core.state.utxo import address_from_public_key
from cfp.core.storage.storage_manager import StorageManager
from cfp.crypto import generate_keypair
from cfp.network.sync import SyncManager, create_sync_response, parse_sync_response


@pytest.fixture
def kp():
    return generate_keypair()


def _signed(kp, parents, ts, tag, ptype=None):
    if ptype is None:
        ptype = PayloadType.TRANSACTION if parents else PayloadType.METADATA
    v = Vertex(timestamp=ts, parents=parents, payload=tag, payload_type=ptype, creator=kp.public_key)
    v.sign(kp.private_key)
    return v


class TestDAGVertexAuth:
    def test_unsigned_vertex_rejected(self, kp):
        dag = DAGSequencer()
        g = _signed(kp, [], 1000, b"g")
        assert dag.add_vertex(g)[0]

        # Build a well-formed child but do NOT sign it (empty signature).
        unsigned = Vertex(timestamp=1001, parents=[g.vertex_id], payload=b"x",
                          payload_type=PayloadType.TRANSACTION, creator=kp.public_key)
        ok, msg = dag.add_vertex(unsigned)
        assert not ok
        assert dag.vertex_count() == 1

    def test_tampered_signature_rejected(self, kp):
        dag = DAGSequencer()
        g = _signed(kp, [], 1000, b"g")
        dag.add_vertex(g)
        child = _signed(kp, [g.vertex_id], 1001, b"c")
        # Flip the signature bytes.
        child.signature = bytes((b ^ 0xFF) for b in child.signature)
        ok, _ = dag.add_vertex(child)
        assert not ok


class TestOrphanCascade:
    def test_deep_reverse_chain_no_recursion(self, kp):
        """
        A long chain fed in reverse (each vertex orphaned until its parent
        arrives) must insert iteratively. We cap the recursion limit just above
        current usage: an iterative implementation uses O(1) extra depth, a
        recursive one would blow past it.
        """
        dag = DAGSequencer()
        g = _signed(kp, [], 1000, b"g")
        dag.add_vertex(g)

        # 400 is well above the recursion headroom we set below (a recursive
        # implementation needs ~2N frames and would blow up), while keeping the
        # number of ECDSA signatures - the real cost here - manageable.
        N = 400
        chain = []
        prev = g.vertex_id
        for i in range(N):
            v = _signed(kp, [prev], 1000 + i + 1, bytes([i % 256]))
            chain.append(v)
            prev = v.vertex_id

        # Buffer all but the first as orphans (reverse order).
        for v in reversed(chain[1:]):
            dag.add_vertex(v)
        assert dag.orphan_count() == N - 1

        # Silence the per-insert INFO logging (dominates runtime at this scale).
        dag_logger = logging.getLogger("cfp.dag")
        prev_level = dag_logger.level
        dag_logger.setLevel(logging.ERROR)
        limit_before = sys.getrecursionlimit()
        sys.setrecursionlimit(len(inspect.stack()) + 400)
        try:
            ok, _ = dag.add_vertex(chain[0])  # unblocks the whole cascade
        finally:
            sys.setrecursionlimit(limit_before)
            dag_logger.setLevel(prev_level)

        assert ok
        assert dag.vertex_count() == N + 1
        assert dag.orphan_count() == 0


class TestLedgerPersistence:
    def test_persist_and_reload(self, kp):
        """Genesis + transfer persisted to SQLite and reloaded (nullifier schema)."""
        kp_b = generate_keypair()
        A = address_from_public_key(kp.public_key)
        B = address_from_public_key(kp_b.public_key)

        with tempfile.TemporaryDirectory() as d:
            sm = StorageManager(Path(d))
            led = Ledger(storage_manager=sm)
            led.create_genesis([(A, 100_000)])
            utxo = led.get_utxos_for_address(A)[0]
            tx = create_transfer(inputs=[(utxo, kp.private_key)],
                                 recipients=[(B, 40_000), (A, 59_000)], fee=1000)
            ok, msg = led.apply_transaction(tx)
            assert ok, msg

            # Fresh ledger from the same DB -> state recovered.
            led2 = Ledger(storage_manager=StorageManager(Path(d)))
            assert led2.get_balance(A) == 59_000
            assert led2.get_balance(B) == 40_000
            assert led2.genesis_done is True


class TestBlockProducerDAG:
    def test_produce_block_inserts_signed_block_vertex(self, kp):
        kp_b, kp_p = generate_keypair(), generate_keypair()
        A = address_from_public_key(kp.public_key)
        B = address_from_public_key(kp_b.public_key)

        led = Ledger()
        led.create_genesis([(A, 100_000)])
        dag = DAGSequencer()
        bp = BlockProducer(led, dag=dag, producer_key=kp_p)

        utxo = led.get_utxos_for_address(A)[0]
        tx = create_transfer(inputs=[(utxo, kp.private_key)],
                             recipients=[(B, 30_000), (A, 69_000)], fee=1000)
        assert bp.submit_transaction(tx)[0]

        block, err = bp.produce_block(sequencer_address=A)
        assert block is not None, err
        assert dag.vertex_count() == 1
        v = dag.get_vertex(dag.get_tips()[0])
        assert v.payload_type == PayloadType.BLOCK
        assert v.verify_signature()

    def test_dag_requires_producer_key(self):
        led = Ledger()
        with pytest.raises(ValueError):
            BlockProducer(led, dag=DAGSequencer())  # no producer_key


class TestEscapeHatchEnforcement:
    def test_raw_tx_reserved_in_block(self, kp):
        """A low-fee raw tx is included despite higher-fee intents (10% quota)."""
        kp_b = generate_keypair()
        A = address_from_public_key(kp.public_key)
        B = address_from_public_key(kp_b.public_key)

        led = Ledger()
        led.create_genesis([(A, 10_000)] * 5)  # 5 independent UTXOs
        utxos = led.get_utxos_for_address(A)
        bp = BlockProducer(led, escape_hatch=EscapeHatchValidator(min_quota=0.10))

        raw_tx = create_transfer(inputs=[(utxos[0], kp.private_key)],
                                 recipients=[(B, 9_900), (A, 90)], fee=10)  # low fee
        bp.submit_transaction(raw_tx, TxClass.RAW)
        for i in range(1, 5):
            t = create_transfer(inputs=[(utxos[i], kp.private_key)],
                                recipients=[(B, 5_000), (A, 3_000)], fee=2000)  # high fee
            bp.submit_transaction(t, TxClass.INTENT)

        block, err = bp.produce_block(sequencer_address=A, max_transactions=4)
        assert block is not None, err
        assert raw_tx.tx_hash in {tx.tx_hash for tx in block.transactions}


class TestSyncRoundTrip:
    def test_sync_rebuilds_identical_dag(self, kp):
        src = DAGSequencer()
        g = _signed(kp, [], 1000, b"g")
        a = _signed(kp, [g.vertex_id], 1001, b"a")
        b = _signed(kp, [g.vertex_id], 1002, b"b")
        c = _signed(kp, [a.vertex_id, b.vertex_id], 1003, b"c")
        for v in (g, a, b, c):
            src.add_vertex(v)

        serialized = SyncManager(dag=src)._get_vertices_after(bytes(32))
        msg = create_sync_response(bytes(32), serialized, has_more=False, state_root=bytes(32))
        vertices, _, _ = parse_sync_response(msg.payload)

        tgt = DAGSequencer()
        for vb in vertices:
            v = Vertex.from_bytes(vb)
            if not tgt.has_vertex(v.vertex_id):
                assert tgt.add_vertex(v)[0]

        assert tgt.vertex_count() == src.vertex_count()
        assert src.linearize() == tgt.linearize()
