# CFP Technical Reference

Technical documentation explaining the architecture and implementation of each protocol component.

## Table of Contents

1. [DAG Sequencing Engine](#1-dag-sequencing-engine)
2. [UTXO Ledger Model](#2-utxo-ledger-with-nullifier-set)
3. [ZK Prover Architecture](#3-zk-prover--verifier)
4. [Intent Layer & Auctions](#4-intent-layer--execution-tickets)
5. [Persistence Architecture](#5-persistence-architecture)
6. [Zero-Knowledge Setup](#6-zero-knowledge-setup)

---

## 1. DAG Sequencing Engine

### Why DAG-based Sequencing?

#### Traditional Blockchain Limitations
In a traditional blockchain (Bitcoin, Ethereum), blocks form a **linear chain**:
```
Block 1 → Block 2 → Block 3 → ...
```

**Problems:**
1. **Serial bottleneck**: Only one block at a time can be produced
2. **Fork resolution overhead**: Competing blocks require consensus rounds
3. **Artificial scarcity**: Block space is limited, causing fee spikes
4. **Latency**: Must wait for block finalization

#### DAG Advantage
A Directed Acyclic Graph allows **partial ordering**:
```
        ┌─→ V2 ─┐
    V1 ─┤       ├─→ V4
        └─→ V3 ─┘
```

**Benefits:**
1. **Parallelism**: Multiple vertices can be added simultaneously
2. **Causal ordering**: Only conflicting transactions need ordering
3. **Immediate liveness**: Vertices are valid as soon as they reference existing parents
4. **Higher throughput**: No artificial block interval constraint

---

### Core Concepts

#### 1. Vertex (Node in DAG)
A vertex is the atomic unit of the DAG, analogous to a "block" but lighter:

```
Vertex {
    vertex_id: Hash           # Unique identifier (hash of content)
    timestamp: u64            # Unix timestamp (for tie-breaking)
    parents: [Hash, ...]      # References to 1+ parent vertices
    payload: Bytes            # Transaction data, intents, or metadata
    payload_type: Enum        # TX, INTENT, METADATA, CHECKPOINT
    creator: PublicKey        # Who created this vertex
    signature: Bytes          # Signature over vertex content
}
```

**Design decisions:**
- `vertex_id` is computed as `hash(timestamp || parents || payload || creator)` — deterministic, content-addressed
- Multiple parents allow vertices to "merge" parallel branches
- `payload_type` enables heterogeneous content (raw TX, intents, prover checkpoints)

#### 2. Causal Ordering
The DAG represents **causal relationships**:
- If vertex A is a parent of vertex B, then A **happened-before** B
- If A and B have no path between them, they are **concurrent** (unordered)

This maps naturally to transaction dependencies:
- If TX₂ spends an output created by TX₁, then TX₂ must reference TX₁ (directly or transitively)
- Independent transactions can be concurrent

#### 3. Tips (Frontier)
**Tips** are vertices with no children yet — the "frontier" of the DAG:

```
Tips = { v ∈ DAG | no vertex w exists where v ∈ parents(w) }
```

New vertices should reference recent tips to:
1. Help finalize older vertices (adding confirmations)
2. Keep the DAG "wide" (parallelism) but not too sparse

#### 4. Deterministic Linearization
For state execution, we need a **total order** from partial order:

**Algorithm: Kahn's Algorithm with Deterministic Tie-Breaking**
```python
def linearize(dag):
    # Topological sort using in-degree tracking
    order = []
    ready = [v for v in dag if in_degree(v) == 0]  # Genesis vertices
    
    while ready:
        # Tie-break: lowest vertex_id (lexicographic hash comparison)
        ready.sort(key=lambda v: v.vertex_id)
        v = ready.pop(0)
        order.append(v)
        
        for child in children(v):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                ready.append(child)
    
    return order
```

**Critical property**: All nodes, given the same DAG, produce the **same linear order**.

---

### Validation Rules

#### Structural Validity
1. **No cycles**: Adding vertex V must not create a cycle (V cannot be ancestor of its own parents)
2. **Parent existence**: All referenced parents must exist in the DAG
3. **No duplicates**: vertex_id must be unique

#### Temporal Validity
4. **Timestamp sanity**: `timestamp ≤ now + MAX_FUTURE_DELTA` (e.g., 5 seconds)
5. **Timestamp ordering**: `timestamp ≥ max(parent.timestamp for parent in parents)` — a vertex cannot claim to be before its parents

#### Cryptographic Validity
6. **Valid signature**: Signature must verify against creator's public key
7. **Correct hash**: vertex_id must match computed hash

---

### Implementation Strategy

#### Data Structures
```python
# Use networkx.DiGraph as the underlying graph structure
# - Nodes: vertex_id → Vertex object
# - Edges: parent → child (direction of time flow)

dag = nx.DiGraph()
vertices = {}  # vertex_id → Vertex
tips = set()   # Current tip vertex IDs
```

#### Key Operations

| Operation | Complexity | Notes |
|-----------|------------|-------|
| `add_vertex(v)` | O(k) | k = number of parents |
| `get_tips()` | O(1) | Maintained incrementally |
| `linearize()` | O(V + E) | Kahn's algorithm |
| `is_ancestor(a, b)` | O(V) | DFS/BFS (can optimize with caching) |
| `validate(v)` | O(k) | Check parents exist, no cycle |

#### Persistence
- **In-memory**: networkx DiGraph for active operations
- **Disk**: SQLite for persistence (vertices table, edges table)
- **Checkpointing**: Periodic snapshots for faster recovery

---

## 2. UTXO Ledger with Nullifier Set

### Why UTXO Instead of Account Model?

#### Account Model (Ethereum-style)
```
State: mapping(address => balance)
Transaction: "Alice sends 10 to Bob"
Result: balance[Alice] -= 10; balance[Bob] += 10
```

**Problems for DAG:**
1. **State contention**: Parallel transactions to/from same account conflict
2. **Ordering dependency**: Must know final balance to validate next transaction
3. **Shared state lock**: Global state access required for any operation

#### UTXO Model (Bitcoin-style)
```
State: set of unspent outputs (UTXOs)
Transaction: consumes inputs (UTXOs) → creates outputs (new UTXOs)
Result: inputs removed, outputs added
```

**Benefits for DAG:**
1. **Isolation**: Each UTXO is independent - no shared state
2. **Parallelism**: Non-conflicting spends can process in parallel
3. **Natural conflict detection**: Double-spend = same input referenced twice
4. **ZK-friendly**: Local state proofs, no global state needed

---

### Core Concepts

#### 1. UTXO (Unspent Transaction Output)
A UTXO represents a "coin" that can be spent exactly once:

```
UTXO {
    tx_hash: bytes32      # Transaction that created this UTXO
    output_index: u8      # Index within transaction outputs
    value: u64            # Amount of tokens
    owner: bytes32        # Public key hash or script hash
    salt: bytes32         # Randomness for commitment (privacy)
}
```

**Commitment** (for Merkle tree): `hash(value || owner || salt)`

This allows the state to be represented as a Merkle tree of commitments,
without revealing the actual values in the tree structure.

#### 2. Nullifier
A **nullifier** is a unique identifier that marks a UTXO as spent:

```
nullifier = hash(tx_hash || output_index || owner_secret)
```

**Why nullifiers instead of just removing from set?**
- **ZK compatibility**: In ZK circuits, we prove "I know a UTXO in the tree and its nullifier is fresh"
- **Privacy**: Nullifier reveals nothing about which UTXO was spent
- **Efficiency**: O(1) double-spend check vs O(log n) Merkle proof

#### 3. Transaction
A transaction consumes inputs and creates outputs:

```
Transaction {
    inputs: [InputRef, ...]     # References to UTXOs being spent
    outputs: [UTXO, ...]        # New UTXOs being created
    fee: u64                    # Fee paid to sequencer
    signature: bytes            # Sign over (inputs || outputs || fee)
}

InputRef {
    tx_hash: bytes32
    output_index: u8
    nullifier: bytes32          # Proves this UTXO is being spent
}
```

#### 4. State Model
The ledger state consists of:

```
LedgerState {
    utxo_set: MerkleTree<Commitment>    # Current unspent outputs
    nullifier_set: Set<bytes32>          # All nullifiers ever used
    state_root: bytes32                  # Merkle root of utxo_set
}
```

**Key invariants:**
- `sum(inputs.value) = sum(outputs.value) + fee`
- All input nullifiers are fresh (not in nullifier_set)
- All inputs exist in utxo_set (Merkle proof)

---

### Transaction Validation

#### Steps:
1. **Structure Check**: Valid field lengths, at least 1 input/output
2. **Balance Check**: `sum(inputs) = sum(outputs) + fee`
3. **Double-Spend Check**: None of the nullifiers in nullifier_set
4. **Existence Check**: All inputs exist (Merkle proof against state_root)
5. **Signature Check**: Valid signature from input owners

#### Pseudo-code:
```python
def validate_tx(tx, state):
    # Check balance
    input_sum = sum(get_utxo(inp).value for inp in tx.inputs)
    output_sum = sum(out.value for out in tx.outputs)
    if input_sum != output_sum + tx.fee:
        return False, "Balance mismatch"
    
    # Check nullifiers
    for inp in tx.inputs:
        if inp.nullifier in state.nullifier_set:
            return False, "Double spend"
    
    # Check Merkle proofs (for ZK version)
    # ...
    
    return True, ""
```

---

### State Transitions

Applying a transaction:

```python
def apply_tx(tx, state):
    # Add nullifiers (mark inputs as spent)
    for inp in tx.inputs:
        state.nullifier_set.add(inp.nullifier)
    
    # Add new outputs to UTXO set
    for i, out in enumerate(tx.outputs):
        commitment = out.compute_commitment()
        state.utxo_set.insert(commitment)
    
    # Recompute state root
    state.state_root = state.utxo_set.root()
```

---

### Merkle Tree Implementation

For the prototype, we'll use a simple append-only Merkle tree:

```
           Root
          /    \
       H(0,1)  H(2,3)
       /  \    /  \
      L0  L1  L2  L3  (Leaf commitments)
```

**Operations:**
- `insert(commitment)`: Add leaf, update path to root
- `root()`: Return current root
- `prove(index)`: Return Merkle proof for leaf at index
- `verify(commitment, proof, root)`: Check inclusion proof

**Note:** Full Merkle tree with deletions is complex. For prototype:
- Append-only (never delete leaves)
- Nullifiers track what's "logically" spent
- ZK circuit will prove: "commitment in tree AND nullifier fresh"

---

### Design Decisions for CFP

#### D1: Simplified UTXO for Prototype
For initial implementation:
- Skip Merkle proofs (trust-based for single node)
- Use Python dict as UTXO set (commitment -> UTXO)
- Add Merkle tree later for ZK integration

#### D2: Nullifier Computation
```python
nullifier = sha256(utxo_commitment || owner_private_key)
```
This ensures:
- Only owner can compute nullifier (proves ownership)
- Nullifier doesn't reveal which UTXO (privacy)

#### D3: Address = Public Key Hash
```python
address = keccak256(public_key)[-20:]
```
Standard Ethereum-style for familiarity.

---

### Implementation Plan

1. **UTXO dataclass**: value, owner, salt, commitment
2. **Transaction dataclass**: inputs, outputs, fee, signature
3. **Ledger class**: UTXO set + nullifier set + apply/validate
4. **Merkle tree** (basic): append-only for state roots
5. **Tests**: balance, double-spend rejection, state transitions

---

## 3. ZK Prover + Verifier

### Why Zero-Knowledge Proofs?

#### The Problem
In CFP, we want to verify state transitions without:
1. Re-executing every transaction (expensive)
2. Trusting the sequencer blindly (centralization risk)
3. Storing all historical data (storage burden)

#### The Solution: ZK Proofs
A ZK proof lets us say:
> "I know a sequence of transactions that transforms state S₁ to S₂"

Without revealing:
- The actual transactions
- Intermediate states
- Any private data

The verifier just checks the proof (fast) and trusts the transition.

---

### ZK Proof System Choice

#### Options Considered

| System | Prover Time | Proof Size | Trusted Setup | Language |
|--------|-------------|------------|---------------|----------|
| **Groth16** | Slow | ~200 bytes | Required | Circom |
| **PLONK** | Medium | ~500 bytes | Universal | Circom |
| **Halo2** | Medium | ~10KB | None | Rust |
| **STARK** | Fast | ~100KB | None | Cairo |

#### Choice: Groth16 via Circom/snarkjs

**Reasons:**
1. **Mature tooling**: Circom is battle-tested (Tornado Cash, ZKSync)
2. **Small proofs**: 200 bytes fits on-chain easily
3. **JavaScript integration**: snarkjs works well with Python via subprocess
4. **Learning curve**: Circom is more approachable than Rust-based systems

**Trade-off**: Trusted setup required, but acceptable for lab environment.

---

### Circuit Design

#### What We Prove

For a batch of N blocks (e.g., N=100):
1. **State transition**: `old_state_root → new_state_root` is valid
2. **Transaction validity**: Each TX in batch is well-formed
3. **Nullifier freshness**: No double-spends within batch

#### Simplified Circuit for Prototype

Given CFP's complexity, we start with a **minimal circuit**:

```circom
template StateTransition() {
    // Public inputs (visible to verifier)
    signal input old_state_root;
    signal input new_state_root;
    signal input batch_hash;  // Hash of transaction batch
    
    // Private inputs (known only to prover)
    signal input transactions[MAX_TXS];
    signal input merkle_proofs[...];
    
    // Verify the transition
    // (For prototype, we simplify this significantly)
}
```

#### Prototype Simplification

For the initial implementation:
1. **Mock circuit**: Prove knowledge of a preimage (simpler)
2. **Real orchestration**: Full subprocess integration with snarkjs
3. **Batch metadata**: Store proof reference on-chain

We can upgrade the circuit complexity later.

---

### Implementation Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CFP Node                         │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐                │
│  │   Prover    │───▶│   Verifier  │                │
│  │  (Python)   │    │  (Python)   │                │
│  └──────┬──────┘    └─────────────┘                │
│         │                                           │
│         ▼                                           │
│  ┌─────────────────────────────────┐               │
│  │     snarkjs (subprocess)        │               │
│  │  - prove (generate proof)       │               │
│  │  - verify (check proof)         │               │
│  └─────────────────────────────────┘               │
│         │                                           │
│         ▼                                           │
│  ┌─────────────────────────────────┐               │
│  │        Circuit Files            │               │
│  │  - circuit.wasm (compiled)      │               │
│  │  - circuit.zkey (proving key)   │               │
│  │  - verification_key.json        │               │
│  └─────────────────────────────────┘               │
└─────────────────────────────────────────────────────┘
```

#### Workflow

1. **Setup (one-time)**:
   - Compile circom circuit
   - Generate powers of tau (trusted setup)
   - Generate proving/verification keys

2. **Proving (per batch)**:
   - Collect batch of blocks
   - Prepare witness (inputs to circuit)
   - Call snarkjs to generate proof
   - Store proof metadata on-chain

3. **Verification**:
   - Load proof and public inputs
   - Call snarkjs verify
   - Accept/reject based on result

---

### Implementation Plan

#### Files to Create

1. **`circuits/simple_transition.circom`**: Simple demonstration circuit
2. **`cfp/core/prover/prover.py`**: Proof generation orchestration
3. **`cfp/core/prover/verifier.py`**: Proof verification
4. **`cfp/core/prover/setup.py`**: Trusted setup handling
5. **`scripts/setup_circuits.sh`**: One-time circuit compilation

#### Proof Metadata

```python
@dataclass
class ProofMetadata:
    batch_start: int          # First block in batch
    batch_end: int            # Last block in batch
    old_state_root: bytes     # State before batch
    new_state_root: bytes     # State after batch
    proof: bytes              # Serialized snarkjs proof
    public_inputs: List[str]  # Public signals
    created_at: int           # Timestamp
    verified: bool            # Verification status
```

---

### Prototype Approach

#### Phase 3a: Mock Prover (Simulated)
- Python-only, no actual ZK
- Simulates proof generation with delay
- Stores metadata as if real proof

#### Phase 3b: Real ZK Integration
- Install circom + snarkjs
- Simple circuit (hash preimage)
- Full subprocess integration

For this prototype, we implement **Phase 3a** first for rapid development,
then enhance to 3b for real ZK demonstration.

---

### Key Decision: What Are We Actually Proving?

For lab environment, the simplest meaningful proof:

**Prove**: "I know data D such that hash(D) = H"

Where:
- `D` = serialized transaction batch
- `H` = batch hash (public, stored on-chain)

This demonstrates:
1. ZK integration works end-to-end
2. Proof generation and verification flow
3. On-chain proof metadata storage

More sophisticated circuits (full state transition proof) can be added later.

---

## 4. Intent Layer + Execution Tickets

### Why Intents?

#### Traditional Transaction Model
User specifies exact execution:
```
"Transfer 100 tokens from me to Bob"
```

**Problems:**
- MEV extraction by frontrunners
- User must know optimal execution path
- No competition for best execution

#### Intent Model
User specifies desired outcome:
```
"I want my 100 TokenA swapped for at least 95 TokenB"
```

**Benefits:**
- Solvers compete for best execution
- MEV flows to users (via better prices)
- Complexity handled by solvers

---

### CFP Intent System

#### Components

1. **Intent**: User's desired outcome
2. **Solver**: Entity that fulfills intents
3. **Auction**: Competition for execution rights
4. **Execution Ticket**: Right to execute an intent
5. **Bond/Slashing**: Economic security for solvers

#### Flow

```
User                    Auction                  Solver
  │                        │                        │
  │──── Submit Intent ────▶│                        │
  │                        │◀──── Submit Bid ───────│
  │                        │     (fee + bond)       │
  │                        │                        │
  │                        │─── Select Winner ─────▶│
  │                        │   (ExecutionTicket)    │
  │                        │                        │
  │◀─────────────────── Execute Intent ────────────│
  │                        │                        │
  │                        │◀── Proof of Execution ─│
  │                        │   (or slash bond)      │
```

---

### Data Structures

#### Intent
```python
Intent {
    intent_id: bytes32        # Unique identifier
    user: address             # Who created this intent
    intent_type: enum         # SWAP, TRANSFER, CUSTOM
    conditions: bytes         # Serialized conditions
    max_fee: uint64           # Maximum fee willing to pay
    deadline_block: uint64    # Must execute by this block
    signature: bytes          # User signature
}
```

#### Execution Ticket
```python
ExecutionTicket {
    ticket_id: bytes32
    intent_id: bytes32        # Which intent
    solver: address           # Winner of auction
    fee_bid: uint64           # Fee solver will pay
    bond: uint64              # Staked amount
    deadline_block: uint64    # Execute by or lose bond
    status: enum              # PENDING, EXECUTED, SLASHED
}
```

#### Solver
```python
Solver {
    address: bytes20
    bond_balance: uint64      # Total bonded
    reputation: uint64        # Earned reputation
    active_tickets: [...]     # Pending executions
}
```

---

### Auction Mechanism

#### First-Price Sealed Bid
1. Solvers submit bids (fee they'll pay + bond)
2. Highest fee wins execution right
3. Winner gets ExecutionTicket
4. Loser bids refunded

#### Execution Requirements
Winner must:
1. Execute within `deadline_block`
2. Satisfy intent conditions
3. Submit proof of execution

#### Slashing
If solver fails:
- Bond is slashed (goes to user + protocol)
- Reputation decreased
- Intent can be re-auctioned

---

### Implementation for CFP

#### Simplifications
- Single-block auction (immediate resolution)
- Simple slashing (binary: execute or lose bond)
- Mock solver agent for testing

#### Files
1. `intent.py`: Intent dataclass
2. `auction.py`: Auction logic
3. `solver.py`: Mock solver implementation

---

## 5. Persistence Architecture

The Convergent Flow Protocol (CFP) uses a unified **SQLite-backed** persistence layer to ensure durability of the DAG, Ledger state, and ZK commitments.

### Overview

The persistence logic is encapsulated in two main classes:

1.  **`StorageManager`** (`cfp/core/storage/storage_manager.py`):
    -   The high-level facade used by core components (`DAGSequencer`, `Ledger`, `NetworkNode`).
    -   Provides atomic operations for saving blocks and updating state.
    -   Handles recovery and loading of state on startup.

2.  **`SQLiteAdapter`** (`cfp/core/storage/sqlite_adapter.py`):
    -   Low-level database driver.
    -   Manages schema creation and SQL execution.
    -   Does NOT store business logic, only data access.

### Schema

We use a relational schema to model the graph and ledger:

#### DAG Topology
-   **`vertices`**: Stores DAG vertices (atomic units).  
    `{ vertex_id (Blob), data (Blob), timestamp (Int) }`
-   **`edges`**: Stores parent-child relationships.  
    `{ parent_id (Blob), child_id (Blob) }`

#### Ledger State
-   **`utxos`**: Unspent Transaction Outputs.  
    `{ utxo_id (Blob), data (Blob) }`
-   **`nullifiers`**: Set of spent nullifiers to prevent double-spends.  
    `{ nullifier (Blob) }`
-   **`transactions`**: Historical transaction data.  
    `{ tx_hash (Blob), data (Blob), block_height (Int) }`
-   **`snapshots`**: Merkle roots and stats at each block height.  
    `{ block_height (Int), state_root (Blob), ... }`

#### ZK State
-   **`commitments`**: Merkle tree leaves (commitments) by index.
-   **`kv_store`**: Generic key-value store for metadata (e.g., current tip).

### Usage

To enable persistence, initialize the `StorageManager` with a directory path and pass it to components:

```python
from pathlib import Path
from cfp.core.storage.storage_manager import StorageManager
from cfp.core.dag import DAGSequencer
from cfp.core.state import Ledger

# Initialize Storage
data_dir = Path("./data")
storage = StorageManager(data_dir=data_dir)

# Initialize Components with persistence
dag = DAGSequencer(storage_manager=storage)
ledger = Ledger(storage_manager=storage)

# Operations persist automatically
dag.add_vertex(v)  # Saved to SQLite
```

If `data_dir` is not provided (or passed as `None`), the system runs in **In-Memory Mode**, useful for testing and ephemeral demos.

---

## 6. Zero-Knowledge Setup

This document describes the ZK circuit compilation and Trusted Setup process for the CFP protocol.

### Circuits

The system uses three main circuits implemented in Circom 2.1:

1. **Auction Selection (`auction_select.circom`)**
   - Proves correct winner selection (blind auction)
   - Verifies determinism of tie-breaks
   - Constraints: ~6,100 (for K=4 candidates)

2. **Intent Satisfaction (`intent_satisfy.circom`)**
   - Proves a solver's solution matches the intent constraints
   - Verifies intent hash derivation
   - Constraints: ~1,500

3. **UTXO Transition (`utxo_transition.circom`)**
   - Proves validity of state transitions (inputs -> outputs)
   - Checks Merkle inclusion, nullifiers, and balance conservation
   - Constraints: ~11,000 (for 2-in/2-out)

### Trusted Setup

We use the Groth16 proving system, which requires a trusted setup ceremony.

#### Phase 1: Powers of Tau
- **Curve**: BN128 (BN254)
- **Power**: 16 (2^16 = 65,536 constraints capacity)
- **Artifact**: `pot16_final.ptau`

#### Phase 2: Circuit-Specific
- Each circuit has its own Phase 2 setup
- Generates `verification_key.json` and `*.zkey` files

### Building from Source

The `setup_circuits.sh` script automates the entire process:

```bash
# 1. Compile circuits to R1CS/WASM
# 2. Generate/Download Powers of Tau
# 3. Perform Phase 2 setup
# 4. Export verification keys
./setup_circuits.sh
```

### Security

For production, the Trusted Setup should be performed as a multi-party computation (MPC) ceremony (e.g., using `snarkjs` or `mpc` tools) to ensure that toxic waste is discarded. The current setup script is for development/testing only ("toxic waste" is discarded but performed by a single machine).
