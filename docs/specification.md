# CFP Protocol Specification

This document specifies the Convergent Flow Protocol, covering intent, solver registry, auction, and scoring mechanisms.

---

## Table of Contents

1. [Intent Specification](#1-intent-specification)
2. [Solver Registry Specification](#2-solver-registry-specification)
3. [Auction Specification](#3-auction-specification)
4. [Scoring Specification](#4-scoring-specification)
5. [Threat Model](#5-threat-model)

---

## 1. Intent Specification

### Overview

An **Intent** represents a user's desired outcome rather than a specific execution path. Users express what they want (e.g., "swap at least X for Y") and solvers compete to find the optimal execution.

### Canonical Intent Format

#### Fields

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `user_pubkey` | bytes | 64 | User's uncompressed public key (ECDSA secp256k1) |
| `nonce` | uint64 | 8 | Unique per-user counter to prevent replay |
| `intent_type` | uint8 | 1 | Type enum (see below) |
| `constraints_hash` | uint256 | 32 | Poseidon hash of typed constraints |
| `max_fee` | uint64 | 8 | Maximum fee willing to pay (in base units) |
| `deadline` | uint64 | 8 | Block number by which intent must be executed |
| `chain_id` | uint64 | 8 | Chain identifier (1 for mainnet prototype) |
| `created_at` | uint64 | 8 | Unix timestamp of creation |

#### Intent Type Enum

```
0x00 = TRANSFER    # Simple value transfer
0x01 = SWAP        # Token swap with min_out
0x02 = CUSTOM      # Custom constraints
```

### Intent ID Computation

The `intent_id` is a deterministic, ZK-provable identifier computed using Poseidon hash:

```
user_pk_hash = poseidon_bytes(user_pubkey)
h = poseidon2(DOMAIN_INTENT_ID, user_pk_hash)
h = poseidon2(h, nonce)
h = poseidon2(h, constraints_hash)
h = poseidon2(h, deadline)
h = poseidon2(h, chain_id)
intent_id = h
```

Where:
- `DOMAIN_INTENT_ID = 0x01`
- All values are field elements in BN254 scalar field

#### Properties

- **Deterministic**: Same inputs always produce same ID
- **Collision-resistant**: Different intents have different IDs
- **ZK-friendly**: Can be proven inside SNARK circuits
- **Domain-separated**: Uses specific domain separator

### Constraints Structure

Constraints are structured data (not free-form JSON) to enable deterministic hashing and ZK proofs.

#### Transfer Constraints

```python
@dataclass
class TransferConstraints:
    recipient: bytes     # 20 bytes
    amount: int          # Exact amount to transfer
```

#### Swap Constraints

```python
@dataclass
class SwapConstraints:
    asset_in: bytes      # 20 bytes (token address or identifier)
    asset_out: bytes     # 20 bytes
    max_in: int          # Maximum input amount
    min_out: int         # Minimum output amount
    venues: List[bytes]  # Allowed execution venues (optional)
```

#### Constraints Hash

```
constraints_hash = poseidon_bytes(serialize(constraints))
```

### Signature

Users sign the intent using ECDSA on secp256k1:

```
message = intent_id (as 32-byte hash)
signature = ecdsa_sign(message, private_key)
```

The signature is 64 bytes (r || s).

### Byte Layout (Canonical Encoding)

For serialization and hashing:

```
Offset  Size  Field
0       64    user_pubkey
64      8     nonce (big-endian)
72      1     intent_type
73      32    constraints_hash
105     8     max_fee (big-endian)
113     8     deadline (big-endian)
121     8     chain_id (big-endian)
129     8     created_at (big-endian)
137     64    signature (r || s)
---
Total: 201 bytes
```

### Validation Rules

An intent is valid if:

1. `user_pubkey` is a valid secp256k1 public key (64 bytes)
2. `nonce` has not been used before by this user
3. `deadline` > current block height
4. `max_fee` > 0
5. `signature` verifies against `user_pubkey` for `intent_id`
6. Constraints are well-formed for the given `intent_type`

---

## 2. Solver Registry Specification

### Overview

The **Solver Registry** is a permissioned list of solver identities that can participate in intent auctions. It serves two critical purposes:

1. **Sybil Resistance**: Prevents identity grinding for tie-break manipulation
2. **Accountability**: Binds solver identities to stake for slashing

### Solver Identity

#### Solver ID

Each registered solver receives a unique `solver_id`:

```
solver_id = Poseidon(DOMAIN_SOLVER_ID, public_key_hash)
```

Where:
- `DOMAIN_SOLVER_ID = 0x10`
- `public_key_hash = poseidon_bytes(public_key)`

#### Properties

- **Deterministic**: Same public key always produces same solver_id
- **Collision-resistant**: Different keys produce different IDs
- **ZK-friendly**: Can be verified in circuits

### Registration

#### Requirements

To register, a solver must:

1. **Provide a unique public key** (ECDSA secp256k1, 64 bytes)
2. **Lock minimum stake** (in protocol tokens)
3. **Sign registration message**

#### Registration Process

```
1. Solver generates keypair (sk, pk)
2. Solver locks stake via UTXO commitment
3. Solver submits registration:
   - public_key: pk
   - stake_utxo_ids: [id1, id2, ...]
   - signature: sign(registration_message, sk)
4. Registry verifies UTXOs belong to solver
5. Registry assigns solver_id = compute_solver_id(pk)
6. Registry locks UTXOs
```

#### Registration Message

```
registration_message = Poseidon(
    DOMAIN_REGISTRATION,
    pk_hash,
    total_stake,
    timestamp
)
```

### Stake Management

#### Minimum Stake

```
MIN_STAKE = 1000  # Protocol tokens (configurable)
```

#### Stake States

| State | Description |
|-------|-------------|
| `LOCKED` | Available for auction participation |
| `BONDED` | Locked in active auction/execution |
| `SLASHED` | Confiscated due to violation |
| `WITHDRAWN` | Returned to solver |

#### Operations

- **Deposit**: Add stake to increase available balance
- **Withdraw**: Remove stake (if not bonded)
- **Bond**: Lock stake for auction participation
- **Slash**: Confiscate stake for violations

### Data Structures

#### RegisteredSolver

```python
@dataclass
class RegisteredSolver:
    solver_id: int           # Poseidon hash of pubkey
    public_key: bytes        # 64 bytes
    stake_total: int         # Total stake deposited
    stake_available: int     # Available for bonding
    stake_bonded: int        # Locked in active executions
    registered_at: int       # Block number
    last_activity: int       # Block number
    is_active: bool          # Can participate in auctions
    slash_count: int         # Number of times slashed
```

#### SolverRegistry API

```python
class SolverRegistry:
    def register(pubkey, stake_utxo_ids) -> solver_id
    def unregister(solver_id) -> bool
    def get_solver(solver_id) -> Optional[RegisteredSolver]
    def is_registered(solver_id) -> bool
    def deposit_stake(solver_id, utxo_ids) -> bool
    def withdraw_stake(solver_id, amount) -> bool
    def bond_stake(solver_id, amount) -> bool
    def release_bond(solver_id, amount) -> bool
    def slash(solver_id, amount, reason) -> bool
```

### Sybil Resistance Strategy

**Problem**: Without registration, an attacker could generate millions of keypairs to find a favorable tie-break hash.

**Solution**: Registration with stake makes this attack economically infeasible. 1M identities × 1000 tokens = 1B tokens locked.

### Rate Limiting

```
MAX_REGISTRATIONS_PER_BLOCK = 10
MIN_STAKE_PER_SOLVER = 1000
REGISTRATION_COOLDOWN = 100  # blocks
```

### Deregistration

Solvers can deregister to recover stake:
1. Solver requests deregistration
2. Wait for cooldown period (pending executions complete)
3. All stake returned
4. Solver ID marked inactive

**Cooldown**: `DEREGISTRATION_COOLDOWN = 1000` blocks (~3 hours)

### Slashing Conditions

| Violation | Slash Percentage |
|-----------|------------------|
| Failed execution (timeout) | 50% of bond |
| Invalid solution submitted | 100% of bond |
| Commit without reveal | 10% of total stake |

---

## 3. Auction Specification

### Overview

The **Commit-Reveal Auction** is a sealed-bid auction mechanism for intent execution. It prevents bid sniping/copying and enables ZK-provable winner selection.

### Auction Lifecycle

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   OPEN      │────▶│   COMMIT    │────▶│   REVEAL    │────▶│  FINALIZED  │
│             │     │   PHASE     │     │   PHASE     │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
    │                     │                   │                    │
    │ Intent              │ Solvers           │ Solvers            │ Winner
    │ submitted           │ submit            │ reveal             │ selected
    │                     │ commitments       │ bids               │
```

### Phases

#### 1. Open Phase
- Intent submitted to auction manager
- Auction created with parameters
- Timers started

#### 2. Commit Phase (Δc blocks)

Solvers submit sealed commitments:

```
SolverCommit = {
    intent_id: bytes32,
    solver_id: int,
    commitment: int,     # C = Poseidon(domain, intent_id, solver_id, score, solution_hash, salt)
    solver_sig: bytes64,
    timestamp: int
}
```

**Rules:**
- One commit per solver per intent
- Solver must be registered
- Commit timestamp must be within window

#### 3. Reveal Phase (Δr blocks)

Solvers reveal their bids:

```
SolverReveal = {
    intent_id: bytes32,
    solver_id: int,
    score: int,          # Utility/fee offered
    solution_hash: int,  # Hash of execution plan
    salt: int            # Random blinding factor
}
```

**Rules:**
- Reveal must match commitment: `C == Poseidon(domain, intent_id, solver_id, score, solution_hash, salt)`
- Non-revealed commits are discarded (and may be penalized)

#### 4. Finalization
- Select winner using argmax(utility, -tie_break)
- Transcript root is computed and published
- Winner receives execution ticket

### Commitment Scheme

#### Format

```
C = Poseidon(
    DOMAIN_SOLVER_COMMIT,
    intent_id,
    solver_id,
    score,
    solution_hash,
    salt
)
```

#### Properties
- **Hiding**: Commitment reveals nothing about bid value
- **Binding**: Cannot open commitment to different value
- **ZK-friendly**: Can be verified in SNARK circuit

### Timing Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `COMMIT_WINDOW` | 10 blocks | Duration of commit phase |
| `REVEAL_WINDOW` | 5 blocks | Duration of reveal phase |
| `MIN_REVEALS` | 1 | Minimum reveals to finalize |
| `TIMESTAMP_TOLERANCE` | 2 blocks | Allowed clock drift |

### State Machine

```python
class AuctionState(IntEnum):
    OPEN = 0           # Accepting intents
    COMMIT_PHASE = 1   # Accepting commits
    REVEAL_PHASE = 2   # Accepting reveals
    FINALIZED = 3      # Winner selected
    CANCELLED = 4      # No valid reveals
```

#### Transitions

```
OPEN -> COMMIT_PHASE: on intent submission
COMMIT_PHASE -> REVEAL_PHASE: after Δc blocks
REVEAL_PHASE -> FINALIZED: after Δr blocks (if valid reveals)
REVEAL_PHASE -> CANCELLED: after Δr blocks (if no valid reveals)
```

### Data Structures

#### CommitRevealAuction

```python
@dataclass
class CommitRevealAuction:
    intent_id: bytes
    intent: Intent
    state: AuctionState
    
    # Phase timing
    commit_start_block: int
    commit_end_block: int
    reveal_end_block: int
    
    # Commits: solver_id -> SolverCommit
    commits: Dict[int, SolverCommit]
    
    # Reveals: solver_id -> SolverReveal
    reveals: Dict[int, SolverReveal]
    
    # Result
    winner_solver_id: Optional[int]
    transcript_root: Optional[int]
```

### Winner Selection

After reveal phase:
1. Validate all reveals (match commitment)
2. Compute utility for each valid reveal
3. Compute tie-break for each solver
4. Select argmax over (utility, -tie_break)
5. Build transcript and compute root

### Transcript

The transcript binds the auction set for verifiability:

```
TranscriptRoot = PoseidonMerkle(leaves)

leaf[i] = Poseidon(
    DOMAIN_TRANSCRIPT_LEAF,
    intent_id,
    solver_id[i],
    commitment[i],
    timestamp_bucket[i]
)
```

### Penalties

| Violation | Penalty |
|-----------|---------|
| Commit without reveal | 10% of stake slashed |
| Invalid reveal (doesn't match) | Reveal ignored (no penalty) |
| Late reveal | Reveal ignored |

### Security Properties

1. **Confidentiality**: Bids hidden until reveal phase
2. **Non-malleability**: Cannot create commitment to unknown value
3. **Fairness**: Winner is deterministic argmax
4. **Auditability**: Transcript proves complete bid set

---

## 4. Scoring Specification

### Overview

The scoring system defines how solver solutions are ranked for an intent. The goal is **deterministic, verifiable winner selection** that can be proven in a ZK circuit.

### Design Principles

1. **Determinism**: Same inputs always produce same ranking
2. **No floating point**: All arithmetic uses fixed-point integers
3. **Total ordering**: Every pair of solutions is comparable
4. **ZK-friendly**: Can be computed inside arithmetic circuits
5. **Ungrindable tie-break**: Solvers cannot manipulate tie-break values

### Utility Function

The utility is a non-negative integer where higher is better.

#### Transfer Intent Utility

For transfers, utility is based on fee efficiency:

```python
def compute_utility_transfer(intent: Intent, solution: Solution) -> int:
    """Utility = fee offered (higher fee = higher utility)"""
    return solution.fee_offered
```

#### Swap Intent Utility

For swaps, utility maximizes user value:

```python
def compute_utility_swap(intent: Intent, solution: Solution) -> int:
    """
    Utility = output_amount - protocol_fee
    
    Solver providing more output to user wins.
    Ties broken by lower input amount if outputs equal.
    """
    # Primary: maximize output (scaled to avoid overflow)
    output_score = solution.output_amount * SCALE_FACTOR
    
    # Secondary: minimize input (inverted, scaled down)
    input_penalty = solution.input_amount  
    
    # Combined (output dominates)
    return output_score - input_penalty
```

Where `SCALE_FACTOR = 2^32`.

### Fixed-Point Arithmetic

```python
SCALE_FACTOR = 2**32
MAX_UTILITY = 2**64 - 1

def safe_add(a: int, b: int) -> int:
    """Addition with overflow check (saturates)."""
    result = a + b
    if result > MAX_UTILITY: return MAX_UTILITY
    return result

def safe_multiply(a: int, b: int, scale: int = SCALE_FACTOR) -> int:
    """Multiply and scale down."""
    return (a * b) // scale
```

**Rounding Rules**: Division always rounds **down** (floor).

### Tie-Break Rule

When two solutions have equal utility, we use a deterministic tie-break:

```python
def compute_tie_break(epoch_seed: int, intent_id: int, solver_id: int) -> int:
    """
    Compute ungrindable tie-break value.
    Smaller tie-break value wins.
    """
    return hash_tie_break(epoch_seed, intent_id, solver_id)
```

#### Properties

- **Epoch-dependent**: Different epochs have different tie-breaks
- **Intent-dependent**: Same solver has different tie-breaks for different intents  
- **Solver-dependent**: Different solvers have different tie-breaks (id assigned by registry)
- **Ungrindable**: Solver cannot predict or manipulate `epoch_seed`

#### Tie-Break Inputs

| Input | Source | Grindability |
|-------|--------|--------------|
| `epoch_seed` | External randomness (L1 block hash) | High |
| `intent_id` | Fixed by user's intent | None |
| `solver_id` | Registry-assigned | Rate-limited |

**Note**: The solver's `salt` is intentionally **excluded** from tie-break computation to prevent grinding.

### Total Ordering

Solutions are compared using lexicographic ordering:

```python
def compare(sol_a, sol_b):
    if utility(a) > utility(b): return 1
    if utility(a) < utility(b): return -1
    
    # Tie-break (smaller wins)
    if tie(a) < tie(b): return 1
    if tie(a) > tie(b): return -1
    return 0
```

### Winner Selection Algorithm

```python
def select_winner(intent: Intent, solutions: List[Solution], epoch_seed: int) -> Optional[Solution]:
    """Select argmax over (utility, -tie_break)."""
    if not solutions: return None
    winner = solutions[0]
    for candidate in solutions[1:]:
        if compare(candidate, winner) > 0:
            winner = candidate
    return winner
```

### ZK Circuit Logic

In the circuit, winner selection is proven by pairwise comparison:
- Utility comparison: ~10 constraints
- Tie-break comparison: ~10 constraints
- Total for K=8 candidates: ~200 constraints

---

## 5. Threat Model

### Overview

This section analyzes security threats to the CFP verifiable auction system and describes the mitigations implemented.

### Threat Categories

#### 1. Auction Manipulation

**1.1 Bid Sniping**
- **Threat:** Attacker observes other bids and submits a winning bid at the last moment.
- **Mitigation:** Commit-reveal auction mechanisms. Bids are sealed until reveal phase.

**1.2 Front-running**
- **Threat:** Attacker observes pending bids and submits their own first.
- **Mitigation:** Commitment ordering uses block timestamp bucketing. Tie-break is ungrindable.

**1.3 Tie-break Grinding**
- **Threat:** Attacker generates many identities to find favorable tie-break.
- **Mitigation:** Solver registry requires stake per identity. Cost to create N identities makes attack economically non-viable.

#### 2. Solver Misbehavior

**2.1 Non-execution**
- **Threat:** Winning solver fails to execute the intent.
- **Mitigation:** Bond is locked at auction win. Slashing (50%) on timeout.

**2.2 Invalid Execution**
- **Threat:** Solver provides solution that doesn't satisfy intent.
- **Mitigation:** ZK proof of intent satisfaction required. Solution hash committed during auction.

**2.3 Commit Without Reveal**
- **Threat:** Solver commits but never reveals (DoS).
- **Mitigation:** 10% stake slashing. Auction proceeds with revealed bids only.

#### 3. Protocol Attacks

**3.1 Double-spend (UTXO)**
- **Threat:** Spend same UTXO twice.
- **Mitigation:** Nullifier published on first spend. Merkle proofs required.

**3.2 State Root Manipulation**
- **Threat:** Invalid state transition posted.
- **Mitigation:** ZK proof of valid transition required (balance conservation).

**3.3 Epoch Manipulation**
- **Threat:** Attacker manipulates epoch seed.
- **Mitigation:** Epoch seed derived from external randomness (L1) after commitments are fixed.

#### 4. Cryptographic Attacks

**4.1 Hash Collision**
- **Threat:** Find collisions in Poseidon hash.
- **Mitigation:** BN254 field (~128-bit security). Domain separation.

**4.2 Commitment Opening**
- **Threat:** Open commitment to different value.
- **Mitigation:** Binding commitment `C = Poseidon(..., salt)`. Salt provides hiding.

### Trust Assumptions

| Component | Trust Level | Notes |
|-----------|-------------|-------|
| L1 (Ethereum) | High | Source of finality and randomness |
| Sequencer | Limited | Can censor but not forge |
| Solvers | Untrusted | Enforced via stake/slashing |
| Users | Untrusted | Signatures verified |
| ZK Prover | Trusted Setup | Powers of tau ceremony |

### Security Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Field size | BN254 (~254 bits) | ~128-bit security |
| Min stake | 1000 tokens | Sybil resistance |
| Commit window | 10 blocks | ~2 minutes |
| Reveal window | 5 blocks | ~1 minute |
| Execution window | 10 blocks | ~2 minutes |
| Slash rate | 50% | Sufficient deterrent |

### Open Questions

1. **Prover availability:** What if prover is down? Fallback to L1 submission (higher gas).
2. **Long-range attacks:** Mitigated by L1 checkpoints.
3. **MEV on L1:** Sequencer bribe attacks? Requires PBS integration research.
