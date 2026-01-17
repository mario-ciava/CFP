# Convergent Flow Protocol (CFP)

> **A research blockchain prototype exploring DAG-based sequencing, ZK provers, intent auctions and UTXO state models.**

[![Status](https://img.shields.io/badge/Status-Research%20Prototype-blue)]()
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-green)]()
[![CI](https://github.com/mario-ciava/cfp/actions/workflows/ci.yml/badge.svg)](https://github.com/mario-ciava/cfp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

## Disclaimer

This is a **research prototype** designed to explore and demonstrate blockchain concepts. It **integrates existing ideas** — DAG sequencing, intent auctions, ZK proofs, and a UTXO/nullifier state model — into a single working codebase; it does **not** claim a novel consensus mechanism or an original research result. It is **not production-ready** and should not be used for managing real value. Focus is on correctness and verifiability, not performance or economic security.

---

## Overview

CFP implements an **Intent-Centric Execution Layer** with:

| Feature | Description |
|---------|-------------|
| **DAG Sequencing** | Directed Acyclic Graph for partial ordering and parallel ingestion; deterministic Kahn linearization |
| **Verifiable Auctions** | Commit-reveal sealed-bid auctions with deterministic integer scoring and a Poseidon transcript |
| **UTXO State Model** | Nullifier-based double-spend prevention; SHA-256 state Merkle tree; Poseidon commitments for ZK |
| **ZK Provers** | Circom/Groth16 circuits; **circomlib-compatible Poseidon** verified end-to-end against a real proof (see [Implementation status](#implementation-status)) |
| **Escape Hatch** | Raw-transaction quota **enforced during block assembly**: user txs get a guaranteed minimum share of each block |

The [Implementation status](#implementation-status) section describes which parts
are complete and which are simplified.

---

## Project Structure

```
cfp/
├── cfp/                    # Main Python package
│   ├── cli/                # Command-line interface
│   ├── core/               # Core protocol logic
│   │   ├── auction/        # Commit-reveal, scoring, transcript
│   │   ├── dag/            # DAG sequencing engine
│   │   ├── intent/         # Intent and auction management
│   │   ├── prover/         # ZK proof orchestration
│   │   ├── registry/       # Solver identity & stake
│   │   ├── state/          # UTXO ledger & Merkle trees
│   │   └── storage/        # SQLite persistence
│   ├── crypto/             # Poseidon, ECDSA, hashing
│   ├── network/            # P2P gossip layer
│   └── utils/              # Logging, validation, benchmarks
├── circuits/               # Circom ZK circuits
│   ├── auction_select.circom
│   ├── intent_satisfy.circom
│   ├── utxo_transition.circom
│   └── poseidon_check.circom  # Python<->circuit Poseidon bridge (CI proof)
├── docs/                   # Documentation
│   ├── documentation.md    # Technical reference
│   ├── specification.md    # Protocol specification
│   └── security.md         # Security notes & threat model
└── tests/                  # Pytest test suite
    ├── unit/               # Unit tests
    └── integration/        # Integration tests
```

---

## Quick Start

### Prerequisites

- **Python 3.11+**
- **Node.js 18+** (for circom/snarkjs)
- **Rust** (for compiling Circom from source)

### Installation

```bash
# Clone and enter directory
git clone https://github.com/mario-ciava/cfp.git
cd cfp

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install Python dependencies
pip install -e .

# Install Node dependencies (for ZK circuits)
npm install

# Compile circuits & run trusted setup (optional, ~5 min)
./setup_circuits.sh
```

### Usage

```bash
# Run interactive demo
cfp demo

# Run specific demo scenarios
cfp demo --scenario intent    # Intent auction demo
cfp demo --scenario zk        # ZK prover demo

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=cfp --cov-report=html
```

---

## Core Components

### DAG Sequencer (`cfp/core/dag/`)
- **Vertex**: atomic unit containing transaction/intent payload
- **Sequencer**: maintains graph, validates structure, linearizes via Kahn's algorithm
- **Orphan Pool**: handles out-of-order vertex arrival

### Verifiable Auction (`cfp/core/auction/`, `cfp/core/intent/`)
- **Commit-Reveal**: sealed-bid auction preventing bid sniping
- **Scoring**: deterministic utility with Poseidon-based tie-breaking
- **Transcript**: merkle commitment binding all bids for ZK verification

### UTXO Ledger (`cfp/core/state/`)
- **Transaction**: UTXO model with inputs, outputs, nullifiers
- **Ledger**: state management with double-spend prevention
- **Merkle Tree**: poseidon-based for ZK compatibility

### ZK Provers (`cfp/core/prover/`, `circuits/`)
- **auction_select.circom**: proves correct winner selection
- **intent_satisfy.circom**: proves solution matches constraints
- **utxo_transition.circom**: proves valid state transitions
- **poseidon_check.circom**: bridge circuit pinning the Python Poseidon to the in-circuit Poseidon

The Python `Poseidon` (`cfp/crypto/poseidon.py`) is **circomlib-compatible** — it
reproduces the canonical circomlib test vectors and matches circomlibjs on random
inputs. `tests/integration/test_zk_proof.py` runs a full **Groth16 setup/prove/verify**
and asserts the in-circuit hash equals the Python one (this test runs in CI). Note:
the auction/state provers **default to a mock** for speed; the real snarkjs path is
opt-in and exercised by the ZK test.

### Solver Registry (`cfp/core/registry/`)
- **Registration**: stake-backed identity management
- **Slashing**: penalties for auction violations
- **Sybil Resistance**: economic barrier to identity grinding

---

## Documentation

| Document | Description |
|----------|-------------|
| [Technical Reference](docs/documentation.md) | Detailed explanations of all components |
| [Protocol Specification](docs/specification.md) | Formal protocol definition and threat model |
| [Security Notes](docs/security.md) | Threat model, security properties, and known limitations |

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/unit/test_dag.py -v

# Run with coverage report
pytest tests/ --cov=cfp --cov-report=html

# Open coverage report
open htmlcov/index.html
```

**Test Coverage**: 300+ tests across 24 files (unit + integration), plus an
end-to-end Groth16 proof test (`tests/integration/test_zk_proof.py`) that runs in CI.
The ZK test skips locally when the `circom`/`snarkjs` toolchain is absent.

---

## Implementation status

Which parts are complete versus simplified:

**Complete and tested**
- secp256k1 ECDSA (low-`s` normalized), SHA-256/Keccak-256.
- UTXO ledger with nullifier double-spend prevention, atomic block rollback,
  duplicate-input / mint-after-genesis guards.
- DAG with deterministic Kahn linearization, mandatory signed vertices,
  iterative (non-recursive) orphan processing.
- Commit-reveal auction, deterministic integer scoring, Poseidon transcript.
- **circomlib-compatible Poseidon**, gated by known-answer vectors and a real
  Groth16 proof (see above).
- SQLite persistence with startup recovery.
- BlockProducer that assembles blocks and inserts a signed block vertex into the DAG.
- **Escape-hatch quota enforced during block assembly**: raw (user) txs get a
  guaranteed minimum share so intent-derived txs can't crowd them out.
- **Signed challenge-response peer handshake**: `peer_id = sha256(pubkey)` and a
  peer authenticates only by signing a fresh nonce (a self-declared id is not
  sufficient). SyncManager serializes/rebuilds a DAG across the wire.

**Simplified or optional (by design)**
- Auction/state **provers default to a mock**; the real snarkjs path is opt-in
  (and covered by the CI ZK-proof test).
- Networking has **no production-grade DoS hardening** (rate limits/bounds only).
- `MockStaking` is a stub used for sequencer selection.
- Two auction implementations coexist by design: `VerifiableAuctionManager` is
  the **canonical** commit-reveal + ZK auction (this is what `cfp demo` runs), and
  the simplified first-price `AuctionManager` is kept only for the solver
  simulation and unit tests (its module docstring says so).

---

## Security Considerations

This is a **research prototype**. The threat model, security properties, and known
limitations are documented in [Security Notes](docs/security.md). In short:

- **ZK Circuits**: not audited - for educational purposes only.
- **Trusted Setup**: single-party setup (toxic waste not properly discarded).
- **Networking**: peer auth is a signed challenge-response, but there is no
  production-grade DoS hardening.
- **Cryptography**: standard primitives (secp256k1, Poseidon). Poseidon is
  circomlib-compatible and vector-tested, but the stack as a whole is not audited.

**Do not use for real value.**

---

## Development

### Code Style

```bash
# Format code
black cfp/ tests/

# Lint
ruff check cfp/ tests/

# Type checking
mypy cfp/
```

### Adding New Features

1. Add implementation in appropriate `cfp/core/` module
2. Export from module's `__init__.py`
3. Add tests in `tests/unit/`
4. Update documentation if needed

---

## Contributing

This is a research project. Contributions welcome for:
- bug fixes
- documentation improvements
- additional test coverage
- performance optimizations

---

## License

See [LICENSE](./LICENSE).
