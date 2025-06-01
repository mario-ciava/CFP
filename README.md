# 🌊 Convergent Flow Protocol (CFP)

> **A research blockchain prototype exploring DAG-based sequencing, ZK provers, intent auctions, and UTXO state models.**

[![Status](https://img.shields.io/badge/Status-Research%20Prototype-blue)]()
[![Python](https://img.shields.io/badge/Python-3.11+-green)]()
[![Tests](https://img.shields.io/badge/Tests-280%20passing-success)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

## ⚠️ Disclaimer

This is a **research prototype** designed to explore and demonstrate blockchain concepts. It is **not production-ready** and should not be used for managing real value. Focus is on correctness and verifiability, not performance or economic security.

---

## 🎯 Overview

CFP implements an **Intent-Centric Execution Layer** with:

| Feature | Description |
|---------|-------------|
| **DAG Sequencing** | Directed Acyclic Graph for partial ordering and parallel ingestion |
| **Verifiable Auctions** | Commit-reveal sealed-bid auctions with ZK winner selection proofs |
| **UTXO State Model** | ZK-friendly state with Poseidon commitments and nullifier sets |
| **ZK Provers** | Circom/Groth16 circuits for state transition and auction verification |
| **Escape Hatch** | Censorship resistance via guaranteed raw transaction quota |

---

## 📁 Project Structure

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
│   └── utxo_transition.circom
├── docs/                   # Documentation
│   ├── documentation.md    # Technical reference
│   ├── specification.md    # Protocol specification
│   └── security_audit.md   # Security audit report
└── tests/                  # Pytest test suite
    ├── unit/               # Unit tests (280 tests)
    └── integration/        # Integration tests
```

---

## 🚀 Quick Start

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

## 🏗️ Core Components

### DAG Sequencer (`cfp/core/dag/`)
- **Vertex**: Atomic unit containing transaction/intent payload
- **Sequencer**: Maintains graph, validates structure, linearizes via Kahn's algorithm
- **Orphan Pool**: Handles out-of-order vertex arrival

### Verifiable Auction (`cfp/core/auction/`, `cfp/core/intent/`)
- **Commit-Reveal**: Sealed-bid auction preventing bid sniping
- **Scoring**: Deterministic utility with Poseidon-based tie-breaking
- **Transcript**: Merkle commitment binding all bids for ZK verification

### UTXO Ledger (`cfp/core/state/`)
- **Transaction**: UTXO model with inputs, outputs, nullifiers
- **Ledger**: State management with double-spend prevention
- **Merkle Tree**: Poseidon-based for ZK compatibility

### ZK Provers (`cfp/core/prover/`, `circuits/`)
- **auction_select.circom**: Proves correct winner selection
- **intent_satisfy.circom**: Proves solution matches constraints
- **utxo_transition.circom**: Proves valid state transitions

### Solver Registry (`cfp/core/registry/`)
- **Registration**: Stake-backed identity management
- **Slashing**: Penalties for auction violations
- **Sybil Resistance**: Economic barrier to identity grinding

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Technical Reference](docs/documentation.md) | Detailed explanations of all components |
| [Protocol Specification](docs/specification.md) | Formal protocol definition and threat model |
| [Security Audit](docs/security_audit.md) | Security review and vulnerability fixes |

---

## 🧪 Testing

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

**Test Coverage**: 280 tests across 17 test files covering unit and integration scenarios.

---

## 🔐 Security Considerations

This is a **research prototype**. Notable security aspects:

- **ZK Circuits**: Not audited - for educational purposes only
- **Trusted Setup**: Single-party setup (toxic waste not properly discarded)
- **Networking**: Basic P2P without DoS protection or peer discovery
- **Cryptography**: Standard primitives (secp256k1, Poseidon) but not audited

**Do not use for real value.**

---

## 📖 Development

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

## 📄 License

MIT License - Research and educational use only.

---

## 🤝 Contributing

This is a research project. Contributions welcome for:
- Bug fixes
- Documentation improvements
- Additional test coverage
- Performance optimizations

---

*Built as a learning exercise in blockchain protocol design.*
