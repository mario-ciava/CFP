"""
Benchmarks for CFP core components.

Run with: python -m cfp.utils.benchmark
"""

import time
import statistics
from typing import Callable, List, Tuple
from dataclasses import dataclass

from cfp.crypto import (
    sha256, keccak256, poseidon2, poseidon_bytes,
    generate_keypair, sign, verify,
)
from cfp.core.auction.transcript import PoseidonMerkleTree, compute_merkle_root
from cfp.core.auction.scoring import compute_utility, compute_tie_break
from cfp.utils.logger import get_logger

logger = get_logger("benchmark")


# =============================================================================
# Benchmark Framework
# =============================================================================


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""
    name: str
    iterations: int
    total_time_ms: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    ops_per_sec: float
    
    def __str__(self) -> str:
        return (
            f"{self.name}: {self.ops_per_sec:.0f} ops/s "
            f"(avg={self.avg_time_ms:.3f}ms, min={self.min_time_ms:.3f}ms, max={self.max_time_ms:.3f}ms)"
        )


def benchmark(
    name: str,
    func: Callable,
    iterations: int = 1000,
    warmup: int = 100,
) -> BenchmarkResult:
    """
    Run a benchmark.
    
    Args:
        name: Benchmark name
        func: Function to benchmark (no args)
        iterations: Number of iterations
        warmup: Warmup iterations
        
    Returns:
        BenchmarkResult
    """
    # Warmup
    for _ in range(warmup):
        func()
    
    # Collect timings
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # ms
    
    total = sum(times)
    avg = statistics.mean(times)
    
    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time_ms=total,
        avg_time_ms=avg,
        min_time_ms=min(times),
        max_time_ms=max(times),
        ops_per_sec=1000 / avg,
    )


# =============================================================================
# Hash Benchmarks
# =============================================================================


def benchmark_hashing() -> List[BenchmarkResult]:
    """Benchmark hash functions."""
    results = []
    data = b"x" * 64  # 64 bytes input
    
    # SHA-256
    results.append(benchmark(
        "SHA-256 (64 bytes)",
        lambda: sha256(data),
        iterations=10000,
    ))
    
    # Keccak-256
    results.append(benchmark(
        "Keccak-256 (64 bytes)",
        lambda: keccak256(data),
        iterations=10000,
    ))
    
    # Poseidon (2 inputs)
    results.append(benchmark(
        "Poseidon2 (2 field elements)",
        lambda: poseidon2(12345, 67890),
        iterations=1000,
    ))
    
    # Poseidon (bytes)
    results.append(benchmark(
        "Poseidon (64 bytes)",
        lambda: poseidon_bytes(data),
        iterations=1000,
    ))
    
    return results


# =============================================================================
# Signature Benchmarks
# =============================================================================


def benchmark_signatures() -> List[BenchmarkResult]:
    """Benchmark signature operations."""
    results = []
    kp = generate_keypair()
    message = b"Test message for signing"
    message_hash = sha256(message)
    signature = sign(message_hash, kp.private_key)
    
    # Key generation
    results.append(benchmark(
        "ECDSA Key Generation",
        lambda: generate_keypair(),
        iterations=100,
    ))
    
    # Signing
    results.append(benchmark(
        "ECDSA Sign",
        lambda: sign(message_hash, kp.private_key),
        iterations=100,
    ))
    
    # Verification
    results.append(benchmark(
        "ECDSA Verify",
        lambda: verify(message_hash, signature, kp.public_key),
        iterations=100,
    ))
    
    return results


# =============================================================================
# Merkle Tree Benchmarks
# =============================================================================


def benchmark_merkle() -> List[BenchmarkResult]:
    """Benchmark Merkle tree operations."""
    results = []
    
    # Build tree (16 leaves)
    leaves = list(range(1, 17))
    results.append(benchmark(
        "PoseidonMerkle Build (16 leaves)",
        lambda: PoseidonMerkleTree(depth=4, leaves=leaves.copy()),
        iterations=100,
    ))
    
    # Build tree (256 leaves)
    big_leaves = list(range(1, 257))
    results.append(benchmark(
        "PoseidonMerkle Build (256 leaves)",
        lambda: PoseidonMerkleTree(depth=8, leaves=big_leaves.copy()),
        iterations=10,
    ))
    
    # Proof generation
    tree = PoseidonMerkleTree(depth=4, leaves=leaves)
    results.append(benchmark(
        "PoseidonMerkle Proof Generation",
        lambda: tree.get_proof(0),
        iterations=1000,
    ))
    
    # Proof verification
    proof = tree.get_proof(0)
    leaf = tree.leaves[0]
    results.append(benchmark(
        "PoseidonMerkle Proof Verification",
        lambda: tree.verify_proof(leaf, 0, proof),
        iterations=1000,
    ))
    
    return results


# =============================================================================
# Scoring Benchmarks
# =============================================================================


def benchmark_scoring() -> List[BenchmarkResult]:
    """Benchmark scoring operations."""
    from dataclasses import dataclass
    
    @dataclass
    class MockIntent:
        max_fee: int = 100
        min_out: int = 1000
    
    @dataclass
    class MockSolution:
        fee_offered: int = 50
        output_amount: int = 1100
        input_amount: int = 1000
    
    results = []
    intent = MockIntent()
    solution = MockSolution()
    
    from cfp.core.auction.scoring import compute_utility_transfer, compute_utility_swap
    
    # Utility computation (transfer)
    results.append(benchmark(
        "Utility Compute (transfer)",
        lambda: compute_utility_transfer(intent, solution),
        iterations=10000,
    ))
    
    # Tie-break computation
    results.append(benchmark(
        "Tie-break Compute",
        lambda: compute_tie_break(
            epoch_seed=12345,
            intent_id=67890,
            solver_id=11111,
        ),
        iterations=1000,
    ))
    
    return results


# =============================================================================
# Full Auction Simulation
# =============================================================================


def benchmark_auction_simulation() -> List[BenchmarkResult]:
    """Benchmark auction operations."""
    from cfp.core.auction import CommitRevealAuction, create_commitment
    from cfp.core.auction.commit_reveal import SolverCommit, SolverReveal
    
    results = []
    
    # Commitment creation
    results.append(benchmark(
        "Commitment Creation",
        lambda: create_commitment(b"\x01" * 32, 1, 100, 999, 42),
        iterations=1000,
    ))
    
    # Auction with commits only (avoid full scoring)
    def run_commits():
        auction = CommitRevealAuction(
            intent_id=b"\x01" * 32,
            intent=None,
            commit_window=10,
            reveal_window=5,
        )
        auction.start(0)
        for i in range(4):
            commitment = create_commitment(b"\x01" * 32, i, 100 + i, 999, i * 1000)
            commit = SolverCommit(b"\x01" * 32, i, commitment)
            auction.submit_commit(commit, 1)
        return auction
    
    results.append(benchmark(
        "Auction Commits (4 solvers)",
        run_commits,
        iterations=100,
    ))
    
    return results


# =============================================================================
# Main
# =============================================================================


def run_all_benchmarks() -> None:
    """Run all benchmarks and print results."""
    print("=" * 60)
    print("CFP Performance Benchmarks")
    print("=" * 60)
    
    sections = [
        ("Hashing", benchmark_hashing),
        ("Signatures", benchmark_signatures),
        ("Merkle Trees", benchmark_merkle),
        ("Scoring", benchmark_scoring),
        ("Auction Simulation", benchmark_auction_simulation),
    ]
    
    for section_name, bench_func in sections:
        print(f"\n{section_name}")
        print("-" * 40)
        results = bench_func()
        for r in results:
            print(f"  {r}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    run_all_benchmarks()
