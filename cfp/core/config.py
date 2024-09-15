"""
Chain configuration parameters for CFP.

Defines consensus rules, economic parameters, and operational limits.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ChainConfig:
    """Chain-wide configuration parameters"""

    # Consensus parameters
    raw_tx_min_quota: float = 0.10  # Minimum 10% raw transactions (escape hatch)
    block_size_limit: int = 1_000_000  # Maximum block size in bytes
    block_time_target: int = 5  # Target block time in seconds

    # ZK Proving parameters
    prover_batch_size: int = 100  # Prove state transition every N blocks
    prover_timeout: int = 300  # Maximum proving time in seconds
    recursive_proof_depth: int = 3  # Depth of recursive proofs

    # Intent auction parameters
    solver_bond_amount: int = 1000  # Minimum bond for solvers
    solver_execution_timeout: int = 10  # Blocks to execute intent
    min_solver_fee: int = 1  # Minimum fee for auction participation

    # Storage parameters
    pruning_block_age: int = 10000  # Prune blocks older than this
    archival_enabled: bool = False  # Enable archival node features

    # Tokenomics
    genesis_supply: int = 1_000_000_000  # Initial token supply
    block_reward: int = 10  # Reward per block
    prover_reward: int = 100  # Reward per successful batch proof
    archiver_reward: int = 5  # Reward for storage proof

    # Paths
    data_dir: Path = Path("data")
    log_dir: Path = Path("logs")
    circuit_dir: Path = Path("circuits")

    def __post_init__(self):
        """Create necessary directories"""
        self.data_dir.mkdir(exist_ok=True, parents=True)
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.circuit_dir.mkdir(exist_ok=True, parents=True)


# Global config instance (can be overridden)
config = ChainConfig()


def load_config(config_path: Optional[str] = None) -> ChainConfig:
    """
    Load configuration from file or use defaults.

    Args:
        config_path: Optional path to config file

    Returns:
        ChainConfig instance
    """
    if config_path:
        # TODO: Implement config file loading (JSON/TOML)
        pass

    return ChainConfig()
