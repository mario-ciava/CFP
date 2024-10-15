"""
ZK Prover - Proof generation for CFP state transitions.

This module provides orchestration for ZK proof generation using snarkjs.
For the prototype, we implement:
1. Mock prover (simulated proofs for rapid development)
2. Real prover (actual snarkjs integration)

The prover generates proofs for batches of blocks, proving state transitions
from old_state_root to new_state_root are valid.
"""

import asyncio
import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import secrets

from cfp.crypto import sha256, bytes_to_hex, hex_to_bytes
from cfp.utils.logger import get_logger

logger = get_logger("prover")


# =============================================================================
# Proof Metadata
# =============================================================================


@dataclass
class ProofMetadata:
    """
    Metadata for a generated ZK proof.
    
    Stored on-chain to allow verification of state transitions.
    """
    proof_id: bytes                 # Unique identifier
    batch_start: int                # First block in proven batch
    batch_end: int                  # Last block in proven batch
    old_state_root: bytes           # State root before batch
    new_state_root: bytes           # State root after batch
    batch_hash: bytes               # Hash of transaction batch
    proof: bytes                    # Serialized proof data
    public_inputs: List[str]        # Public signals
    created_at: int                 # Unix timestamp
    proving_time_ms: int            # Time to generate proof
    verified: bool = False          # Whether verified successfully
    
    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "proof_id": bytes_to_hex(self.proof_id),
            "batch_start": self.batch_start,
            "batch_end": self.batch_end,
            "old_state_root": bytes_to_hex(self.old_state_root),
            "new_state_root": bytes_to_hex(self.new_state_root),
            "batch_hash": bytes_to_hex(self.batch_hash),
            "proof": bytes_to_hex(self.proof),
            "public_inputs": self.public_inputs,
            "created_at": self.created_at,
            "proving_time_ms": self.proving_time_ms,
            "verified": self.verified,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ProofMetadata":
        """Create from dict."""
        return cls(
            proof_id=hex_to_bytes(data["proof_id"]),
            batch_start=data["batch_start"],
            batch_end=data["batch_end"],
            old_state_root=hex_to_bytes(data["old_state_root"]),
            new_state_root=hex_to_bytes(data["new_state_root"]),
            batch_hash=hex_to_bytes(data["batch_hash"]),
            proof=hex_to_bytes(data["proof"]),
            public_inputs=data["public_inputs"],
            created_at=data["created_at"],
            proving_time_ms=data["proving_time_ms"],
            verified=data.get("verified", False),
        )


# =============================================================================
# Mock Prover (Simulated ZK)
# =============================================================================


class MockProver:
    """
    Simulated ZK prover for development and testing.
    
    Generates fake proofs with configurable delay to simulate
    real proving time. Useful for testing the proof pipeline
    without requiring actual ZK infrastructure.
    """
    
    def __init__(
        self,
        proving_delay_ms: int = 1000,
        success_rate: float = 1.0,
    ):
        """
        Initialize mock prover.
        
        Args:
            proving_delay_ms: Simulated proving time in milliseconds
            success_rate: Probability of successful proof (for testing failures)
        """
        self.proving_delay_ms = proving_delay_ms
        self.success_rate = success_rate
        self.proofs_generated = 0
    
    def generate_proof(
        self,
        batch_start: int,
        batch_end: int,
        old_state_root: bytes,
        new_state_root: bytes,
        transactions: List[bytes],
    ) -> Tuple[ProofMetadata, str]:
        """
        Generate a mock proof for a batch of blocks.
        
        Args:
            batch_start: First block number
            batch_end: Last block number
            old_state_root: State root before batch
            new_state_root: State root after batch
            transactions: List of serialized transactions
            
        Returns:
            (ProofMetadata, error_message)
        """
        start_time = time.time()
        
        # Simulate proving time
        time.sleep(self.proving_delay_ms / 1000)
        
        # Simulate potential failure
        if secrets.randbelow(100) / 100 > self.success_rate:
            return None, "Mock proving failed (simulated failure)"
        
        # Compute batch hash
        batch_data = b"".join(transactions)
        batch_hash = sha256(batch_data)
        
        # Generate fake proof (just random bytes)
        fake_proof = secrets.token_bytes(256)
        
        # Create proof ID
        proof_id = sha256(
            batch_hash +
            old_state_root +
            new_state_root +
            batch_start.to_bytes(8, "big") +
            batch_end.to_bytes(8, "big")
        )
        
        proving_time_ms = int((time.time() - start_time) * 1000)
        
        metadata = ProofMetadata(
            proof_id=proof_id,
            batch_start=batch_start,
            batch_end=batch_end,
            old_state_root=old_state_root,
            new_state_root=new_state_root,
            batch_hash=batch_hash,
            proof=fake_proof,
            public_inputs=[
                bytes_to_hex(old_state_root),
                bytes_to_hex(new_state_root),
                bytes_to_hex(batch_hash),
            ],
            created_at=int(time.time()),
            proving_time_ms=proving_time_ms,
            verified=False,
        )
        
        self.proofs_generated += 1
        logger.info(f"Mock proof generated for blocks {batch_start}-{batch_end} in {proving_time_ms}ms")
        
        return metadata, ""
    
    def verify_proof(self, proof: ProofMetadata) -> Tuple[bool, str]:
        """
        Verify a mock proof.
        
        For mock proofs, just checks the structure is valid.
        """
        if not proof.proof:
            return False, "Empty proof"
        
        # Mock verification always succeeds if proof exists
        proof.verified = True
        return True, "Mock verification passed"


# =============================================================================
# Real Prover (snarkjs integration)
# =============================================================================


class SnarkJSProver:
    """
    Real ZK prover using snarkjs via subprocess.
    
    Requires:
    - Node.js installed
    - snarkjs installed globally (npm install -g snarkjs)
    - Compiled circuit files (circuit.wasm, circuit.zkey)
    """
    
    def __init__(
        self,
        circuit_dir: Path,
        circuit_name: str = "simple_transition",
    ):
        """
        Initialize snarkjs prover.
        
        Args:
            circuit_dir: Directory containing compiled circuit files
            circuit_name: Name of the circuit
        """
        self.circuit_dir = Path(circuit_dir)
        self.circuit_name = circuit_name
        
        # Expected file paths
        self.wasm_path = self.circuit_dir / f"{circuit_name}_js" / f"{circuit_name}.wasm"
        self.zkey_path = self.circuit_dir / f"{circuit_name}.zkey"
        self.vkey_path = self.circuit_dir / "verification_key.json"
        
        self.proofs_generated = 0
    
    def is_setup_complete(self) -> bool:
        """Check if circuit files exist."""
        return (
            self.wasm_path.exists() and
            self.zkey_path.exists() and
            self.vkey_path.exists()
        )
    
    def generate_proof(
        self,
        batch_start: int,
        batch_end: int,
        old_state_root: bytes,
        new_state_root: bytes,
        transactions: List[bytes],
    ) -> Tuple[Optional[ProofMetadata], str]:
        """
        Generate a real ZK proof using snarkjs.
        
        Args:
            batch_start: First block number
            batch_end: Last block number
            old_state_root: State root before batch
            new_state_root: State root after batch
            transactions: List of serialized transactions
            
        Returns:
            (ProofMetadata, error_message)
        """
        if not self.is_setup_complete():
            return None, f"Circuit not compiled. Run setup first."
        
        start_time = time.time()
        
        # Prepare witness input
        batch_data = b"".join(transactions)
        batch_hash = sha256(batch_data)
        
        # Convert to field elements for circom
        # (simplified - real circuit would have more complex inputs)
        witness_input = {
            "old_state_root": int.from_bytes(old_state_root[:16], "big"),
            "new_state_root": int.from_bytes(new_state_root[:16], "big"),
            "batch_hash": int.from_bytes(batch_hash[:16], "big"),
        }
        
        # Write input file
        input_path = self.circuit_dir / "input.json"
        with open(input_path, "w") as f:
            json.dump(witness_input, f)
        
        # Generate witness
        witness_path = self.circuit_dir / "witness.wtns"
        try:
            result = subprocess.run(
                [
                    "node",
                    str(self.circuit_dir / f"{self.circuit_name}_js" / "generate_witness.js"),
                    str(self.wasm_path),
                    str(input_path),
                    str(witness_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                return None, f"Witness generation failed: {result.stderr}"
        except subprocess.TimeoutExpired:
            return None, "Witness generation timed out"
        except FileNotFoundError:
            return None, "Node.js not found"
        
        # Generate proof
        proof_path = self.circuit_dir / "proof.json"
        public_path = self.circuit_dir / "public.json"
        try:
            result = subprocess.run(
                [
                    "snarkjs", "groth16", "prove",
                    str(self.zkey_path),
                    str(witness_path),
                    str(proof_path),
                    str(public_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                return None, f"Proof generation failed: {result.stderr}"
        except subprocess.TimeoutExpired:
            return None, "Proof generation timed out"
        except FileNotFoundError:
            return None, "snarkjs not found"
        
        # Read proof and public inputs
        with open(proof_path) as f:
            proof_json = json.load(f)
        with open(public_path) as f:
            public_inputs = json.load(f)
        
        proving_time_ms = int((time.time() - start_time) * 1000)
        
        # Create proof ID
        proof_id = sha256(
            batch_hash +
            old_state_root +
            new_state_root +
            batch_start.to_bytes(8, "big")
        )
        
        metadata = ProofMetadata(
            proof_id=proof_id,
            batch_start=batch_start,
            batch_end=batch_end,
            old_state_root=old_state_root,
            new_state_root=new_state_root,
            batch_hash=batch_hash,
            proof=json.dumps(proof_json).encode(),
            public_inputs=public_inputs,
            created_at=int(time.time()),
            proving_time_ms=proving_time_ms,
            verified=False,
        )
        
        self.proofs_generated += 1
        logger.info(f"Proof generated for blocks {batch_start}-{batch_end} in {proving_time_ms}ms")
        
        return metadata, ""
    
    def verify_proof(self, proof: ProofMetadata) -> Tuple[bool, str]:
        """
        Verify a ZK proof using snarkjs.
        
        Args:
            proof: Proof metadata to verify
            
        Returns:
            (is_valid, error_message)
        """
        if not self.vkey_path.exists():
            return False, "Verification key not found"
        
        # Write proof and public inputs to temp files
        proof_path = self.circuit_dir / "verify_proof.json"
        public_path = self.circuit_dir / "verify_public.json"
        
        try:
            proof_json = json.loads(proof.proof.decode())
            with open(proof_path, "w") as f:
                json.dump(proof_json, f)
            with open(public_path, "w") as f:
                json.dump(proof.public_inputs, f)
        except Exception as e:
            return False, f"Failed to parse proof: {e}"
        
        # Run verification
        try:
            result = subprocess.run(
                [
                    "snarkjs", "groth16", "verify",
                    str(self.vkey_path),
                    str(public_path),
                    str(proof_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode == 0 and "OK" in result.stdout:
                proof.verified = True
                return True, ""
            else:
                return False, f"Verification failed: {result.stdout}"
                
        except subprocess.TimeoutExpired:
            return False, "Verification timed out"
        except FileNotFoundError:
            return False, "snarkjs not found"


# =============================================================================
# Prover Manager
# =============================================================================


class ProverManager:
    """
    High-level prover management for CFP.
    
    Handles batch collection, proof generation, and storage.
    Supports both mock and real provers.
    """
    
    def __init__(
        self,
        circuit_dir: Optional[Path] = None,
        use_mock: bool = True,
        batch_size: int = 100,
    ):
        """
        Initialize prover manager.
        
        Args:
            circuit_dir: Directory for circuit files
            use_mock: Use mock prover instead of real ZK
            batch_size: Number of blocks per proof batch
        """
        self.batch_size = batch_size
        self.proof_history: List[ProofMetadata] = []
        
        if use_mock:
            self.prover = MockProver(proving_delay_ms=100)
        else:
            if circuit_dir is None:
                circuit_dir = Path("circuits")
            self.prover = SnarkJSProver(circuit_dir)
    
    def should_prove(self, current_block: int, last_proven_block: int) -> bool:
        """Check if we should generate a new proof."""
        return (current_block - last_proven_block) >= self.batch_size
    
    def generate_batch_proof(
        self,
        batch_start: int,
        batch_end: int,
        old_state_root: bytes,
        new_state_root: bytes,
        transactions: List[bytes],
    ) -> Tuple[Optional[ProofMetadata], str]:
        """
        Generate proof for a batch of blocks.
        
        Args:
            batch_start: First block number
            batch_end: Last block number
            old_state_root: State before batch
            new_state_root: State after batch
            transactions: All transactions in batch
            
        Returns:
            (ProofMetadata, error_message)
        """
        metadata, error = self.prover.generate_proof(
            batch_start=batch_start,
            batch_end=batch_end,
            old_state_root=old_state_root,
            new_state_root=new_state_root,
            transactions=transactions,
        )
        
        if metadata:
            self.proof_history.append(metadata)
        
        return metadata, error
    
    def verify_proof(self, proof: ProofMetadata) -> Tuple[bool, str]:
        """Verify a proof."""
        return self.prover.verify_proof(proof)
    
    def get_latest_proof(self) -> Optional[ProofMetadata]:
        """Get the most recent proof."""
        return self.proof_history[-1] if self.proof_history else None
    
    def get_proof_by_range(self, block_num: int) -> Optional[ProofMetadata]:
        """Find proof that covers a specific block."""
        for proof in reversed(self.proof_history):
            if proof.batch_start <= block_num <= proof.batch_end:
                return proof
        return None
    
    def stats(self) -> dict:
        """Get prover statistics."""
        return {
            "proofs_generated": len(self.proof_history),
            "use_mock": isinstance(self.prover, MockProver),
            "batch_size": self.batch_size,
            "latest_batch_end": self.proof_history[-1].batch_end if self.proof_history else 0,
        }
