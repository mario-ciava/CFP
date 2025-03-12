"""
Auction Prover - ZK proof generation for auction selection.

This module handles:
- Witness generation for auction_select circuit
- Proof generation via snarkjs
- Proof verification

The prover proves that winner selection was done correctly:
1. Winner has highest utility among candidates
2. Tie-breaks computed correctly with Poseidon
3. All bids are included in transcript (Merkle proof)
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

from cfp.crypto import poseidon2, FIELD_PRIME
from cfp.core.auction.transcript import PoseidonMerkleTree, TranscriptBuilder
from cfp.core.auction.scoring import compute_tie_break
from cfp.utils.logger import get_logger

logger = get_logger("auction_prover")


# =============================================================================
# Constants
# =============================================================================

# Default number of candidates
DEFAULT_K = 4

# Tree depth for transcript Merkle tree
DEFAULT_TREE_DEPTH = 4

# Domain separator (must match circuit)
DOMAIN_TIE_BREAK = 6


# =============================================================================
# Witness Data
# =============================================================================


@dataclass
class AuctionWitness:
    """
    Witness data for auction selection proof.
    
    Contains all values needed to generate the ZK proof.
    """
    # Public inputs
    intent_id: int
    transcript_root: int
    winner_solver_id: int
    winner_score: int
    epoch_seed: int
    
    # Private inputs
    all_solver_ids: List[int] = field(default_factory=list)
    all_scores: List[int] = field(default_factory=list)
    all_commitments: List[int] = field(default_factory=list)
    merkle_proof: List[List[int]] = field(default_factory=list)
    merkle_indices: List[int] = field(default_factory=list)
    
    def to_json(self, k: int = DEFAULT_K, tree_depth: int = DEFAULT_TREE_DEPTH) -> dict:
        """
        Convert to JSON format for snarkjs.
        
        Pads arrays to expected length K.
        """
        # Pad arrays to K
        solver_ids = self.all_solver_ids + [0] * (k - len(self.all_solver_ids))
        scores = self.all_scores + [0] * (k - len(self.all_scores))
        commitments = self.all_commitments + [0] * (k - len(self.all_commitments))
        
        # Pad merkle proofs
        empty_proof = [0] * tree_depth
        proofs = self.merkle_proof + [empty_proof] * (k - len(self.merkle_proof))
        indices = self.merkle_indices + [0] * (k - len(self.merkle_indices))
        
        return {
            "intent_id": str(self.intent_id),
            "transcript_root": str(self.transcript_root),
            "winner_solver_id": str(self.winner_solver_id),
            "winner_score": str(self.winner_score),
            "epoch_seed": str(self.epoch_seed),
            "all_solver_ids": [str(x) for x in solver_ids[:k]],
            "all_scores": [str(x) for x in scores[:k]],
            "all_commitments": [str(x) for x in commitments[:k]],
            "merkle_proof": [[str(x) for x in proof[:tree_depth]] for proof in proofs[:k]],
            "merkle_indices": [str(x) for x in indices[:k]],
        }


# =============================================================================
# Auction Prover
# =============================================================================


class AuctionProver:
    """
    Generates and verifies ZK proofs for auction selection.
    
    Integrates with snarkjs for proof operations.
    """
    
    def __init__(
        self,
        circuit_dir: Path,
        k: int = DEFAULT_K,
        tree_depth: int = DEFAULT_TREE_DEPTH,
    ):
        """
        Initialize the prover.
        
        Args:
            circuit_dir: Path to compiled circuit files
            k: Number of candidates
            tree_depth: Merkle tree depth
        """
        self.circuit_dir = Path(circuit_dir)
        self.k = k
        self.tree_depth = tree_depth
        
        # Expected files
        self.wasm_path = self.circuit_dir / "auction_select_js" / "auction_select.wasm"
        self.zkey_path = self.circuit_dir / "auction_select.zkey"
        self.vkey_path = self.circuit_dir / "verification_key.json"
        
        logger.info(f"AuctionProver initialized: k={k}, tree_depth={tree_depth}")
    
    def is_setup_complete(self) -> bool:
        """Check if circuit files exist."""
        return (
            self.wasm_path.exists() and
            self.zkey_path.exists() and
            self.vkey_path.exists()
        )
    
    # =========================================================================
    # Witness Generation
    # =========================================================================
    
    def generate_witness(
        self,
        intent_id: int,
        epoch_seed: int,
        bids: List[Tuple[int, int, int]],  # (solver_id, score, commitment)
        transcript: TranscriptBuilder,
    ) -> AuctionWitness:
        """
        Generate witness for auction proof.
        
        Args:
            intent_id: Intent being auctioned
            epoch_seed: External randomness
            bids: List of (solver_id, score, commitment) tuples
            transcript: Completed transcript with Merkle proofs
            
        Returns:
            AuctionWitness ready for proof generation
        """
        if not bids:
            raise ValueError("No bids provided")
        
        # Compute tie-breaks and find winner
        solver_ids = []
        scores = []
        commitments = []
        tiebreaks = []
        
        for solver_id, score, commitment in bids:
            solver_ids.append(solver_id)
            scores.append(score)
            commitments.append(commitment)
            tiebreak = compute_tie_break(epoch_seed, intent_id, solver_id)
            tiebreaks.append(tiebreak)
        
        # Find winner using same logic as scoring module
        winner_idx = 0
        winner_score = scores[0]
        winner_tiebreak = tiebreaks[0]
        
        for i in range(1, len(bids)):
            if scores[i] > winner_score:
                winner_idx = i
                winner_score = scores[i]
                winner_tiebreak = tiebreaks[i]
            elif scores[i] == winner_score and tiebreaks[i] < winner_tiebreak:
                winner_idx = i
                winner_score = scores[i]
                winner_tiebreak = tiebreaks[i]
        
        # Generate Merkle proofs for all bids
        merkle_proofs = []
        merkle_indices = []
        
        for i in range(len(bids)):
            proof = transcript.tree.get_proof(i)
            merkle_proofs.append(proof)
            merkle_indices.append(i)
        
        witness = AuctionWitness(
            intent_id=intent_id,
            transcript_root=transcript.root,
            winner_solver_id=solver_ids[winner_idx],
            winner_score=winner_score,
            epoch_seed=epoch_seed,
            all_solver_ids=solver_ids,
            all_scores=scores,
            all_commitments=commitments,
            merkle_proof=merkle_proofs,
            merkle_indices=merkle_indices,
        )
        
        logger.debug(f"Generated witness: winner={witness.winner_solver_id}, score={witness.winner_score}")
        return witness
    
    # =========================================================================
    # Proof Generation
    # =========================================================================
    
    def generate_proof(
        self,
        witness: AuctionWitness,
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Generate ZK proof from witness.
        
        Args:
            witness: Auction witness data
            
        Returns:
            (proof_dict, public_signals) or (None, None) on error
        """
        if not self.is_setup_complete():
            logger.error("Circuit setup not complete")
            return None, None
        
        try:
            # Write witness to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(witness.to_json(self.k, self.tree_depth), f)
                input_path = f.name
            
            # Create temp paths for outputs
            witness_path = tempfile.mktemp(suffix='.wtns')
            proof_path = tempfile.mktemp(suffix='.json')
            public_path = tempfile.mktemp(suffix='.json')
            
            # Generate witness using node
            result = subprocess.run(
                [
                    "node",
                    str(self.circuit_dir / "auction_select_js" / "generate_witness.js"),
                    str(self.wasm_path),
                    input_path,
                    witness_path,
                ],
                capture_output=True,
                text=True,
            )
            
            if result.returncode != 0:
                logger.error(f"Witness generation failed: {result.stderr}")
                return None, None
            
            # Generate proof using snarkjs
            result = subprocess.run(
                [
                    "npx", "snarkjs", "groth16", "prove",
                    str(self.zkey_path),
                    witness_path,
                    proof_path,
                    public_path,
                ],
                capture_output=True,
                text=True,
            )
            
            if result.returncode != 0:
                logger.error(f"Proof generation failed: {result.stderr}")
                return None, None
            
            # Read proof and public signals
            with open(proof_path) as f:
                proof = json.load(f)
            with open(public_path) as f:
                public_signals = json.load(f)
            
            logger.info("Proof generated successfully")
            return proof, public_signals
            
        except Exception as e:
            logger.error(f"Proof generation error: {e}")
            return None, None
        finally:
            # Cleanup temp files
            import os
            for path in [input_path, witness_path, proof_path, public_path]:
                try:
                    os.unlink(path)
                except:
                    pass
    
    # =========================================================================
    # Proof Verification
    # =========================================================================
    
    def verify_proof(
        self,
        proof: Dict,
        public_signals: List[str],
    ) -> bool:
        """
        Verify a ZK proof.
        
        Args:
            proof: Proof dictionary from snarkjs
            public_signals: Public input signals
            
        Returns:
            True if proof is valid
        """
        if not self.vkey_path.exists():
            logger.error("Verification key not found")
            return False
        
        try:
            # Write to temp files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(proof, f)
                proof_path = f.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(public_signals, f)
                public_path = f.name
            
            # Verify using snarkjs
            result = subprocess.run(
                [
                    "npx", "snarkjs", "groth16", "verify",
                    str(self.vkey_path),
                    public_path,
                    proof_path,
                ],
                capture_output=True,
                text=True,
            )
            
            is_valid = "OK" in result.stdout
            
            if is_valid:
                logger.info("Proof verification: VALID")
            else:
                logger.warning(f"Proof verification: INVALID - {result.stdout}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Proof verification error: {e}")
            return False
        finally:
            # Cleanup
            import os
            try:
                os.unlink(proof_path)
                os.unlink(public_path)
            except:
                pass


# =============================================================================
# Mock Prover for Testing
# =============================================================================


class MockAuctionProver:
    """
    Mock prover for testing without actual circuit compilation.
    
    Simulates proof generation/verification by checking witness validity.
    """
    
    def __init__(self, k: int = DEFAULT_K, tree_depth: int = DEFAULT_TREE_DEPTH):
        self.k = k
        self.tree_depth = tree_depth
    
    def is_setup_complete(self) -> bool:
        return True
    
    def generate_witness(
        self,
        intent_id: int,
        epoch_seed: int,
        bids: List[Tuple[int, int, int]],
        transcript: TranscriptBuilder,
    ) -> AuctionWitness:
        """Generate witness (same logic as real prover)."""
        if not bids:
            raise ValueError("No bids provided")
        
        solver_ids = []
        scores = []
        commitments = []
        tiebreaks = []
        
        for solver_id, score, commitment in bids:
            solver_ids.append(solver_id)
            scores.append(score)
            commitments.append(commitment)
            tiebreaks.append(compute_tie_break(epoch_seed, intent_id, solver_id))
        
        # Find winner
        winner_idx = 0
        for i in range(1, len(bids)):
            if scores[i] > scores[winner_idx]:
                winner_idx = i
            elif scores[i] == scores[winner_idx]:
                if tiebreaks[i] < tiebreaks[winner_idx]:
                    winner_idx = i
        
        # Get Merkle proofs
        merkle_proofs = [transcript.tree.get_proof(i) for i in range(len(bids))]
        
        return AuctionWitness(
            intent_id=intent_id,
            transcript_root=transcript.root,
            winner_solver_id=solver_ids[winner_idx],
            winner_score=scores[winner_idx],
            epoch_seed=epoch_seed,
            all_solver_ids=solver_ids,
            all_scores=scores,
            all_commitments=commitments,
            merkle_proof=merkle_proofs,
            merkle_indices=list(range(len(bids))),
        )
    
    def generate_proof(
        self,
        witness: AuctionWitness,
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """Generate mock proof (just validates witness)."""
        # Validate winner is correct
        if not self._validate_winner(witness):
            return None, None
        
        # Generate fake proof
        proof = {
            "pi_a": ["1", "2", "1"],
            "pi_b": [["1", "2"], ["3", "4"], ["1", "1"]],
            "pi_c": ["1", "2", "1"],
            "protocol": "groth16",
            "curve": "bn128",
        }
        
        public_signals = [
            str(witness.intent_id),
            str(witness.transcript_root),
            str(witness.winner_solver_id),
            str(witness.winner_score),
            str(witness.epoch_seed),
        ]
        
        return proof, public_signals
    
    def verify_proof(
        self,
        proof: Dict,
        public_signals: List[str],
    ) -> bool:
        """Verify mock proof (always valid if format correct)."""
        return (
            isinstance(proof, dict) and
            "pi_a" in proof and
            isinstance(public_signals, list) and
            len(public_signals) >= 5
        )
    
    def _validate_winner(self, witness: AuctionWitness) -> bool:
        """Check that declared winner is actually the argmax."""
        if not witness.all_scores:
            return False
        
        best_idx = 0
        for i in range(1, len(witness.all_scores)):
            if witness.all_scores[i] > witness.all_scores[best_idx]:
                best_idx = i
            elif witness.all_scores[i] == witness.all_scores[best_idx]:
                tie_i = compute_tie_break(
                    witness.epoch_seed, witness.intent_id, witness.all_solver_ids[i]
                )
                tie_best = compute_tie_break(
                    witness.epoch_seed, witness.intent_id, witness.all_solver_ids[best_idx]
                )
                if tie_i < tie_best:
                    best_idx = i
        
        return (
            witness.winner_solver_id == witness.all_solver_ids[best_idx] and
            witness.winner_score == witness.all_scores[best_idx]
        )


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "AuctionProver",
    "MockAuctionProver",
    "AuctionWitness",
    "DEFAULT_K",
    "DEFAULT_TREE_DEPTH",
]
