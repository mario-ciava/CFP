"""
Transaction - State transition in CFP ledger.

Conceptual Background:
---------------------
A Transaction consumes inputs (UTXOs) and creates outputs (new UTXOs).

The fundamental invariant is value conservation:
    sum(inputs.value) = sum(outputs.value) + fee

Each input references a specific UTXO and provides:
- The UTXO identifier (tx_hash + output_index)
- A nullifier (proves ownership and marks as spent)
- A signature (authorizes the spend)

Transaction Types:
-----------------
1. Transfer: Standard value transfer between addresses
2. Mint: Create new tokens (special, only in genesis or by protocol)

Double-Spend Prevention:
-----------------------
When a transaction is applied:
1. Check all input nullifiers are fresh (not in nullifier set)
2. Add all nullifiers to the set
3. Any future transaction trying to use the same nullifier fails

This ensures each UTXO can only be spent once.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import secrets

from cfp.crypto import sha256, sign, verify, bytes_to_hex
from cfp.core.state.utxo import UTXO, address_from_public_key


# =============================================================================
# Constants
# =============================================================================

# SECURITY: Maximum value that can fit in 8 bytes (used for serialization)
MAX_VALUE = 2**64 - 1


# =============================================================================
# Input Reference
# =============================================================================


@dataclass
class TxInput:
    """
    A transaction input - reference to a UTXO being spent.
    
    Attributes:
        tx_hash: Transaction that created the UTXO
        output_index: Index in that transaction's outputs
        nullifier: Nullifier to mark UTXO as spent
        signature: Signature authorizing the spend
    """
    tx_hash: bytes       # 32 bytes
    output_index: int    # 0-255
    nullifier: bytes     # 32 bytes
    signature: bytes     # 64 bytes (ECDSA signature)
    
    @property
    def utxo_id(self) -> bytes:
        """Get the UTXO identifier this input references."""
        return self.tx_hash + self.output_index.to_bytes(1, byteorder="big")
    
    def to_bytes(self) -> bytes:
        """Serialize input."""
        return (
            self.tx_hash +
            self.output_index.to_bytes(1, byteorder="big") +
            self.nullifier +
            self.signature
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "TxInput":
        """Deserialize input."""
        offset = 0
        tx_hash = data[offset:offset + 32]
        offset += 32
        output_index = data[offset]
        offset += 1
        nullifier = data[offset:offset + 32]
        offset += 32
        signature = data[offset:offset + 64]
        return cls(tx_hash, output_index, nullifier, signature)


# =============================================================================
# Output
# =============================================================================


@dataclass
class TxOutput:
    """
    A transaction output - a new UTXO to be created.
    
    Note: This is the "template" for a UTXO. The actual UTXO will be
    created with the transaction hash once the transaction is confirmed.
    
    Attributes:
        value: Token amount
        owner: Recipient address (20 bytes)
        salt: Randomness for commitment (32 bytes)
    """
    value: int
    owner: bytes  # 20 bytes
    salt: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    
    def to_utxo(self, tx_hash: bytes, index: int) -> UTXO:
        """Convert output template to actual UTXO."""
        return UTXO(
            tx_hash=tx_hash,
            output_index=index,
            value=self.value,
            owner=self.owner,
            salt=self.salt,
        )
    
    def to_bytes(self) -> bytes:
        """Serialize output."""
        return (
            self.value.to_bytes(8, byteorder="big") +
            self.owner +
            self.salt
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "TxOutput":
        """Deserialize output."""
        value = int.from_bytes(data[0:8], byteorder="big")
        owner = data[8:28]
        salt = data[28:60]
        return cls(value, owner, salt)


# =============================================================================
# Transaction
# =============================================================================


@dataclass
class Transaction:
    """
    A state transition that consumes inputs and creates outputs.
    
    Invariants:
    - sum(inputs.value) = sum(outputs.value) + fee
    - All input nullifiers are fresh
    - All inputs exist and are owned by signers
    
    Attributes:
        inputs: List of TxInputs being spent
        outputs: List of TxOutputs being created
        fee: Fee paid to sequencer
        tx_hash: Hash of the transaction (computed)
    """
    inputs: List[TxInput]
    outputs: List[TxOutput]
    fee: int
    tx_hash: bytes = field(default=b"")
    
    def __post_init__(self):
        """Validate basic structure."""
        if len(self.outputs) == 0:
            raise ValueError("Transaction must have at least one output")
        if self.fee < 0:
            raise ValueError("Fee cannot be negative")
    
    # =========================================================================
    # Transaction Hash
    # =========================================================================
    
    def compute_content_bytes(self) -> bytes:
        """
        Compute canonical byte representation for hashing.
        
        Format: num_inputs(1) || inputs || num_outputs(1) || outputs || fee(8)
        """
        parts = []
        
        # Inputs
        parts.append(len(self.inputs).to_bytes(1, byteorder="big"))
        for inp in self.inputs:
            # For hash, we only include tx_hash, output_index, nullifier (not signature)
            parts.append(inp.tx_hash)
            parts.append(inp.output_index.to_bytes(1, byteorder="big"))
            parts.append(inp.nullifier)
        
        # Outputs
        parts.append(len(self.outputs).to_bytes(1, byteorder="big"))
        for out in self.outputs:
            parts.append(out.to_bytes())
        
        # Fee
        parts.append(self.fee.to_bytes(8, byteorder="big"))
        
        return b"".join(parts)
    
    def compute_tx_hash(self) -> bytes:
        """Compute the transaction hash."""
        return sha256(self.compute_content_bytes())
    
    def compute_signing_hash(self) -> bytes:
        """
        Compute the hash that inputs should sign.
        
        This is the message that each input signer authorizes.
        """
        return self.compute_tx_hash()
    
    # =========================================================================
    # Signing
    # =========================================================================
    
    def sign_input(self, input_index: int, private_key: bytes) -> None:
        """
        Sign a specific input.
        
        Args:
            input_index: Which input to sign
            private_key: Private key of the input's UTXO owner
        """
        if input_index >= len(self.inputs):
            raise IndexError(f"Input index {input_index} out of range")
        
        signing_hash = self.compute_signing_hash()
        signature = sign(signing_hash, private_key)
        self.inputs[input_index] = TxInput(
            tx_hash=self.inputs[input_index].tx_hash,
            output_index=self.inputs[input_index].output_index,
            nullifier=self.inputs[input_index].nullifier,
            signature=signature,
        )
    
    def verify_input_signature(self, input_index: int, public_key: bytes) -> bool:
        """
        Verify a specific input's signature.
        
        Args:
            input_index: Which input to verify
            public_key: Public key that should have signed
            
        Returns:
            True if signature is valid
        """
        if input_index >= len(self.inputs):
            return False
        
        signing_hash = self.compute_signing_hash()
        return verify(signing_hash, self.inputs[input_index].signature, public_key)
    
    def finalize(self) -> None:
        """Compute and set the transaction hash."""
        self.tx_hash = self.compute_tx_hash()
    
    # =========================================================================
    # Validation
    # =========================================================================
    
    def validate_structure(self) -> tuple[bool, str]:
        """
        Validate structural correctness (not state).
        
        Checks:
        - Has at least one output
        - Fee is non-negative
        - All fields have correct lengths
        """
        if len(self.outputs) == 0:
            return False, "Must have at least one output"
        
        if self.fee < 0:
            return False, "Fee cannot be negative"
        
        # SECURITY: Check fee doesn't exceed max value for serialization
        if self.fee > MAX_VALUE:
            return False, f"Fee exceeds maximum value: {self.fee} > {MAX_VALUE}"
        
        # Check input field lengths
        for i, inp in enumerate(self.inputs):
            if len(inp.tx_hash) != 32:
                return False, f"Input {i}: tx_hash must be 32 bytes"
            if len(inp.nullifier) != 32:
                return False, f"Input {i}: nullifier must be 32 bytes"
        
        # Check output field lengths and value bounds
        for i, out in enumerate(self.outputs):
            if len(out.owner) != 20:
                return False, f"Output {i}: owner must be 20 bytes"
            if len(out.salt) != 32:
                return False, f"Output {i}: salt must be 32 bytes"
            if out.value <= 0:
                return False, f"Output {i}: value must be positive"
            # SECURITY: Prevent integer overflow at serialization
            if out.value > MAX_VALUE:
                return False, f"Output {i}: value exceeds maximum: {out.value} > {MAX_VALUE}"
        
        return True, ""
    
    # =========================================================================
    # Serialization
    # =========================================================================
    
    def to_bytes(self) -> bytes:
        """Serialize transaction."""
        parts = []
        
        # tx_hash
        parts.append(self.tx_hash if self.tx_hash else bytes(32))
        
        # Inputs
        parts.append(len(self.inputs).to_bytes(1, byteorder="big"))
        for inp in self.inputs:
            parts.append(inp.to_bytes())
        
        # Outputs
        parts.append(len(self.outputs).to_bytes(1, byteorder="big"))
        for out in self.outputs:
            parts.append(out.to_bytes())
        
        # Fee
        parts.append(self.fee.to_bytes(8, byteorder="big"))
        
        return b"".join(parts)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "Transaction":
        """Deserialize transaction."""
        offset = 0
        
        # tx_hash
        tx_hash = data[offset:offset + 32]
        offset += 32
        
        # Inputs
        num_inputs = data[offset]
        offset += 1
        inputs = []
        for _ in range(num_inputs):
            inp = TxInput.from_bytes(data[offset:offset + 129])
            inputs.append(inp)
            offset += 129  # 32 + 1 + 32 + 64
        
        # Outputs
        num_outputs = data[offset]
        offset += 1
        outputs = []
        for _ in range(num_outputs):
            out = TxOutput.from_bytes(data[offset:offset + 60])
            outputs.append(out)
            offset += 60  # 8 + 20 + 32
        
        # Fee
        fee = int.from_bytes(data[offset:offset + 8], byteorder="big")
        
        tx = cls(inputs=inputs, outputs=outputs, fee=fee)
        tx.tx_hash = tx_hash
        return tx
    
    # =========================================================================
    # Utility
    # =========================================================================
    
    def __repr__(self) -> str:
        tx_id = bytes_to_hex(self.tx_hash)[:10] + "..." if self.tx_hash else "unsigned"
        return f"Transaction(id={tx_id}, inputs={len(self.inputs)}, outputs={len(self.outputs)}, fee={self.fee})"
    
    def total_output_value(self) -> int:
        """Sum of all output values."""
        return sum(out.value for out in self.outputs)


# =============================================================================
# Factory Functions
# =============================================================================


def create_transfer(
    inputs: List[tuple[UTXO, bytes]],  # List of (utxo, private_key)
    recipients: List[tuple[bytes, int]],  # List of (address, value)
    fee: int,
) -> Transaction:
    """
    Create a signed transfer transaction.
    
    Args:
        inputs: List of (UTXO, private_key) tuples
        recipients: List of (address, value) tuples
        fee: Transaction fee
        
    Returns:
        Signed Transaction
        
    Note: The caller must ensure sum(inputs) = sum(recipients) + fee
    """
    # Build inputs
    tx_inputs = []
    for utxo, private_key in inputs:
        nullifier = utxo.compute_nullifier(private_key)
        tx_inputs.append(TxInput(
            tx_hash=utxo.tx_hash,
            output_index=utxo.output_index,
            nullifier=nullifier,
            signature=bytes(64),  # Placeholder, will be signed
        ))
    
    # Build outputs
    tx_outputs = []
    for address, value in recipients:
        tx_outputs.append(TxOutput(value=value, owner=address))
    
    # Create transaction
    tx = Transaction(inputs=tx_inputs, outputs=tx_outputs, fee=fee)
    
    # Sign all inputs
    for i, (utxo, private_key) in enumerate(inputs):
        tx.sign_input(i, private_key)
    
    # Finalize
    tx.finalize()
    
    return tx


def create_mint(
    recipient: bytes,
    value: int,
) -> Transaction:
    """
    Create a mint transaction (no inputs, creates new tokens).
    
    This is a special transaction for genesis or protocol rewards.
    In production, this would be restricted to authorized entities.
    
    Args:
        recipient: Address to receive minted tokens
        value: Amount to mint
        
    Returns:
        Mint Transaction
    """
    tx = Transaction(
        inputs=[],  # No inputs for mint
        outputs=[TxOutput(value=value, owner=recipient)],
        fee=0,
    )
    tx.finalize()
    return tx
