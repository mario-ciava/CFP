"""
Input Validation - Security-focused input sanitization.

Provides validation for all external inputs to prevent:
- Buffer overflows
- Integer overflows  
- Invalid format attacks
- Resource exhaustion
"""

import re
from typing import Tuple, Any, List, Optional
from cfp.crypto import FIELD_PRIME

# =============================================================================
# Constants
# =============================================================================

# Maximum sizes
MAX_PUBLIC_KEY_SIZE = 64
MAX_SIGNATURE_SIZE = 65
MAX_ADDRESS_SIZE = 20
MAX_HASH_SIZE = 32
MAX_INTENT_DATA_SIZE = 4096  # 4KB
MAX_ARRAY_LENGTH = 256
MAX_STRING_LENGTH = 1024

# Field bounds
MIN_AMOUNT = 0
MAX_AMOUNT = 2**64 - 1
MIN_BLOCK = 0
MAX_BLOCK = 2**32 - 1


# =============================================================================
# Validation Functions
# =============================================================================


def validate_bytes(
    data: Any,
    name: str,
    expected_length: Optional[int] = None,
    max_length: Optional[int] = None,
) -> Tuple[bool, str]:
    """
    Validate bytes input.
    
    Args:
        data: Data to validate
        name: Field name for error messages
        expected_length: Exact expected length
        max_length: Maximum allowed length
        
    Returns:
        (is_valid, error_message)
    """
    if not isinstance(data, (bytes, bytearray)):
        return False, f"{name} must be bytes, got {type(data).__name__}"
    
    if expected_length is not None and len(data) != expected_length:
        return False, f"{name} must be {expected_length} bytes, got {len(data)}"
    
    if max_length is not None and len(data) > max_length:
        return False, f"{name} exceeds max length {max_length}, got {len(data)}"
    
    return True, ""


def validate_public_key(public_key: Any) -> Tuple[bool, str]:
    """Validate a public key."""
    return validate_bytes(public_key, "public_key", expected_length=MAX_PUBLIC_KEY_SIZE)


def validate_signature(signature: Any) -> Tuple[bool, str]:
    """Validate a signature."""
    return validate_bytes(signature, "signature", expected_length=MAX_SIGNATURE_SIZE)


def validate_address(address: Any) -> Tuple[bool, str]:
    """Validate an address."""
    return validate_bytes(address, "address", expected_length=MAX_ADDRESS_SIZE)


def validate_hash(hash_value: Any, name: str = "hash") -> Tuple[bool, str]:
    """Validate a hash value."""
    return validate_bytes(hash_value, name, expected_length=MAX_HASH_SIZE)


def validate_integer(
    value: Any,
    name: str,
    min_val: int = MIN_AMOUNT,
    max_val: int = MAX_AMOUNT,
) -> Tuple[bool, str]:
    """
    Validate integer within bounds.
    
    Args:
        value: Value to validate
        name: Field name for errors
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        
    Returns:
        (is_valid, error_message)
    """
    if not isinstance(value, int):
        return False, f"{name} must be int, got {type(value).__name__}"
    
    if value < min_val:
        return False, f"{name} must be >= {min_val}, got {value}"
    
    if value > max_val:
        return False, f"{name} must be <= {max_val}, got {value}"
    
    return True, ""


def validate_field_element(value: Any, name: str = "field_element") -> Tuple[bool, str]:
    """Validate a field element (< FIELD_PRIME)."""
    valid, err = validate_integer(value, name, 0, FIELD_PRIME - 1)
    return valid, err


def validate_amount(amount: Any) -> Tuple[bool, str]:
    """Validate a token amount."""
    return validate_integer(amount, "amount", MIN_AMOUNT, MAX_AMOUNT)


def validate_block_number(block: Any) -> Tuple[bool, str]:
    """Validate a block number."""
    return validate_integer(block, "block_number", MIN_BLOCK, MAX_BLOCK)


def validate_array(
    data: Any,
    name: str,
    max_length: int = MAX_ARRAY_LENGTH,
) -> Tuple[bool, str]:
    """
    Validate array/list input.
    
    Args:
        data: Data to validate
        name: Field name for errors
        max_length: Maximum allowed length
        
    Returns:
        (is_valid, error_message)
    """
    if not isinstance(data, (list, tuple)):
        return False, f"{name} must be list/tuple, got {type(data).__name__}"
    
    if len(data) > max_length:
        return False, f"{name} exceeds max length {max_length}, got {len(data)}"
    
    return True, ""


def validate_string(
    value: Any,
    name: str,
    max_length: int = MAX_STRING_LENGTH,
    pattern: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Validate string input.
    
    Args:
        value: Value to validate
        name: Field name for errors
        max_length: Maximum string length
        pattern: Optional regex pattern
        
    Returns:
        (is_valid, error_message)
    """
    if not isinstance(value, str):
        return False, f"{name} must be str, got {type(value).__name__}"
    
    if len(value) > max_length:
        return False, f"{name} exceeds max length {max_length}"
    
    if pattern and not re.match(pattern, value):
        return False, f"{name} does not match required pattern"
    
    return True, ""


def validate_hex_string(value: Any, name: str, expected_bytes: Optional[int] = None) -> Tuple[bool, str]:
    """
    Validate a hex string (with or without 0x prefix).
    
    Args:
        value: Value to validate
        name: Field name
        expected_bytes: Expected byte length when decoded
        
    Returns:
        (is_valid, error_message)
    """
    if not isinstance(value, str):
        return False, f"{name} must be str, got {type(value).__name__}"
    
    # Remove 0x prefix if present
    hex_str = value[2:] if value.startswith("0x") else value
    
    # Must be even length
    if len(hex_str) % 2 != 0:
        return False, f"{name} has odd length, invalid hex"
    
    # Must be valid hex
    try:
        bytes.fromhex(hex_str)
    except ValueError:
        return False, f"{name} contains invalid hex characters"
    
    if expected_bytes is not None:
        actual_bytes = len(hex_str) // 2
        if actual_bytes != expected_bytes:
            return False, f"{name} must be {expected_bytes} bytes, got {actual_bytes}"
    
    return True, ""


# =============================================================================
# Composite Validators
# =============================================================================


def validate_intent_data(data: Any) -> Tuple[bool, str]:
    """Validate intent data structure."""
    if not isinstance(data, dict):
        return False, "Intent data must be dict"
    
    required_fields = ["user_address", "intent_type", "max_fee", "deadline_block"]
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
    
    # Validate user_address
    if isinstance(data["user_address"], bytes):
        valid, err = validate_address(data["user_address"])
    else:
        valid, err = validate_hex_string(data["user_address"], "user_address", 20)
    if not valid:
        return False, err
    
    # Validate max_fee
    valid, err = validate_amount(data["max_fee"])
    if not valid:
        return False, err
    
    # Validate deadline_block
    valid, err = validate_block_number(data["deadline_block"])
    if not valid:
        return False, err
    
    return True, ""


def validate_bid_data(data: Any) -> Tuple[bool, str]:
    """Validate bid data structure."""
    if not isinstance(data, dict):
        return False, "Bid data must be dict"
    
    required = ["intent_id", "solver_id", "commitment"]
    for field in required:
        if field not in data:
            return False, f"Missing required field: {field}"
    
    # Validate intent_id
    if isinstance(data["intent_id"], bytes):
        valid, err = validate_hash(data["intent_id"], "intent_id")
    else:
        valid, err = validate_field_element(data["intent_id"], "intent_id")
    if not valid:
        return False, err
    
    # Validate solver_id
    valid, err = validate_field_element(data["solver_id"], "solver_id")
    if not valid:
        return False, err
    
    # Validate commitment
    valid, err = validate_field_element(data["commitment"], "commitment")
    if not valid:
        return False, err
    
    return True, ""


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "validate_bytes",
    "validate_public_key",
    "validate_signature",
    "validate_address",
    "validate_hash",
    "validate_integer",
    "validate_field_element",
    "validate_amount",
    "validate_block_number",
    "validate_array",
    "validate_string",
    "validate_hex_string",
    "validate_intent_data",
    "validate_bid_data",
    "MAX_PUBLIC_KEY_SIZE",
    "MAX_SIGNATURE_SIZE",
    "MAX_ADDRESS_SIZE",
    "MAX_HASH_SIZE",
]
