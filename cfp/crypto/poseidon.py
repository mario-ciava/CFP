"""
Poseidon Hash Function for CFP.

ZK-friendly hashing over the BN254 scalar field, **compatible with circomlib's
Poseidon** so that hashes computed here match those computed inside the Circom
circuits (and by snarkjs / circomlibjs).

Compatibility is achieved by:
- Using circomlib's exact Grain-LFSR round constants ``C`` and MDS matrices ``M``,
  vendored in ``params/poseidon_bn254_constants.json`` (generated from circomlibjs).
- Implementing the standard (unoptimized) Poseidon permutation from the circomlib
  reference (``poseidon_reference.js``): capacity element initialised to 0, the
  output is ``state[0]``.
- Domain separation is done the circomlib way: the domain tag is passed as an
  *input* element (e.g. ``poseidon([DOMAIN, x])``), never smuggled into the
  capacity slot. This keeps every CFP hash both domain-separated and
  circuit-reproducible.

The known-answer vectors in ``params/poseidon.json`` are checked by
``verify_params()`` (and by ``tests/unit/test_poseidon.py``).

References:
- Poseidon paper: https://eprint.iacr.org/2019/458
- circomlib / circomlibjs: https://github.com/iden3/circomlibjs

Parameters (BN254 / alt_bn128):
- Field prime: 21888242871839275222246405745257275088548364400416034343698204186575808495617
- S-box: x^5 ; full rounds R_F = 8 ; partial rounds R_P depends on width t
  (t=3 -> 57), matching circomlib's N_ROUNDS_P table.
"""

import json
from pathlib import Path
from typing import List, Optional, Tuple

# BN254 scalar field prime
FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# Domain separators (passed as the FIRST input element, circomlib-style).
DOMAIN_INTENT_ID = 0x01
DOMAIN_SOLVER_COMMIT = 0x02
DOMAIN_NULLIFIER = 0x03
DOMAIN_UTXO_COMMITMENT = 0x04
DOMAIN_TRANSCRIPT_LEAF = 0x05
DOMAIN_TIE_BREAK = 0x06


# =============================================================================
# Round constants / MDS matrices (circomlib Grain-LFSR params, vendored)
# =============================================================================

# Full rounds (fixed); partial rounds per width t (index = t - 2).
N_ROUNDS_F = 8
N_ROUNDS_P = [56, 57, 56, 60, 60, 63]

_CONSTANTS_PATH = Path(__file__).parent.parent.parent / "params" / "poseidon_bn254_constants.json"

# Lazily-loaded, indexed by (t - 2):
#   _C[t-2] -> flat list of t*(R_F+R_P) round constants
#   _M[t-2] -> t x t MDS matrix
_C: Optional[List[List[int]]] = None
_M: Optional[List[List[List[int]]]] = None


def _load_constants() -> Tuple[List[List[int]], List[List[List[int]]]]:
    """Load and cache the vendored circomlib Poseidon constants."""
    global _C, _M
    if _C is None or _M is None:
        with open(_CONSTANTS_PATH) as f:
            data = json.load(f)
        _C = [[int(x) for x in row] for row in data["C"]]
        _M = [[[int(x) for x in r] for r in mat] for mat in data["M"]]
    return _C, _M


def _get_params(t: int) -> Tuple[List[int], List[List[int]], int]:
    """Return (round_constants, mds_matrix, n_partial_rounds) for width ``t``."""
    C, M = _load_constants()
    idx = t - 2
    if idx < 0 or idx >= len(C):
        raise ValueError(f"Unsupported Poseidon width t={t} (supported t=2..{len(C) + 1})")
    return C[idx], M[idx], N_ROUNDS_P[idx]


# =============================================================================
# Poseidon permutation (circomlib reference)
# =============================================================================

def _pow5(x: int) -> int:
    """S-box: x^5 mod p."""
    return pow(x, 5, FIELD_PRIME)


def poseidon_hash(inputs: List[int], domain_sep: int = 0) -> int:
    """
    Compute the circomlib-compatible Poseidon hash of ``inputs``.

    Args:
        inputs: 1..6 field elements (integers in [0, FIELD_PRIME)).
        domain_sep: optional domain tag. When non-zero it is prepended as the
            first input element (circomlib-style), NOT placed in the capacity.

    Returns:
        Hash as a field element (integer), equal to ``state[0]`` after the
        permutation — identical to circomlib/snarkjs ``poseidon(inputs)``.
    """
    ins = list(inputs)
    if domain_sep:
        ins = [domain_sep % FIELD_PRIME] + ins

    if not (1 <= len(ins) <= len(N_ROUNDS_P)):
        raise ValueError(f"Poseidon supports 1..{len(N_ROUNDS_P)} inputs, got {len(ins)}")
    for i, val in enumerate(ins):
        if not (0 <= val < FIELD_PRIME):
            raise ValueError(f"Input {i} out of field range: {val}")

    t = len(ins) + 1
    C, M, n_rounds_p = _get_params(t)
    n_rounds_f = N_ROUNDS_F
    half_f = n_rounds_f // 2

    # Capacity element is 0 (circomlib convention).
    state = [0] + ins

    for r in range(n_rounds_f + n_rounds_p):
        # Add round constants.
        state = [(state[i] + C[r * t + i]) % FIELD_PRIME for i in range(t)]

        # S-box: full rounds apply to all elements, partial rounds to state[0].
        if r < half_f or r >= half_f + n_rounds_p:
            state = [_pow5(x) for x in state]
        else:
            state[0] = _pow5(state[0])

        # MDS mix: new_state[i] = sum_j M[i][j] * state[j].
        state = [
            sum(M[i][j] * state[j] for j in range(t)) % FIELD_PRIME
            for i in range(t)
        ]

    return state[0]


# =============================================================================
# Convenience Functions
# =============================================================================

def poseidon2(a: int, b: int, domain_sep: int = 0) -> int:
    """Hash two field elements."""
    return poseidon_hash([a, b], domain_sep)


def poseidon1(a: int, domain_sep: int = 0) -> int:
    """Hash one field element."""
    return poseidon_hash([a], domain_sep)


def poseidon_bytes(data: bytes, domain_sep: int = 0) -> int:
    """
    Hash arbitrary bytes using Poseidon.

    Splits data into 31-byte chunks (to stay below FIELD_PRIME) and folds them
    with a 2-to-1 Poseidon, seeded by ``domain_sep``.
    """
    if not data:
        return poseidon1(0, domain_sep)

    chunks = []
    for i in range(0, len(data), 31):
        chunk = data[i:i + 31]
        chunks.append(int.from_bytes(chunk, byteorder="big"))

    # Fold iteratively: h = poseidon(h, chunk), starting from the domain tag.
    h = domain_sep % FIELD_PRIME
    for chunk in chunks:
        h = poseidon2(h, chunk)

    return h


def poseidon_bytes_to_bytes(data: bytes, domain_sep: int = 0) -> bytes:
    """Hash bytes and return 32-byte result."""
    h = poseidon_bytes(data, domain_sep)
    return h.to_bytes(32, byteorder="big")


def int_to_bytes32(val: int) -> bytes:
    """Convert field element to 32 bytes."""
    return val.to_bytes(32, byteorder="big")


def bytes32_to_int(data: bytes) -> int:
    """Convert 32 bytes to field element."""
    if len(data) != 32:
        raise ValueError(f"Expected 32 bytes, got {len(data)}")
    val = int.from_bytes(data, byteorder="big")
    if val >= FIELD_PRIME:
        raise ValueError(f"Value {val} exceeds field prime")
    return val


# =============================================================================
# CFP-Specific Hash Functions
# =============================================================================

def hash_intent_id(
    user_pubkey: bytes,
    nonce: int,
    constraints_hash: int,
    deadline: int,
    chain_id: int = 1
) -> int:
    """
    Compute intent_id using Poseidon.

    intent_id = Poseidon-fold(DOMAIN_INTENT_ID, pk_hash, nonce, constraints_hash,
    deadline, chain_id). Uses 2-input Poseidon iteratively.
    """
    pk_hash = poseidon_bytes(user_pubkey)

    h = poseidon2(DOMAIN_INTENT_ID, pk_hash)
    h = poseidon2(h, nonce)
    h = poseidon2(h, constraints_hash)
    h = poseidon2(h, deadline)
    h = poseidon2(h, chain_id)

    return h


def hash_solver_commit(
    intent_id: int,
    solver_id: int,
    score: int,
    solution_hash: int,
    salt: int
) -> int:
    """
    Compute solver commitment.

    C = Poseidon-fold(DOMAIN_SOLVER_COMMIT, intent_id, solver_id, score,
    solution_hash, salt).
    """
    h = poseidon2(DOMAIN_SOLVER_COMMIT, intent_id)
    h = poseidon2(h, solver_id)
    h = poseidon2(h, score)
    h = poseidon2(h, solution_hash)
    h = poseidon2(h, salt)

    return h


def hash_nullifier(nullifier_key: int, merkle_path_index: int) -> int:
    """
    Compute nullifier for UTXO spending.

    nullifier = Poseidon(Poseidon(DOMAIN_NULLIFIER, nk), merkle_path_index).
    """
    return poseidon2(
        poseidon2(DOMAIN_NULLIFIER, nullifier_key),
        merkle_path_index
    )


def hash_utxo_commitment(amount: int, pubkey_hash: int, salt: int) -> int:
    """
    Compute UTXO commitment.

    commitment = Poseidon-fold(DOMAIN_UTXO_COMMITMENT, amount, pubkey_hash, salt).
    """
    h = poseidon2(DOMAIN_UTXO_COMMITMENT, amount)
    h = poseidon2(h, pubkey_hash)
    h = poseidon2(h, salt)

    return h


def hash_transcript_leaf(intent_id: int, solver_id: int, commitment: int, timestamp_bucket: int) -> int:
    """
    Compute transcript leaf for auction binding.

    leaf = Poseidon-fold(DOMAIN_TRANSCRIPT_LEAF, intent_id, solver_id, C,
    timestamp_bucket).
    """
    h = poseidon2(DOMAIN_TRANSCRIPT_LEAF, intent_id)
    h = poseidon2(h, solver_id)
    h = poseidon2(h, commitment)
    h = poseidon2(h, timestamp_bucket)

    return h


def hash_tie_break(epoch_seed: int, intent_id: int, solver_id: int) -> int:
    """
    Compute tie-break value for equal-utility bids.

    tie = Poseidon-fold(DOMAIN_TIE_BREAK, epoch_seed, intent_id, solver_id).
    """
    h = poseidon2(DOMAIN_TIE_BREAK, epoch_seed)
    h = poseidon2(h, intent_id)
    h = poseidon2(h, solver_id)

    return h


# =============================================================================
# Verification
# =============================================================================

def verify_params() -> bool:
    """
    Verify that Poseidon matches the circomlib known-answer test vectors.

    Returns True iff every vector in params/poseidon.json (or the hardcoded
    fallback) reproduces exactly.
    """
    params_path = Path(__file__).parent.parent.parent / "params" / "poseidon.json"

    if not params_path.exists():
        test_vectors = [
            ([1, 2], "7853200120776062878684798364095072458815029376092732009249414926327459813530"),
            ([0, 0], "14744269619966411208579211824598458697587494354926760081771325075741142829156"),
        ]
    else:
        with open(params_path) as f:
            params = json.load(f)
        test_vectors = [
            ([int(x) for x in tv["inputs"]], tv["expected"])
            for tv in params.get("test_vectors", [])
        ]

    for inputs, expected in test_vectors:
        result = poseidon_hash(inputs)
        if str(result) != expected:
            print(f"FAIL: poseidon({inputs}) = {result}, expected {expected}")
            return False

    return True


if __name__ == "__main__":
    print("Poseidon self-test...")
    print(f"poseidon(1, 2) = {poseidon2(1, 2)}")
    print(f"poseidon(0, 0) = {poseidon2(0, 0)}")
    print(f"verify_params() = {verify_params()}")
