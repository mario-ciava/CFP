# Security Notes

CFP is a **research prototype**, not audited software. This document summarizes the
threat model it considers, the properties the implementation aims to provide, and
its known limitations. It is a self-assessment, not a substitute for an independent
audit.

**Do not use for real value.**

## Threat model

- **Value conservation / double-spend.** The UTXO ledger rejects reused nullifiers
  and duplicate inputs within a transaction, and enforces
  `sum(inputs) == sum(outputs) + fee`. Block application is atomic with rollback.
- **Unauthorized state changes.** Each input carries an ECDSA signature that must
  recover to the UTXO owner. Minting is restricted to genesis.
- **DAG integrity.** Vertices are content-addressed and must be signed; unsigned or
  tampered vertices are rejected. Linearization is deterministic (Kahn with a
  lexicographic tie-break), so honest nodes agree on ordering.
- **Resource exhaustion.** The orphan pool is bounded and processed iteratively (no
  unbounded recursion). Messages, peers, and the mempool are size-bounded.
- **Auction manipulation.** Bids are sealed (commit-reveal); the winner is a
  deterministic integer utility with an ungrindable tie-break, bound by a Poseidon
  transcript and provable in ZK.
- **Censorship.** A raw-transaction quota is enforced during block assembly, so user
  transactions cannot be fully crowded out by intent-derived ones.
- **Peer authentication.** Peers authenticate with a signed challenge-response;
  `peer_id = sha256(pubkey)` and a self-declared id is never sufficient.

## Cryptography

- secp256k1 ECDSA with low-`s` normalization; SHA-256 / Keccak-256.
- Poseidon over BN254, parameter-compatible with circomlib (known-answer vectors in
  `params/poseidon.json`, checked by the test suite). A Groth16 proof over
  `circuits/poseidon_check.circom` confirms the Python and in-circuit hashes agree.

## Known limitations

- ZK circuits and the trusted setup are **not audited**; the setup is single-party.
- The auction/state provers default to a mock; the real snarkjs path is opt-in
  (exercised by the CI ZK-proof job).
- The P2P layer has size/rate bounds but **no production-grade DoS hardening**.
- `MockStaking` is a placeholder for sequencer selection.
- Two auctions coexist by design: `VerifiableAuctionManager` (canonical) and a
  simplified `AuctionManager` used for the solver simulation and tests.

## Reproducing the security-relevant tests

```bash
pytest tests/ -q                                            # unit + integration
CIRCOM_BIN=$(which circom) pytest tests/integration/test_zk_proof.py   # real proof
```
