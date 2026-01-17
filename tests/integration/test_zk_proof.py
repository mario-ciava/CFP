"""
End-to-end ZK proof test.

Compiles a Circom circuit, runs a full Groth16 setup/prove/verify with snarkjs,
and asserts the circuit's public output equals the value computed by the Python
Poseidon (cfp/crypto/poseidon.py) — i.e. the Python and in-circuit hashes agree.

Requires the ZK toolchain (circom + snarkjs). When either is missing the test
skips with a clear reason; CI installs both and runs it for real.

Toolchain discovery:
- circom: $CIRCOM_BIN, else `circom` on PATH, else ~/.cargo/bin/circom.
- snarkjs: node_modules/snarkjs/build/cli.cjs, else `npx snarkjs`.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cfp.crypto import poseidon_hash

REPO_ROOT = Path(__file__).resolve().parents[2]
CIRCUIT = REPO_ROOT / "circuits" / "poseidon_check.circom"
NODE_MODULES = REPO_ROOT / "node_modules"


def _find_circom():
    env = os.environ.get("CIRCOM_BIN")
    if env and Path(env).exists():
        return env
    onpath = shutil.which("circom")
    if onpath:
        return onpath
    cargo = Path.home() / ".cargo" / "bin" / "circom"
    if cargo.exists():
        return str(cargo)
    return None


def _snarkjs_cmd():
    cli = NODE_MODULES / "snarkjs" / "build" / "cli.cjs"
    if cli.exists() and shutil.which("node"):
        return ["node", str(cli)]
    if shutil.which("npx"):
        return ["npx", "--no-install", "snarkjs"]
    return None


CIRCOM = _find_circom()
SNARKJS = _snarkjs_cmd()

pytestmark = pytest.mark.skipif(
    CIRCOM is None
    or SNARKJS is None
    or not (NODE_MODULES / "circomlib").exists()
    or not CIRCUIT.exists(),
    reason="ZK toolchain not available (need circom, snarkjs, node_modules/circomlib)",
)


def _run(cmd, cwd=None):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    assert proc.returncode == 0, f"cmd failed: {cmd}\nstdout:{proc.stdout}\nstderr:{proc.stderr}"
    return proc.stdout


def test_poseidon_bridge_groth16_end_to_end(tmp_path):
    """A real Groth16 proof verifies and its public output matches Python Poseidon."""
    sj = SNARKJS
    a, b = 3, 4
    expected = poseidon_hash([a, b])

    # 1. Compile the circuit (circomlib resolved via -l node_modules).
    _run([CIRCOM, str(CIRCUIT), "--r1cs", "--wasm", "--sym",
          "-o", str(tmp_path), "-l", str(NODE_MODULES)])

    # 2. Powers of Tau (2^12 is ample for a ~200-constraint Poseidon(2)).
    _run(sj + ["powersoftau", "new", "bn128", "12", str(tmp_path / "pot0.ptau")])
    _run(sj + ["powersoftau", "contribute", str(tmp_path / "pot0.ptau"),
               str(tmp_path / "pot1.ptau"), "--name=c1", "-e=cfp-test-entropy-1"])
    _run(sj + ["powersoftau", "prepare", "phase2", str(tmp_path / "pot1.ptau"),
               str(tmp_path / "potfinal.ptau")])

    # 3. Groth16 setup + verification key.
    _run(sj + ["groth16", "setup", str(tmp_path / "poseidon_check.r1cs"),
               str(tmp_path / "potfinal.ptau"), str(tmp_path / "c0.zkey")])
    _run(sj + ["zkey", "contribute", str(tmp_path / "c0.zkey"),
               str(tmp_path / "cfinal.zkey"), "--name=c1", "-e=cfp-test-entropy-2"])
    _run(sj + ["zkey", "export", "verificationkey", str(tmp_path / "cfinal.zkey"),
               str(tmp_path / "vkey.json")])

    # 4. Witness for (a, b), then prove.
    (tmp_path / "input.json").write_text(json.dumps({"a": str(a), "b": str(b)}))
    _run(["node", str(tmp_path / "poseidon_check_js" / "generate_witness.js"),
          str(tmp_path / "poseidon_check_js" / "poseidon_check.wasm"),
          str(tmp_path / "input.json"), str(tmp_path / "witness.wtns")])
    _run(sj + ["groth16", "prove", str(tmp_path / "cfinal.zkey"),
               str(tmp_path / "witness.wtns"), str(tmp_path / "proof.json"),
               str(tmp_path / "public.json")])

    # 5. Verify: snarkjs prints "OK!" on success.
    out = _run(sj + ["groth16", "verify", str(tmp_path / "vkey.json"),
                     str(tmp_path / "public.json"), str(tmp_path / "proof.json")])
    assert "OK!" in out

    # 6. The circuit's public output must equal the Python-side hash.
    public = json.loads((tmp_path / "public.json").read_text())
    assert int(public[0]) == expected, "in-circuit Poseidon != Python Poseidon"
