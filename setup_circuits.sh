#!/bin/bash
set -e

# Configuration
POWER=16
PTAU_FILE="pot${POWER}_final.ptau"
CIRCUITS=("auction_select" "intent_satisfy" "utxo_transition")

# Detect circom
CIRCOM_CMD="circom"
if ! command -v circom &> /dev/null; then
    if [ -f "$HOME/.cargo/bin/circom" ]; then
        CIRCOM_CMD="$HOME/.cargo/bin/circom"
    else
        echo "Error: circom not found. Please install circom (Rust version recommended)."
        echo "See: https://docs.circom.io/getting-started/installation/"
        exit 1
    fi
fi

# 0. Compile Circuits
echo "============================================================"
echo "Phase 0: Compiling Circuits"
echo "============================================================"
mkdir -p circuits/build

for CIRCUIT in "${CIRCUITS[@]}"; do
    if [ ! -f "circuits/${CIRCUIT}.circom" ]; then
        echo "Error: circuits/${CIRCUIT}.circom not found!"
        exit 1
    fi
    echo "Compiling $CIRCUIT.circom..."
    $CIRCOM_CMD "circuits/${CIRCUIT}.circom" --r1cs --wasm --sym -o circuits/build
done

# 1. Phase 1: Powers of Tau
if [ ! -f "$PTAU_FILE" ]; then
    echo "============================================================"
    echo "Phase 1: Generating Powers of Tau (2^$POWER)"
    echo "============================================================"
    npx snarkjs powersoftau new bn128 $POWER pot_0000.ptau -v
    npx snarkjs powersoftau contribute pot_0000.ptau "$PTAU_FILE" --name="CFP Setup" -v -e="$(openssl rand -hex 20)"
    rm pot_0000.ptau
else
    echo "Using existing Powers of Tau: $PTAU_FILE"
fi

# Prepare for Phase 2 (Groth16)
PREPARED_PTAU="pot${POWER}_final_prepared.ptau"
if [ ! -f "$PREPARED_PTAU" ]; then
    echo "Preparing Powers of Tau for Phase 2..."
    npx snarkjs powersoftau prepare phase2 "$PTAU_FILE" "$PREPARED_PTAU" -v
fi

# 2. Phase 2: Circuit Setup (circuit-specific)
for CIRCUIT in "${CIRCUITS[@]}"; do
    echo "============================================================"
    echo "Phase 2: Setting up circuit: $CIRCUIT"
    echo "============================================================"
    
    R1CS="circuits/build/${CIRCUIT}.r1cs"
    ZKEY_0="circuits/build/${CIRCUIT}_0000.zkey"
    ZKEY_FINAL="circuits/build/${CIRCUIT}_final.zkey"
    VKEY="circuits/build/${CIRCUIT}_verification_key.json"
    
    if [ ! -f "$R1CS" ]; then
        echo "Error: $R1CS compilation failed."
        exit 1
    fi
    
    # Skip if final zkey exists to save time (idempotency)
    if [ -f "$ZKEY_FINAL" ] && [ -f "$VKEY" ]; then
        echo "Artifacts for $CIRCUIT already exist. Skipping setup."
        continue
    fi
    
    echo "Generating zkey..."
    npx snarkjs groth16 setup "$R1CS" "$PREPARED_PTAU" "$ZKEY_0"
    
    echo "Contributing to zkey..."
    npx snarkjs zkey contribute "$ZKEY_0" "$ZKEY_FINAL" --name="CFP Phase2" -v -e="$(openssl rand -hex 20)"
    rm "$ZKEY_0"
    
    echo "Exporting verification key..."
    npx snarkjs zkey export verificationkey "$ZKEY_FINAL" "$VKEY"
    
    ls -lh "$VKEY"
done

echo ""
echo "✅ Trusted Setup Complete!"
