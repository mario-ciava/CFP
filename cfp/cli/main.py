"""
CFP CLI - Command Line Interface for Convergent Flow Protocol

Main entry point for all CLI commands.
"""

import json
import click
from pathlib import Path
from typing import Optional

from cfp.utils.logger import setup_logging, get_logger


def decrypt_wallet_key(wallet_data: dict, wallet_name: str, password: str) -> Optional[bytes]:
    """
    Decrypt a wallet's private key.
    
    Args:
        wallet_data: Loaded wallet JSON data
        wallet_name: Wallet name (used as salt)
        password: User's password
        
    Returns:
        Decrypted private key bytes, or None on failure
    """
    import base64
    import hashlib
    from cryptography.fernet import Fernet, InvalidToken
    from cfp.crypto import hex_to_bytes
    
    # Check for legacy plaintext wallet
    if "private_key" in wallet_data:
        return hex_to_bytes(wallet_data["private_key"])
    
    # Decrypt encrypted wallet
    if "encrypted_private_key" not in wallet_data:
        return None
    
    try:
        salt = wallet_name.encode()
        key = base64.urlsafe_b64encode(
            hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        )
        fernet = Fernet(key)
        return fernet.decrypt(wallet_data["encrypted_private_key"].encode())
    except InvalidToken:
        return None


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--data-dir", default="~/.cfp", help="Data directory")
@click.version_option(version="0.2.0")
@click.pass_context
def cli(ctx, debug, data_dir):
    """Convergent Flow Protocol - Research blockchain prototype"""
    import logging

    level = logging.DEBUG if debug else logging.INFO
    setup_logging(level=level)
    
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = Path(data_dir).expanduser()
    ctx.obj["data_dir"].mkdir(parents=True, exist_ok=True)


# =============================================================================
# Wallet Commands
# =============================================================================

@cli.group()
def wallet():
    """Wallet management commands"""
    pass


@wallet.command("create")
@click.option("--name", default="default", help="Wallet name")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Encryption password")
@click.pass_context
def wallet_create(ctx, name, password):
    """Create a new encrypted wallet"""
    import base64
    import hashlib
    from cryptography.fernet import Fernet
    from cfp.crypto import generate_keypair, bytes_to_hex
    from cfp.core.state import address_from_public_key
    
    kp = generate_keypair()
    address = address_from_public_key(kp.public_key)
    
    # Derive encryption key from password using PBKDF2
    salt = name.encode()  # Use wallet name as salt (deterministic per wallet)
    key = base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    )
    fernet = Fernet(key)
    
    # Encrypt private key
    encrypted_private_key = fernet.encrypt(kp.private_key).decode('utf-8')
    
    wallet_path = ctx.obj["data_dir"] / "wallets" / f"{name}.json"
    wallet_path.parent.mkdir(parents=True, exist_ok=True)
    
    wallet_data = {
        "name": name,
        "address": bytes_to_hex(address),
        "encrypted_private_key": encrypted_private_key,  # Encrypted!
        "public_key": bytes_to_hex(kp.public_key),
    }
    
    wallet_path.write_text(json.dumps(wallet_data, indent=2))
    
    click.echo(f"✓ Wallet created: {name}")
    click.echo(f"  Address: {bytes_to_hex(address)}")
    click.echo(f"  Saved to: {wallet_path}")
    click.echo(f"  ⚠️  Remember your password - it cannot be recovered!")


@wallet.command("list")
@click.pass_context
def wallet_list(ctx):
    """List all wallets"""
    wallet_dir = ctx.obj["data_dir"] / "wallets"
    if not wallet_dir.exists():
        click.echo("No wallets found.")
        return
    
    for wallet_file in wallet_dir.glob("*.json"):
        data = json.loads(wallet_file.read_text())
        click.echo(f"  {data['name']}: {data['address']}")


@wallet.command("balance")
@click.argument("address")
def wallet_balance(address):
    """Get wallet balance (demo mode)"""
    click.echo(f"Address: {address}")
    click.echo(f"Balance: 1000 CFP (demo)")


# =============================================================================
# Demo Command
# =============================================================================


@cli.command("demo")
@click.option("--scenario", default="basic", help="Demo scenario to run")
def demo(scenario):
    """Run interactive demo of CFP capabilities"""
    from cfp.crypto import generate_keypair, bytes_to_hex
    from cfp.core.state import Ledger, address_from_public_key, create_transfer
    from cfp.core.dag import DAGSequencer, create_genesis_vertex, create_vertex, PayloadType
    from cfp.core.prover import ProverManager
    from cfp.core.intent import AuctionManager, create_intent, IntentType, SolverBid
    from cfp.core.tokenomics import FeeManager
    
    click.echo("=" * 60)
    click.echo("  CONVERGENT FLOW PROTOCOL - DEMO")
    click.echo("=" * 60)
    click.echo()
    
    # Setup
    click.echo("📦 Initializing components...")
    kp_alice = generate_keypair()
    kp_bob = generate_keypair()
    kp_solver = generate_keypair()
    
    alice = address_from_public_key(kp_alice.public_key)
    bob = address_from_public_key(kp_bob.public_key)
    solver = address_from_public_key(kp_solver.public_key)
    
    ledger = Ledger()
    dag = DAGSequencer()
    prover = ProverManager(use_mock=True, batch_size=10)
    auction = AuctionManager()
    fees = FeeManager()
    
    click.echo("  ✓ Ledger, DAG, Prover, Auction, Fees initialized")
    click.echo()
    
    # Genesis
    click.echo("🏛️  Creating genesis...")
    genesis = create_genesis_vertex(kp_alice)
    dag.add_vertex(genesis)
    ledger.create_genesis([(alice, 10000), (solver, 5000)])
    click.echo(f"  ✓ Genesis block created")
    click.echo(f"  ✓ Alice balance: {ledger.get_balance(alice)} CFP")
    click.echo(f"  ✓ Solver balance: {ledger.get_balance(solver)} CFP")
    click.echo()
    
    # Transfer
    click.echo("💸 Alice sends 500 CFP to Bob...")
    utxos = ledger.get_utxos_for_address(alice)
    tx = create_transfer(
        inputs=[(utxos[0], kp_alice.private_key)],
        recipients=[(bob, 500), (alice, 9490)],  # 10 fee
        fee=10,
    )
    ledger.apply_transaction(tx)
    fees.process_fee(tx.tx_hash, 10)
    
    v1 = create_vertex([genesis.vertex_id], tx.to_bytes(), PayloadType.TRANSACTION, kp_alice)
    dag.add_vertex(v1)
    
    click.echo(f"  ✓ Transaction applied")
    click.echo(f"  ✓ Alice: {ledger.get_balance(alice)} CFP")
    click.echo(f"  ✓ Bob: {ledger.get_balance(bob)} CFP")
    click.echo()
    
    # Intent
    click.echo("🎯 Bob submits an intent...")
    intent = create_intent(
        user_address=bob,
        intent_type=IntentType.TRANSFER,
        conditions={"recipient": "0x" + bytes_to_hex(alice), "amount": 100},
        max_fee=20,
        deadline_block=100,
        private_key=kp_bob.private_key,
    )
    auction.submit_intent(intent)
    click.echo(f"  ✓ Intent submitted: {bytes_to_hex(intent.intent_id)[:16]}...")
    click.echo()
    
    # Solver bids
    click.echo("🔧 Solver submits bid...")
    auction.deposit_bond(solver, 1000)
    bid = SolverBid(intent_id=intent.intent_id, solver=solver, fee_bid=15, bond=100)
    auction.submit_bid(bid)
    click.echo(f"  ✓ Bid: fee=15, bond=100")
    click.echo()
    
    # Resolve auction
    click.echo("⚖️  Resolving auction...")
    ticket = auction.resolve_auction(intent.intent_id, current_block=5)
    click.echo(f"  ✓ Winner: solver")
    click.echo(f"  ✓ Ticket ID: {bytes_to_hex(ticket.ticket_id)[:16]}...")
    click.echo()
    
    # ZK Proof
    click.echo("🔐 Generating ZK proof for batch...")
    proof, _ = prover.generate_batch_proof(
        batch_start=0,
        batch_end=10,
        old_state_root=bytes(32),
        new_state_root=ledger.state_root,
        transactions=[tx.to_bytes()],
    )
    click.echo(f"  ✓ Proof generated in {proof.proving_time_ms}ms")
    click.echo(f"  ✓ Proof ID: {bytes_to_hex(proof.proof_id)[:16]}...")
    click.echo()
    
    # Stats
    click.echo("📊 Final Statistics:")
    click.echo(f"  DAG: {dag.vertex_count()} vertices, {len(dag.get_tips())} tips")
    click.echo(f"  Ledger: {len(ledger.utxo_set)} UTXOs, {len(ledger.nullifier_set)} nullifiers")
    click.echo(f"  State Root: {bytes_to_hex(ledger.state_root)[:16]}...")
    click.echo(f"  Fees: {fees.stats()}")
    click.echo()
    click.echo("✅ Demo complete!")


# =============================================================================
# Stats Command
# =============================================================================


@cli.command("stats")
def stats():
    """Show system statistics"""
    click.echo("CFP System Statistics")
    click.echo("-" * 40)
    click.echo("  Version: 0.2.0")
    click.echo("  Modules: DAG, UTXO, Prover, Intent, Storage, Network")
    click.echo("  Tests: 76 passing")
    click.echo("  Status: Research prototype")


# Node Commands
# =============================================================================


@cli.group()
def node():
    """Node management commands"""
    pass


@node.command("start")
@click.option("--port", default=9000, help="P2P port")
@click.option("--connect", default=None, help="Peer to connect to (host:port)")
def node_start(port, connect):
    """Start CFP P2P node"""
    import asyncio
    from cfp.network import NetworkNode, NodeConfig
    
    async def run_node():
        config = NodeConfig(port=port)
        node = NetworkNode(config)
        await node.start()
        
        if connect:
            host, peer_port = connect.split(":")
            click.echo(f"Connecting to {host}:{peer_port}...")
            await node.connect_to_peer(host, int(peer_port))
        
        click.echo(f"Node running on port {port}. Press Ctrl+C to stop.")
        
        try:
            while True:
                await asyncio.sleep(10)
                click.echo(f"  Peers: {node.peer_count}")
        except asyncio.CancelledError:
            pass
        finally:
            await node.stop()
    
    try:
        asyncio.run(run_node())
    except KeyboardInterrupt:
        click.echo("\nNode stopped.")


# =============================================================================
# Transaction Commands
# =============================================================================


@cli.group()
def tx():
    """Transaction commands"""
    pass


@tx.command("send")
@click.option("--from", "from_wallet", required=True, help="Sender wallet name")
@click.option("--to", required=True, help="Recipient address (0x...)")
@click.option("--amount", required=True, type=int, help="Amount to send")
@click.option("--fee", default=10, type=int, help="Transaction fee")
@click.pass_context
def tx_send(ctx, from_wallet, to, amount, fee):
    """Send a transaction (demo mode)"""
    from cfp.crypto import generate_keypair, bytes_to_hex, hex_to_bytes
    from cfp.core.state import Ledger, address_from_public_key, create_transfer
    
    # Load wallet
    wallet_path = ctx.obj["data_dir"] / "wallets" / f"{from_wallet}.json"
    if not wallet_path.exists():
        click.echo(f"❌ Wallet '{from_wallet}' not found")
        click.echo(f"   Create with: cfp wallet create --name {from_wallet}")
        return
    
    wallet_data = json.loads(wallet_path.read_text())
    
    click.echo("Transaction (Demo Mode)")
    click.echo("-" * 40)
    click.echo(f"  From: {wallet_data['name']} ({wallet_data['address'][:12]}...)")
    click.echo(f"  To: {to[:12]}...")
    click.echo(f"  Amount: {amount} CFP")
    click.echo(f"  Fee: {fee} CFP")
    click.echo("")
    
    # Demo: simulate transaction
    click.echo("⚠️  Demo mode: transactions are simulated, not persisted")
    click.echo("")
    
    # Create demo ledger with sender balance
    ledger = Ledger()
    sender_kp = generate_keypair()
    sender_addr = address_from_public_key(sender_kp.public_key)
    recipient_addr = hex_to_bytes(to)
    
    ledger.create_genesis([(sender_addr, 10000)])
    
    # Create transaction
    utxos = ledger.get_utxos_for_address(sender_addr)
    change = 10000 - amount - fee
    
    if change < 0:
        click.echo(f"❌ Insufficient balance for amount + fee")
        return
    
    tx = create_transfer(
        inputs=[(utxos[0], sender_kp.private_key)],
        recipients=[(recipient_addr, amount), (sender_addr, change)],
        fee=fee,
    )
    
    success, msg = ledger.apply_transaction(tx)
    
    if success:
        click.echo(f"✅ Transaction created")
        click.echo(f"   TX Hash: {bytes_to_hex(tx.tx_hash)[:20]}...")
        click.echo(f"   Status: Applied (demo)")
    else:
        click.echo(f"❌ Transaction failed: {msg}")


# =============================================================================
# DAG Commands
# =============================================================================


@cli.group()
def dag():
    """DAG inspection commands"""
    pass


@dag.command("show")
@click.option("--limit", default=10, help="Max vertices to show")
def dag_show(limit):
    """Show DAG structure (demo mode)"""
    from cfp.crypto import generate_keypair, bytes_to_hex
    from cfp.core.dag import DAGSequencer, create_genesis_vertex, create_vertex, PayloadType
    
    click.echo("DAG Structure (Demo)")
    click.echo("-" * 40)
    
    # Create demo DAG
    kp = generate_keypair()
    dag = DAGSequencer()
    
    genesis = create_genesis_vertex(kp)
    dag.add_vertex(genesis)
    
    # Add some vertices
    v1 = create_vertex([genesis.vertex_id], b"tx1", PayloadType.TRANSACTION, kp)
    v2 = create_vertex([genesis.vertex_id], b"tx2", PayloadType.TRANSACTION, kp)
    dag.add_vertex(v1)
    dag.add_vertex(v2)
    
    v3 = create_vertex([v1.vertex_id, v2.vertex_id], b"merge", PayloadType.TRANSACTION, kp)
    dag.add_vertex(v3)
    
    # Display
    click.echo(f"  Total vertices: {dag.vertex_count()}")
    click.echo(f"  Tips: {len(dag.get_tips())}")
    click.echo("")
    click.echo("  Linearized order:")
    
    for i, vid in enumerate(dag.linearize()[:limit]):
        v = dag.get_vertex(vid)
        short_id = bytes_to_hex(vid)[:10]
        parents = len(v.parents)
        click.echo(f"    {i+1}. {short_id}... ({parents} parents, {v.payload_type.name})")


if __name__ == "__main__":
    cli()
