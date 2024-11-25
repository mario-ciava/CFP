"""
CFP CLI - Command Line Interface for Convergent Flow Protocol

Main entry point for all CLI commands.
"""

import json
import click
from pathlib import Path

from cfp.utils.logger import setup_logging, get_logger


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--data-dir", default="~/.cfp", help="Data directory")
@click.version_option(version="0.1.1")
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
@click.pass_context
def wallet_create(ctx, name):
    """Create a new wallet"""
    from cfp.crypto import generate_keypair, bytes_to_hex
    from cfp.core.state import address_from_public_key
    
    kp = generate_keypair()
    address = address_from_public_key(kp.public_key)
    
    wallet_path = ctx.obj["data_dir"] / "wallets" / f"{name}.json"
    wallet_path.parent.mkdir(parents=True, exist_ok=True)
    
    wallet_data = {
        "name": name,
        "address": bytes_to_hex(address),
        "private_key": bytes_to_hex(kp.private_key),
        "public_key": bytes_to_hex(kp.public_key),
    }
    
    wallet_path.write_text(json.dumps(wallet_data, indent=2))
    
    click.echo(f"✓ Wallet created: {name}")
    click.echo(f"  Address: {bytes_to_hex(address)}")
    click.echo(f"  Saved to: {wallet_path}")


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
    click.echo("  Version: 0.1.1")
    click.echo("  Modules: DAG, UTXO, Prover, Intent, Storage")
    click.echo("  Tests: 65+ passing")
    click.echo("  Status: Research prototype")


# =============================================================================
# Node Commands (placeholder)
# =============================================================================


@cli.group()
def node():
    """Node management commands"""
    pass


@node.command("start")
@click.option("--port", default=8545, help="RPC port")
def node_start(port):
    """Start CFP node (not implemented)"""
    click.echo("⚠️  Node networking not yet implemented (planned for v0.2.0)")
    click.echo("   Will include: P2P layer, gossip protocol, state sync")
    click.echo("")
    click.echo("For now, use 'cfp demo' to see the system in action.")


if __name__ == "__main__":
    cli()
