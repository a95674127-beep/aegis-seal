//! Append entries to a hash-chained audit ledger, verify the chain,
//! and use an external checkpoint to detect truncation / rewrites.
//!
//! Run with: `cargo run --example audit_ledger`

use aegis_seal::ledger::{AuditLedger, CheckpointVerdict, LedgerCheckpoint};

fn main() {
    let mut ledger = AuditLedger::new();
    ledger.append(b"user alice created");
    ledger.append(b"user bob created");
    let third = ledger.append(b"policy updated");
    println!(
        "appended 3 entries; tip seq={} chain_hash={}",
        third.seq,
        hex::encode(third.chain_hash)
    );

    match ledger.verify() {
        Ok(()) => println!("chain verifies"),
        Err(e) => println!("chain invalid: {e}"),
    }

    // Save an external checkpoint (store this somewhere an attacker
    // cannot rewrite along with the chain — see LedgerCheckpoint docs).
    let checkpoint = ledger.checkpoint();
    let json = checkpoint.to_json();
    println!("checkpoint json: {json}");

    // The checkpoint round-trips through JSON.
    match LedgerCheckpoint::from_json(&json) {
        Ok(parsed) => {
            println!(
                "checkpoint verdict after round-trip: {:?}",
                ledger.verify_checkpoint(&parsed)
            );
        }
        Err(e) => println!("checkpoint parse failed: {e}"),
    }

    // Growth after the checkpoint is not tampering.
    ledger.append(b"user carol created");
    let verdict = ledger.verify_checkpoint(&checkpoint);
    println!("verdict after growth: {verdict:?}");
    assert_eq!(verdict, CheckpointVerdict::Match);
}
