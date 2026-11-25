//! Verify a MACK vault chain-tip checkpoint independently, using
//! only its four public values (public key, seq, head hash, signature).
//!
//! Run with: `cargo run --example verify_checkpoint`
//!
//! The values below are the pinned test vector from
//! `src/checkpoint.rs`, produced by the vault's own signing code
//! with its test seed, so this example runs offline with no vault,
//! no database, and no signing key present.

use aegis_seal::checkpoint::{checkpoint_message, verify_checkpoint, CHECKPOINT_DOMAIN};

const PUBKEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const SEQ: u64 = 5;
const HEAD_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SIGNATURE: &str = "80a73edcc5624f8cb6cdb5b8783ee4a5cf7ec738eb46542ecbf0c7dfc1a947a\
    ad50ad5f609aed8cb64dc68f8873a0a77547e321b2b9a9079e903db4405f72d01";

fn main() {
    // The signed message is domain ‖ seq (8-byte BE) ‖ head hash.
    let message = checkpoint_message(SEQ, HEAD_HASH);
    println!(
        "domain: {:?} ({} bytes), reconstructed message: {} bytes",
        String::from_utf8_lossy(CHECKPOINT_DOMAIN),
        CHECKPOINT_DOMAIN.len(),
        message.len()
    );

    match verify_checkpoint(PUBKEY, SEQ, HEAD_HASH, SIGNATURE) {
        Ok(()) => println!("checkpoint signature valid"),
        Err(e) => println!("checkpoint rejected: {e}"),
    }

    // The same signature at a different sequence must be rejected.
    match verify_checkpoint(PUBKEY, SEQ + 1, HEAD_HASH, SIGNATURE) {
        Ok(()) => println!("ERROR: wrong seq verified"),
        Err(_) => println!("wrong seq correctly rejected"),
    }
}
