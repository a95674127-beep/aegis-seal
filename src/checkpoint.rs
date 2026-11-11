//! Independent verification of MACK vault chain-tip checkpoints
//! (Elevation B0, the "Twin Link").
//!
//! The vault (`ai-infinity-force-one-vault`, `src/vault/checkpoint.rs`)
//! signs its audit ledger's chain tip at explicit checkpoints. This
//! module is the *other side* of that link: given only the public
//! values a checkpoint prints — the signer's public key, the sequence
//! count, the head hash, and the signature — it reconstructs the
//! signed message byte-for-byte and verifies the Ed25519 signature,
//! without the vault, its database, or the signing key being present.
//!
//! The byte layout is reproduced exactly from the vault's
//! `checkpoint_message` and must never drift from it:
//! `"mack-checkpoint-v1"` (18 ASCII bytes) ‖ `seq` as 8 bytes,
//! big-endian ‖ the head hash as its UTF-8 (hex string) bytes.

use crate::crypto::verify_signature;
use crate::AegisError;

/// Domain separator prefixed to every vault checkpoint message, so a
/// checkpoint signature can never be replayed as a signature over any
/// other payload shape. Byte-identical to the vault's
/// `CHECKPOINT_DOMAIN`.
pub const CHECKPOINT_DOMAIN: &[u8] = b"mack-checkpoint-v1";

/// Reconstructs the exact byte string the vault signs for a
/// checkpoint: domain separator ‖ `seq` (8 bytes, big-endian) ‖
/// `head_hash` as UTF-8 bytes.
pub fn checkpoint_message(seq: u64, head_hash: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + 8 + head_hash.len());
    msg.extend_from_slice(CHECKPOINT_DOMAIN);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(head_hash.as_bytes());
    msg
}

/// Verifies a vault checkpoint signature against the signer's public
/// key and the checkpoint's recorded `(seq, head_hash)`. This proves
/// the holder of the checkpoint key attested that the ledger had
/// `seq` entries ending at `head_hash`; it says nothing about entries
/// appended after the checkpoint.
pub fn verify_checkpoint(
    public_key_hex: &str,
    seq: u64,
    head_hash: &str,
    signature_hex: &str,
) -> Result<(), AegisError> {
    verify_signature(
        public_key_hex,
        signature_hex,
        &checkpoint_message(seq, head_hash),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-good vector produced by the VAULT's own signing code
    // (ai-infinity-force-one-vault `CheckpointSigner::sign_checkpoint`,
    // src/vault/checkpoint.rs), generated 2026-11-11 with the vault
    // crate's test seed [7u8; 32], seq 5, and the head hash below
    // (the SHA-256 of the empty string, used as an opaque head-hash
    // string). If the vault's message layout ever changes, this
    // vector must be regenerated — that is the point of pinning it.
    const VECTOR_PUBKEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const VECTOR_SEQ: u64 = 5;
    const VECTOR_HEAD_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const VECTOR_SIGNATURE: &str =
        "80a73edcc5624f8cb6cdb5b8783ee4a5cf7ec738eb46542ecbf0c7dfc1a947a\
        ad50ad5f609aed8cb64dc68f8873a0a77547e321b2b9a9079e903db4405f72d01";

    #[test]
    fn message_layout_matches_vault_scheme() {
        let msg = checkpoint_message(VECTOR_SEQ, VECTOR_HEAD_HASH);
        assert_eq!(msg.len(), 18 + 8 + VECTOR_HEAD_HASH.len());
        assert!(msg.starts_with(CHECKPOINT_DOMAIN));
        let seq_bytes = msg.get(18..26).map(|s| s.to_vec());
        assert_eq!(seq_bytes, Some(VECTOR_SEQ.to_be_bytes().to_vec()));
        let head_bytes = msg.get(26..).map(|s| s.to_vec());
        assert_eq!(head_bytes, Some(VECTOR_HEAD_HASH.as_bytes().to_vec()));
    }

    #[test]
    fn vault_checkpoint_vector_verifies() {
        assert!(verify_checkpoint(
            VECTOR_PUBKEY,
            VECTOR_SEQ,
            VECTOR_HEAD_HASH,
            VECTOR_SIGNATURE
        )
        .is_ok());
    }

    #[test]
    fn wrong_signature_rejected() {
        // Flip the first hex character of the genuine signature.
        let mut sig = VECTOR_SIGNATURE.as_bytes().to_vec();
        if let Some(first) = sig.first_mut() {
            *first = if *first == b'0' { b'1' } else { b'0' };
        }
        let bad_sig = String::from_utf8(sig).unwrap_or_default();
        assert!(verify_checkpoint(VECTOR_PUBKEY, VECTOR_SEQ, VECTOR_HEAD_HASH, &bad_sig).is_err());
    }

    #[test]
    fn wrong_seq_rejected() {
        assert!(verify_checkpoint(
            VECTOR_PUBKEY,
            VECTOR_SEQ + 1,
            VECTOR_HEAD_HASH,
            VECTOR_SIGNATURE
        )
        .is_err());
    }

    #[test]
    fn wrong_head_hash_rejected() {
        let other_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856";
        assert!(
            verify_checkpoint(VECTOR_PUBKEY, VECTOR_SEQ, other_hash, VECTOR_SIGNATURE).is_err()
        );
    }
}
