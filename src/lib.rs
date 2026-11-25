#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs
)]

//! # Aegis-Seal Core Library
//!
//! Ed25519 signing, a hash-chained audit ledger, and secret / entropy
//! scanning in safe Rust.
//!
//! - [`crypto`] — [`crypto::SealedSigningKey`] (memory-scrubbed
//!   Ed25519 keys with file custody), [`crypto::verify_signature`],
//!   SHA-256 hashing ([`crypto::hash_bytes`],
//!   [`crypto::hash_file_streaming`]), and constant-time digest
//!   comparison.
//! - [`ledger`] — [`ledger::AuditLedger`], an append-only SHA-256
//!   hash chain whose [`ledger::AuditLedger::verify`] detects edits,
//!   plus external [`ledger::LedgerCheckpoint`] values that also
//!   detect tail truncation and whole-chain rewrites.
//! - [`checkpoint`] — independent verification of MACK vault
//!   chain-tip checkpoints from their four public values alone.
//! - [`scanner`] — zero-trust policy scanning
//!   ([`scanner::enforce_zero_trust_policy`]) that rejects known
//!   credential patterns and high-entropy windows.
//!
//! All fallible operations return [`AegisError`].
//!
//! # Example
//!
//! ```
//! use aegis_seal::ledger::{AuditLedger, CheckpointVerdict};
//!
//! let mut ledger = AuditLedger::new();
//! ledger.append(b"first event");
//! ledger.append(b"second event");
//! assert_eq!(ledger.verify(), Ok(()));
//!
//! let checkpoint = ledger.checkpoint();
//! ledger.append(b"third event");
//! // Growth after a checkpoint is not tampering.
//! assert_eq!(
//!     ledger.verify_checkpoint(&checkpoint),
//!     CheckpointVerdict::Match
//! );
//! ```
/// Independent verification of MACK vault chain-tip checkpoints.
pub mod checkpoint;
/// Ed25519 signing keys, SHA-256 hashing, and signature verification.
pub mod crypto;
/// Hash-chained, tamper-evident audit ledger.
pub mod ledger;
/// Secret-pattern and entropy scanning for zero-trust policy enforcement.
pub mod scanner;

use thiserror::Error;

/// Unified error type for all Aegis-Seal operations.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum AegisError {
    /// Cryptographic signature or key parsing failed.
    #[error("Cryptographic verification failure")]
    CryptoFailure,
    /// Input exceeded strict memory safety bounds.
    #[error("Input exceeds maximum allowed safety bound")]
    InputBoundExceeded,
    /// Policy violation detected.
    #[error("Security policy violation: {0}")]
    PolicyViolation(String),
    /// Audit ledger integrity check failed.
    #[error("Ledger tamper detected at sequence {0}: {1}")]
    LedgerTamper(u64, String),
    /// Serialization or I/O error.
    #[error("Storage or format error: {0}")]
    StorageError(String),
}
