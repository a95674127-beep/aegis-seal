#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs
)]

//! # Aegis-Seal Core Library
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
