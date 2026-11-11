use crate::AegisError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum file size allowed for single-pass policy inspection (256 MiB).
pub const MAX_INSPECT_BYTES: u64 = 256 * 1024 * 1024;

/// Memory-scrubbed wrapper around an Ed25519 private signing key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SealedSigningKey {
    secret_bytes: [u8; 32],
}

impl SealedSigningKey {
    /// Generates a new cryptographically secure Ed25519 keypair from OS entropy.
    pub fn generate() -> (Self, VerifyingKey) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let secret_bytes = signing_key.to_bytes();
        (Self { secret_bytes }, verifying_key)
    }

    /// Reconstructs a `SealedSigningKey` from a 64-character hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, AegisError> {
        let trimmed = hex_str.trim();
        let bytes = hex::decode(trimmed).map_err(|_| AegisError::CryptoFailure)?;
        if bytes.len() != 32 {
            return Err(AegisError::CryptoFailure);
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&bytes);
        Ok(Self { secret_bytes })
    }

    /// Exports the private key as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.secret_bytes)
    }

    /// Signs a canonical message payload using Ed25519.
    pub fn sign(&self, message: &[u8]) -> String {
        let signing_key = SigningKey::from_bytes(&self.secret_bytes);
        let sig: Signature = signing_key.sign(message);
        hex::encode(sig.to_bytes())
    }
}

/// Computes a streaming SHA-256 digest of a file.
pub fn hash_file_streaming(path: &Path) -> Result<[u8; 32], AegisError> {
    let file = File::open(path).map_err(|e| AegisError::StorageError(e.to_string()))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|e| AegisError::StorageError(e.to_string()))?;
        if count == 0 {
            break;
        }
        if let Some(slice) = buffer.get(..count) {
            hasher.update(slice);
        }
    }
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    Ok(digest)
}

/// Computes SHA-256 of an in-memory byte slice.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

/// Constant-time comparison of two 32-byte digests.
pub fn constant_time_digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Verifies an Ed25519 hex signature against a public key hex and canonical message.
pub fn verify_signature(
    public_key_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> Result<(), AegisError> {
    let pub_bytes = hex::decode(public_key_hex.trim()).map_err(|_| AegisError::CryptoFailure)?;
    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| AegisError::CryptoFailure)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pub_array).map_err(|_| AegisError::CryptoFailure)?;
    let sig_bytes = hex::decode(signature_hex.trim()).map_err(|_| AegisError::CryptoFailure)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AegisError::CryptoFailure)?;
    let signature = Signature::from_bytes(&sig_array);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| AegisError::CryptoFailure)
}
