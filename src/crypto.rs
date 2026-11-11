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

    /// Reconstructs a `SealedSigningKey` from a raw 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            secret_bytes: *seed,
        }
    }

    /// Writes the key seed to `path` as a raw 32-byte file.
    ///
    /// The file **is** the credential. On Unix it is created owner-only
    /// (0600). Creation fails if the file already exists, so an existing
    /// notary key is never silently overwritten. The seed is never
    /// printed, logged, or exported in any text form — custody is the
    /// file itself.
    pub fn save_to_file(&self, path: &Path) -> Result<(), AegisError> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|e| AegisError::StorageError(e.to_string()))?;
        file.write_all(&self.secret_bytes)
            .map_err(|e| AegisError::StorageError(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| AegisError::StorageError(e.to_string()))?;
        }
        Ok(())
    }

    /// Loads a `SealedSigningKey` from a 32-byte seed file written by
    /// [`SealedSigningKey::save_to_file`]. Any other length is rejected.
    pub fn load_from_file(path: &Path) -> Result<Self, AegisError> {
        let mut bytes = std::fs::read(path).map_err(|e| AegisError::StorageError(e.to_string()))?;
        if bytes.len() != 32 {
            bytes.zeroize();
            return Err(AegisError::CryptoFailure);
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self { secret_bytes })
    }

    /// The public (verifying) half of this keypair.
    pub fn verifying_key(&self) -> VerifyingKey {
        SigningKey::from_bytes(&self.secret_bytes).verifying_key()
    }

    /// Hex encoding of the **public** key — the only key material this
    /// API ever exposes as text. The private key has no text export.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().to_bytes())
    }

    /// Short fingerprint of the public key (first 8 bytes of its
    /// SHA-256 digest, hex) for eyeball comparison between parties.
    pub fn public_key_fingerprint(&self) -> String {
        let digest = hash_bytes(&self.verifying_key().to_bytes());
        hex::encode(&digest[..8])
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_key_path(test_name: &str) -> std::path::PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aegis_key_test_{}_{}_{}",
            test_name,
            std::process::id(),
            id
        ));
        let _ = std::fs::create_dir_all(&p);
        p.push("key.bin");
        p
    }

    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    /// v0.2 key custody: keygen writes a key file; the key loaded back
    /// from that file is the same key (same public half) and its
    /// signatures verify — while the secret never appears as text.
    #[test]
    fn key_file_round_trip_signs_and_verifies() {
        let path = temp_key_path("round_trip");
        let (key, _) = SealedSigningKey::generate();
        let pub_hex = key.public_key_hex();
        assert_eq!(pub_hex.len(), 64);
        assert!(key.save_to_file(&path).is_ok());

        let loaded = SealedSigningKey::load_from_file(&path);
        assert!(loaded.is_ok());
        if let Ok(loaded) = loaded {
            assert_eq!(loaded.public_key_hex(), pub_hex);
            let signature = loaded.sign(b"twin link checkpoint");
            assert!(verify_signature(&pub_hex, &signature, b"twin link checkpoint").is_ok());
            assert!(verify_signature(&pub_hex, &signature, b"different message").is_err());
        }
        cleanup(&path);
    }

    /// The key file is a credential: it must be owner-only on Unix.
    #[cfg(unix)]
    #[test]
    fn key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_key_path("perms");
        let (key, _) = SealedSigningKey::generate();
        assert!(key.save_to_file(&path).is_ok());
        let mode = std::fs::metadata(&path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(mode, 0o600, "key file must be 0600");
        cleanup(&path);
    }

    /// A file that is not exactly one 32-byte seed is not a key.
    #[test]
    fn load_rejects_wrong_length_key_file() {
        let path = temp_key_path("bad_len");
        assert!(std::fs::write(&path, b"too short").is_ok());
        assert!(SealedSigningKey::load_from_file(&path).is_err());
        cleanup(&path);
    }

    /// Key generation must never clobber an existing notary key.
    #[test]
    fn save_refuses_to_overwrite_existing_key() {
        let path = temp_key_path("no_overwrite");
        let (key, _) = SealedSigningKey::generate();
        assert!(key.save_to_file(&path).is_ok());
        let (other, _) = SealedSigningKey::generate();
        assert!(other.save_to_file(&path).is_err());
        cleanup(&path);
    }
}
