//! Sign a message with an in-memory key and verify the signature.
//!
//! Run with: `cargo run --example sign_and_verify`
//!
//! This uses [`SealedSigningKey::generate`] so no key file is touched.
//! For on-disk custody see `SealedSigningKey::save_to_file` /
//! `SealedSigningKey::load_from_file` (the CLI `keygen` / `sign`
//! commands use those).

use aegis_seal::crypto::{constant_time_digest_eq, hash_bytes, verify_signature, SealedSigningKey};

fn main() {
    let (key, _verifying_key) = SealedSigningKey::generate();

    println!("public_key_hex: {}", key.public_key_hex());
    println!("fingerprint:    {}", key.public_key_fingerprint());

    let message = b"release v0.4.0 approved";
    let signature = key.sign(message);
    println!("signature_hex:  {signature}");

    match verify_signature(&key.public_key_hex(), &signature, message) {
        Ok(()) => println!("signature valid"),
        Err(e) => println!("signature rejected: {e}"),
    }

    // A different message must not verify under the same signature.
    match verify_signature(&key.public_key_hex(), &signature, b"tampered") {
        Ok(()) => println!("ERROR: tampered message verified"),
        Err(_) => println!("tampered message correctly rejected"),
    }

    // Hashing helpers: SHA-256 of bytes, compared in constant time.
    let digest_a = hash_bytes(b"payload");
    let digest_b = hash_bytes(b"payload");
    println!(
        "hash_bytes equal (constant-time): {}",
        constant_time_digest_eq(&digest_a, &digest_b)
    );
}
