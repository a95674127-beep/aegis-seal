#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let seq = u64::from_be_bytes(data[0..8].try_into().unwrap_or([0; 8]));
    let rest = &data[8..];
    let pk_len = rest.len() / 3;
    let public_key_hex = hex::encode(&rest[..pk_len]);
    let signature_hex = hex::encode(&rest[pk_len..]);
    let head_hash = hex::encode(aegis_seal::crypto::hash_bytes(rest));
    let _ = aegis_seal::checkpoint::verify_checkpoint(&public_key_hex, seq, &head_hash, &signature_hex);
});
