#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = aegis_seal::scanner::shannon_entropy(data);
    let _ = aegis_seal::scanner::enforce_zero_trust_policy(data, None);
    let _ = aegis_seal::scanner::enforce_zero_trust_policy(data, Some(4.5));
});
