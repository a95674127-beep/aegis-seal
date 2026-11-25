//! Scan byte buffers with the zero-trust secret / entropy policy.
//!
//! Run with: `cargo run --example policy_scan`

use aegis_seal::scanner::{enforce_zero_trust_policy, shannon_entropy, DEFAULT_MAX_ENTROPY};

fn report(label: &str, data: &[u8]) {
    println!("{label}: entropy {:.2} bits/byte", shannon_entropy(data));
    match enforce_zero_trust_policy(data, None) {
        Ok(overall) => println!("  policy: clean (overall entropy {overall:.2})"),
        Err(e) => println!("  policy: rejected — {e}"),
    }
}

fn main() {
    println!("default max entropy: {DEFAULT_MAX_ENTROPY:.2} bits/byte");

    report(
        "clean config text",
        b"ordinary configuration text with nothing sensitive inside it",
    );

    // Known credential patterns are rejected regardless of entropy.
    report(
        "stripe-like key",
        b"config: key = sk_live_example_do_not_use",
    );
    report(
        "private key header",
        b"-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----",
    );
}
