# Aegis-Seal

A small, hardened Rust library and CLI for sealing and verifying records:

- **Ed25519 signing** — memory-scrubbed signing keys (`zeroize`), sign and
  verify messages, streaming SHA-256 file hashing, constant-time digest
  comparison.
- **Hash-chained audit ledger** — append-only entries linked by SHA-256;
  modification, deletion, or reordering of a recorded entry is detected by
  `verify()` and reported as a tamper error with the sequence number.
- **Secret / entropy scanner** — rejects known credential patterns (private
  key headers, cloud and token prefixes) and high-entropy windows that look
  like embedded secrets, under a zero-trust policy check.

The library forbids `unsafe` code and denies `unwrap` / `expect` / `panic`
in library code via clippy lints.

## Status

v0.1 scaffold — initial working implementation, not yet independently
reviewed and not production-audited. Local verification at first push:
`cargo build --release`, `cargo test` (**9 passed, 0 failed**),
`cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` all
clean on the author workstation.

## CLI

```
aegis-seal keygen
aegis-seal sign <private_key_hex> <message>
aegis-seal verify <public_key_hex> <signature_hex> <message>
aegis-seal hash <file>
aegis-seal scan <file>
```

## Provenance

Built from Allen Mack's design (AI Infinity Force One) with AI assistance,
which is disclosed here rather than hidden. The signing, ledger, and
scanner modules start from that design; the ledger module and CLI were
written to complete the scaffold at v0.1.
