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

v0.2.0 — key custody hardened (see below). Working implementation, not yet
independently reviewed and not production-audited. Local verification at
the v0.2 push: `cargo build --release`, `cargo test` (**13 passed,
0 failed**), `cargo fmt --check`, and
`cargo clippy --all-targets -- -D warnings` all clean on the author
workstation, plus a CLI smoke test of the keygen → sign → verify flow.

## Key custody

The signing key is a 32-byte seed in a **key file** — by default
`./aegis-key.bin`, or wherever `--key <path>` points.

- `keygen` creates the file **owner-only (0600 on Unix)** and refuses to
  overwrite an existing key.
- The private key is **never printed and has no text export**. (v0.1
  printed the private key as hex at keygen; v0.2 removed that API
  entirely.) The only key material ever displayed is the **public key
  hex** and its short fingerprint.
- **The key file is the credential.** Back it up offline like one.
  Whoever holds the file can sign as this notary; losing the file loses
  the notary identity — there is no recovery and no export to fall back
  on by design.

## CLI

```
aegis-seal keygen [--key <path>]
aegis-seal sign [--key <path>] <message>
aegis-seal verify <public_key_hex> <signature_hex> <message>
aegis-seal hash <file>
aegis-seal scan <file>
```

## Provenance

Built from Allen Mack's design (AI Infinity Force One) with AI assistance,
which is disclosed here rather than hidden. The signing, ledger, and
scanner modules start from that design; the ledger module and CLI were
written to complete the scaffold at v0.1.
