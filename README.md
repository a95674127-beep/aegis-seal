# Aegis-Seal

A small, hardened Rust library and CLI for sealing and verifying records:

- **Ed25519 signing** — memory-scrubbed signing keys (`zeroize`), sign and
  verify messages, streaming SHA-256 file hashing, constant-time digest
  comparison.
- **Hash-chained audit ledger** — append-only entries linked by SHA-256;
  modification, deletion, or reordering of a recorded entry is detected by
  `verify()` and reported as a tamper error with the sequence number.
  External checkpoints (see "Ledger checkpoints" below) add detection of
  tail truncation and whole-chain rewrites.
- **Secret / entropy scanner** — rejects known credential patterns (private
  key headers, cloud and token prefixes) and high-entropy windows that look
  like embedded secrets, under a zero-trust policy check.

The library forbids `unsafe` code and denies `unwrap` / `expect` / `panic`
in library code via clippy lints.

## Status

v0.4.0 — adds external checkpoints for the crate's own ledger chain
(see "Ledger checkpoints" below); v0.3.0 added independent
verification of MACK vault checkpoints; v0.2.0 hardened key custody.
Working implementation, not yet independently reviewed and not
production-audited. Local verification at the v0.4.0 build:
`cargo test` (**26 unit tests + 1 doctest passed, 0 failed**),
`cargo fmt --check`, `cargo build --examples`, and
`cargo clippy --all-targets -- -D warnings` all clean, plus (at
v0.3.0) a live cross-check: a checkpoint block printed by the
vault's `twin_demo` example verified with `verify-checkpoint`, and
a one-character signature change was rejected.

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

## Library usage

Add the crate as a dependency and use the four modules directly.
Every fallible operation returns `AegisError`.

```rust
use aegis_seal::crypto::{verify_signature, SealedSigningKey};
use aegis_seal::ledger::AuditLedger;
use aegis_seal::scanner::enforce_zero_trust_policy;

// Sign and verify (in-memory key; see "Key custody" for files).
let (key, _verifying_key) = SealedSigningKey::generate();
let signature = key.sign(b"hello");
assert!(verify_signature(&key.public_key_hex(), &signature, b"hello").is_ok());

// Hash-chained ledger.
let mut ledger = AuditLedger::new();
ledger.append(b"first event");
assert_eq!(ledger.verify(), Ok(()));

// Zero-trust policy scan (returns overall entropy on success).
assert!(enforce_zero_trust_policy(b"ordinary config text", None).is_ok());
```

### Public API overview

| Area | Items |
| --- | --- |
| Errors | `AegisError` (`CryptoFailure`, `InputBoundExceeded`, `PolicyViolation`, `LedgerTamper`, `StorageError`) |
| Signing (`crypto`) | `SealedSigningKey` (`generate`, `from_seed`, `save_to_file`, `load_from_file`, `verifying_key`, `public_key_hex`, `public_key_fingerprint`, `sign`), `verify_signature` |
| Hashing (`crypto`) | `hash_bytes`, `hash_file_streaming`, `constant_time_digest_eq`, `MAX_INSPECT_BYTES` |
| Ledger (`ledger`) | `AuditLedger` (`new`, `append`, `entries`, `verify`, `checkpoint`, `verify_checkpoint`), `LedgerEntry`, `LedgerCheckpoint` (`to_json`, `from_json`), `CheckpointVerdict` (`Match`, `Truncated`, `Rewritten`, `ChainInvalid`) |
| Vault checkpoints (`checkpoint`) | `verify_checkpoint`, `checkpoint_message`, `CHECKPOINT_DOMAIN` |
| Scanner (`scanner`) | `enforce_zero_trust_policy`, `shannon_entropy`, `DEFAULT_MAX_ENTROPY` |

Full rustdoc: `cargo doc --open`.

## Examples

Runnable examples live in `examples/` — each covers one area of the
public API and is built by `cargo build --examples`:

```
cargo run --example sign_and_verify    # SealedSigningKey, verify_signature, hash_bytes
cargo run --example audit_ledger       # AuditLedger, LedgerCheckpoint JSON, CheckpointVerdict
cargo run --example verify_checkpoint  # vault checkpoint vector, checkpoint_message
cargo run --example policy_scan        # enforce_zero_trust_policy, shannon_entropy
```

## CLI

```
aegis-seal keygen [--key <path>]
aegis-seal sign [--key <path>] <message>
aegis-seal verify <public_key_hex> <signature_hex> <message>
aegis-seal verify-checkpoint --pubkey <hex> --seq <n> --head-hash <hex> --signature <hex>
aegis-seal hash <file>
aegis-seal scan <file>
```

## Vault checkpoint verification (Twin Link)

`verify-checkpoint` checks an Ed25519 checkpoint signature produced
by the MACK vault (AI Infinity Force One, Elevation B0) completely
independently — no vault code, no ledger database, and no signing key
involved, only the four public values a checkpoint prints. It
reconstructs the vault's signed message byte-for-byte
(`"mack-checkpoint-v1"` ‖ seq as 8-byte big-endian ‖ head hash) and
prints `checkpoint signature valid` (exit 0) or fails nonzero. A test
vector generated by the vault's own signing code is pinned in
`src/checkpoint.rs`, so any future drift between the two
implementations fails this crate's tests.

## Ledger checkpoints

The ledger's hash chain is unkeyed: it detects edits inside the
chain, but on its own it cannot detect entries cut off the tail or
a whole-chain rewrite — both leave a chain that still verifies (see
the limitation list in `CHANGELOG.md`). `AuditLedger::checkpoint()`
closes that gap the same way the vault's signed checkpoints do: it
exports the chain's length and tip hash as a small JSON value
(`{"length":<n>,"tip":"<hex>"}`), and
`AuditLedger::verify_checkpoint()` later compares a chain against a
saved checkpoint and reports `Match`, `Truncated`, `Rewritten`, or
`ChainInvalid`. Entries appended after the checkpoint count as
growth, not tampering.

The honesty condition, stated plainly: **a checkpoint only helps if
it is stored somewhere an attacker cannot rewrite it along with the
chain** — another machine, a signed message, a printed record. A
checkpoint kept next to the chain, editable by whoever rewrites the
chain, anchors nothing.

## Provenance

Built from Allen Mack's design (AI Infinity Force One) with AI assistance,
which is disclosed here rather than hidden. The signing, ledger, and
scanner modules start from that design; the ledger module and CLI were
written to complete the scaffold at v0.1.
