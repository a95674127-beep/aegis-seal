# Security Policy

Aegis-Seal is an open-source Rust verification crate maintained by a single
developer. Security reports are welcome and read personally by the
maintainer.

## Reporting a vulnerability

Report privately by email: **a95674127@gmail.com**

Please include a description of the issue, the component involved
(Ed25519 signing and key custody, the hash-chained audit ledger, the
secret/entropy scanner, or vault checkpoint verification), steps to
reproduce or a proof of concept, and the version or commit you tested
against.

Please do **not** open a public issue or post details publicly before
contacting the maintainer.

## What to expect

- **Acknowledgment:** within 5 business days. This is a solo-maintained
  project; every report is read by the maintainer personally.
- **Triage:** confirmed issues are fixed in priority order.
- **Disclosure:** coordinated disclosure is requested — please allow up to
  90 days for a fix before public disclosure. Reporters are credited in the
  release notes with their permission.

## Safe harbor

Good-faith security research conducted under this policy is authorized.
The maintainer will not pursue or support legal action against researchers
who, in good faith, test only against their own keys and files, avoid
privacy violations, data destruction, and service degradation, and give
the maintainer reasonable time to respond before disclosing.

## Scope

**In scope:** this repository's code — key generation and custody, signing
and verification, the audit ledger, the scanner, and checkpoint
verification.

**Out of scope:**

- Vulnerabilities in third-party dependencies — please report those
  upstream.
- Loss or theft of a key file. The key file **is** the credential by
  design; custody of it is the operator's responsibility, the same as any
  private key.
- Social engineering and physical attacks.

**Known design limits (documented, not vulnerabilities):** the audit
ledger's hash chain is unkeyed — tamper-evident, not tamper-proof. Tail
truncation and whole-chain rewrites are not detectable from the chain
alone; anchor the chain tip externally (signed checkpoints are the
intended mechanism; 0.4.0 also adds unsigned ledger checkpoints —
see `CHANGELOG.md`). The scanner is pattern-and-entropy heuristics, not a
proof that a file is secret-free. See `CHANGELOG.md` for the full
limitation list.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.0 | Yes |
| Earlier | Best effort |

— Allen Mack, AI Infinity Force One (sole proprietor)
