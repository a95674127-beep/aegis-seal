use crate::crypto::hash_bytes;
use crate::AegisError;

/// A single entry in the hash-chained audit ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// Position of this entry in the chain (0-based).
    pub seq: u64,
    /// Chain hash of the previous entry (all zero for the genesis entry).
    pub prev_hash: [u8; 32],
    /// SHA-256 hash of the payload recorded by this entry.
    pub payload_hash: [u8; 32],
    /// Hash linking this entry to its sequence, predecessor, and payload.
    pub chain_hash: [u8; 32],
}

fn compute_chain_hash(seq: u64, prev_hash: &[u8; 32], payload_hash: &[u8; 32]) -> [u8; 32] {
    let mut material = Vec::with_capacity(72);
    material.extend_from_slice(&seq.to_be_bytes());
    material.extend_from_slice(prev_hash);
    material.extend_from_slice(payload_hash);
    hash_bytes(&material)
}

/// Append-only audit ledger whose entries form a SHA-256 hash chain.
///
/// Any modification, deletion, or reordering of a recorded entry breaks
/// the chain and is reported by [`AuditLedger::verify`] as
/// [`AegisError::LedgerTamper`].
#[derive(Debug, Default)]
pub struct AuditLedger {
    entries: Vec<LedgerEntry>,
}

impl AuditLedger {
    /// Creates an empty ledger.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends a payload to the ledger and returns the stored entry.
    pub fn append(&mut self, payload: &[u8]) -> LedgerEntry {
        let seq = self.entries.len() as u64;
        let prev_hash = self.entries.last().map_or([0u8; 32], |e| e.chain_hash);
        let payload_hash = hash_bytes(payload);
        let chain_hash = compute_chain_hash(seq, &prev_hash, &payload_hash);
        let entry = LedgerEntry {
            seq,
            prev_hash,
            payload_hash,
            chain_hash,
        };
        self.entries.push(entry.clone());
        entry
    }

    /// Returns all entries in append order.
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// Verifies the full chain: sequence order, previous-hash links, and
    /// every entry's chain hash.
    pub fn verify(&self) -> Result<(), AegisError> {
        let mut prev_hash = [0u8; 32];
        for (index, entry) in self.entries.iter().enumerate() {
            let expected_seq = index as u64;
            if entry.seq != expected_seq {
                return Err(AegisError::LedgerTamper(
                    entry.seq,
                    format!("sequence mismatch: expected {expected_seq}"),
                ));
            }
            if entry.prev_hash != prev_hash {
                return Err(AegisError::LedgerTamper(
                    entry.seq,
                    "previous-hash link broken".to_string(),
                ));
            }
            let expected_chain =
                compute_chain_hash(entry.seq, &entry.prev_hash, &entry.payload_hash);
            if entry.chain_hash != expected_chain {
                return Err(AegisError::LedgerTamper(
                    entry.seq,
                    "chain hash mismatch".to_string(),
                ));
            }
            prev_hash = entry.chain_hash;
        }
        Ok(())
    }

    /// Exports an external checkpoint of the chain's current state:
    /// the entry count and the tip's chain hash. See
    /// [`LedgerCheckpoint`] for how the value is stored and used.
    pub fn checkpoint(&self) -> LedgerCheckpoint {
        LedgerCheckpoint {
            length: self.entries.len() as u64,
            tip: self.entries.last().map_or([0u8; 32], |e| e.chain_hash),
        }
    }

    /// Checks this ledger against a checkpoint taken earlier with
    /// [`AuditLedger::checkpoint`].
    ///
    /// The chain is verified on its own first: a chain that fails
    /// [`AuditLedger::verify`] reports
    /// [`CheckpointVerdict::ChainInvalid`]. Otherwise the checkpointed
    /// prefix is compared — a chain now shorter than the checkpoint
    /// reports [`CheckpointVerdict::Truncated`], and a different chain
    /// hash at the checkpoint's length reports
    /// [`CheckpointVerdict::Rewritten`]. An unchanged prefix reports
    /// [`CheckpointVerdict::Match`], including when entries were
    /// appended after the checkpoint: growth is not tampering.
    pub fn verify_checkpoint(&self, checkpoint: &LedgerCheckpoint) -> CheckpointVerdict {
        if self.verify().is_err() {
            return CheckpointVerdict::ChainInvalid;
        }
        if (self.entries.len() as u64) < checkpoint.length {
            return CheckpointVerdict::Truncated;
        }
        if checkpoint.length == 0 {
            return CheckpointVerdict::Match;
        }
        // The length check above guarantees this index exists.
        let index = (checkpoint.length - 1) as usize;
        match self.entries.get(index) {
            Some(entry) if entry.chain_hash == checkpoint.tip => CheckpointVerdict::Match,
            Some(_) => CheckpointVerdict::Rewritten,
            None => CheckpointVerdict::Truncated,
        }
    }
}

/// An external checkpoint of the ledger chain: how many entries the
/// chain held, and the chain hash of its tip at that moment.
///
/// The hash chain alone cannot detect tail truncation or a
/// whole-chain rewrite — both leave a shorter or recomputed chain
/// that still passes [`AuditLedger::verify`]. Saving the value
/// returned by [`AuditLedger::checkpoint`] and later passing it to
/// [`AuditLedger::verify_checkpoint`] makes both attacks detectable.
///
/// A checkpoint only helps if it is stored somewhere an attacker
/// cannot rewrite it along with the chain — another machine, a
/// signed message, a printed record. A checkpoint kept next to the
/// chain, editable by whoever rewrites the chain, anchors nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerCheckpoint {
    /// Number of entries in the chain when the checkpoint was taken.
    pub length: u64,
    /// Chain hash of the last entry at checkpoint time; all zero for
    /// an empty chain.
    pub tip: [u8; 32],
}

impl LedgerCheckpoint {
    /// Serializes the checkpoint as a small JSON object:
    /// `{"length":<count>,"tip":"<64 lowercase hex characters>"}`.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"length\":{},\"tip\":\"{}\"}}",
            self.length,
            hex::encode(self.tip)
        )
    }

    /// Parses a checkpoint produced by [`LedgerCheckpoint::to_json`].
    /// Field order and insignificant whitespace are tolerated;
    /// anything malformed is rejected with
    /// [`AegisError::StorageError`].
    pub fn from_json(text: &str) -> Result<Self, AegisError> {
        let body = text
            .trim()
            .strip_prefix('{')
            .and_then(|t| t.strip_suffix('}'))
            .ok_or_else(|| {
                AegisError::StorageError("checkpoint JSON must be an object".to_string())
            })?;
        let mut length: Option<u64> = None;
        let mut tip: Option<[u8; 32]> = None;
        for field in body.split(',') {
            let (key, value) = field.split_once(':').ok_or_else(|| {
                AegisError::StorageError("malformed checkpoint field".to_string())
            })?;
            match key.trim().trim_matches('"') {
                "length" => {
                    length = Some(value.trim().parse::<u64>().map_err(|_| {
                        AegisError::StorageError(
                            "checkpoint length is not a valid count".to_string(),
                        )
                    })?);
                }
                "tip" => {
                    let bytes = hex::decode(value.trim().trim_matches('"')).map_err(|_| {
                        AegisError::StorageError("checkpoint tip is not valid hex".to_string())
                    })?;
                    tip = Some(bytes.try_into().map_err(|_| {
                        AegisError::StorageError("checkpoint tip must be 32 bytes".to_string())
                    })?);
                }
                other => {
                    return Err(AegisError::StorageError(format!(
                        "unknown checkpoint field: {other}"
                    )));
                }
            }
        }
        match (length, tip) {
            (Some(length), Some(tip)) => Ok(Self { length, tip }),
            _ => Err(AegisError::StorageError(
                "checkpoint JSON must contain length and tip".to_string(),
            )),
        }
    }
}

/// Outcome of checking a ledger against a previously saved
/// [`LedgerCheckpoint`], as reported by
/// [`AuditLedger::verify_checkpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointVerdict {
    /// The checkpointed prefix is present and unchanged. Entries
    /// appended after the checkpoint are growth, not tampering.
    Match,
    /// The chain is now shorter than the checkpoint recorded:
    /// entries were truncated from the tail.
    Truncated,
    /// The entry at the checkpoint's length has a different chain
    /// hash than the checkpoint recorded: the chain was rewritten.
    Rewritten,
    /// The chain fails its own internal verification
    /// ([`AuditLedger::verify`]).
    ChainInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_verify_ok() {
        let mut ledger = AuditLedger::new();
        ledger.append(b"first event");
        ledger.append(b"second event");
        ledger.append(b"third event");
        assert_eq!(ledger.entries().len(), 3);
        assert_eq!(ledger.verify(), Ok(()));
    }

    #[test]
    fn empty_ledger_verifies() {
        let ledger = AuditLedger::new();
        assert_eq!(ledger.verify(), Ok(()));
    }

    #[test]
    fn tampered_payload_hash_is_detected() {
        let mut ledger = AuditLedger::new();
        ledger.append(b"genuine event");
        ledger.append(b"second event");
        if let Some(entry) = ledger.entries.first_mut() {
            entry.payload_hash = hash_bytes(b"forged event");
        }
        assert!(matches!(
            ledger.verify(),
            Err(AegisError::LedgerTamper(0, _))
        ));
    }

    #[test]
    fn reordered_entries_are_detected() {
        let mut ledger = AuditLedger::new();
        ledger.append(b"first event");
        ledger.append(b"second event");
        ledger.entries.swap(0, 1);
        assert!(matches!(
            ledger.verify(),
            Err(AegisError::LedgerTamper(_, _))
        ));
    }

    #[test]
    fn checkpoint_matches_unchanged_chain() {
        let mut ledger = AuditLedger::new();
        ledger.append(b"first event");
        ledger.append(b"second event");
        ledger.append(b"third event");
        let checkpoint = ledger.checkpoint();
        assert_eq!(checkpoint.length, 3);
        assert_eq!(
            ledger.verify_checkpoint(&checkpoint),
            CheckpointVerdict::Match
        );
    }

    #[test]
    fn checkpoint_allows_growth_after_checkpoint() {
        let mut ledger = AuditLedger::new();
        ledger.append(b"first event");
        ledger.append(b"second event");
        let checkpoint = ledger.checkpoint();
        ledger.append(b"third event");
        ledger.append(b"fourth event");
        assert_eq!(
            ledger.verify_checkpoint(&checkpoint),
            CheckpointVerdict::Match
        );
    }

    #[test]
    fn checkpoint_detects_tail_truncation() {
        let mut ledger = AuditLedger::new();
        for payload in ["one", "two", "three", "four", "five"] {
            ledger.append(payload.as_bytes());
        }
        let checkpoint = ledger.checkpoint();
        // The documented limitation: cutting entries off the tail
        // leaves a shorter chain that still verifies on its own.
        ledger.entries.truncate(3);
        assert_eq!(ledger.verify(), Ok(()));
        // Against the saved checkpoint, the same chain is caught.
        assert_eq!(
            ledger.verify_checkpoint(&checkpoint),
            CheckpointVerdict::Truncated
        );
    }

    #[test]
    fn checkpoint_detects_whole_chain_rewrite() {
        let mut ledger = AuditLedger::new();
        ledger.append(b"genuine one");
        ledger.append(b"genuine two");
        ledger.append(b"genuine three");
        let checkpoint = ledger.checkpoint();
        // An attacker who replaces every payload and recomputes the
        // whole chain produces a chain that verifies on its own...
        let mut rewritten = AuditLedger::new();
        rewritten.append(b"forged one");
        rewritten.append(b"forged two");
        rewritten.append(b"forged three");
        assert_eq!(rewritten.verify(), Ok(()));
        // ...but its tip at the checkpoint's length is not the tip
        // the checkpoint recorded.
        assert_eq!(
            rewritten.verify_checkpoint(&checkpoint),
            CheckpointVerdict::Rewritten
        );
    }

    #[test]
    fn checkpoint_reports_internally_invalid_chain() {
        let mut ledger = AuditLedger::new();
        ledger.append(b"genuine event");
        ledger.append(b"second event");
        let checkpoint = ledger.checkpoint();
        if let Some(entry) = ledger.entries.first_mut() {
            entry.payload_hash = hash_bytes(b"forged event");
        }
        assert_eq!(
            ledger.verify_checkpoint(&checkpoint),
            CheckpointVerdict::ChainInvalid
        );
    }

    #[test]
    fn checkpoint_of_empty_ledger() {
        let mut ledger = AuditLedger::new();
        let checkpoint = ledger.checkpoint();
        assert_eq!(checkpoint.length, 0);
        assert_eq!(checkpoint.tip, [0u8; 32]);
        assert_eq!(
            ledger.verify_checkpoint(&checkpoint),
            CheckpointVerdict::Match
        );
        ledger.append(b"first event");
        assert_eq!(
            ledger.verify_checkpoint(&checkpoint),
            CheckpointVerdict::Match
        );
    }

    #[test]
    fn checkpoint_json_round_trip() {
        let mut ledger = AuditLedger::new();
        ledger.append(b"first event");
        ledger.append(b"second event");
        let checkpoint = ledger.checkpoint();
        let json = checkpoint.to_json();
        assert_eq!(LedgerCheckpoint::from_json(&json), Ok(checkpoint));
    }

    #[test]
    fn checkpoint_json_rejects_malformed_input() {
        assert!(LedgerCheckpoint::from_json("not json").is_err());
        assert!(LedgerCheckpoint::from_json("{}").is_err());
        assert!(LedgerCheckpoint::from_json("{\"length\":2}").is_err());
        let zero_tip = "00".repeat(32);
        let negative = format!("{{\"length\":-1,\"tip\":\"{zero_tip}\"}}");
        assert!(LedgerCheckpoint::from_json(&negative).is_err());
        assert!(LedgerCheckpoint::from_json("{\"length\":1,\"tip\":\"00\"}").is_err());
        assert!(LedgerCheckpoint::from_json("{\"length\":1,\"tip\":\"zz\"}").is_err());
    }
}
