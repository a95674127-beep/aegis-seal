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
}
