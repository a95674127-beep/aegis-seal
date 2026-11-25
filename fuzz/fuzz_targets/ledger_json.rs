#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(cp) = aegis_seal::ledger::LedgerCheckpoint::from_json(text) {
            let mut ledger = aegis_seal::ledger::AuditLedger::new();
            ledger.append(text.as_bytes());
            let _ = ledger.verify();
            let _ = ledger.verify_checkpoint(&cp);
        }
    }
});
