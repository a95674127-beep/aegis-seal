use aegis_seal::crypto::{hash_file_streaming, verify_signature, SealedSigningKey};
use aegis_seal::scanner::enforce_zero_trust_policy;
use std::path::Path;
use std::process::ExitCode;

fn print_usage() {
    eprintln!("aegis-seal — Ed25519 signing, hash-chained ledger, secret/entropy scanner");
    eprintln!("usage:");
    eprintln!("  aegis-seal keygen");
    eprintln!("  aegis-seal sign <private_key_hex> <message>");
    eprintln!("  aegis-seal verify <public_key_hex> <signature_hex> <message>");
    eprintln!("  aegis-seal hash <file>");
    eprintln!("  aegis-seal scan <file>");
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn cmd_keygen() -> ExitCode {
    let (key, verifying_key) = SealedSigningKey::generate();
    println!("WARNING: the private key below is a SECRET. Store it offline; never share it.");
    println!("private_key_hex: {}", key.to_hex());
    println!("public_key_hex: {}", hex::encode(verifying_key.to_bytes()));
    ExitCode::SUCCESS
}

fn cmd_sign(private_key_hex: &str, message: &str) -> ExitCode {
    match SealedSigningKey::from_hex(private_key_hex) {
        Ok(key) => {
            println!("{}", key.sign(message.as_bytes()));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_verify(public_key_hex: &str, signature_hex: &str, message: &str) -> ExitCode {
    match verify_signature(public_key_hex, signature_hex, message.as_bytes()) {
        Ok(()) => {
            println!("signature valid");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_hash(file: &str) -> ExitCode {
    match hash_file_streaming(Path::new(file)) {
        Ok(digest) => {
            println!("{}", hex::encode(digest));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_scan(file: &str) -> ExitCode {
    let data = match std::fs::read(file) {
        Ok(bytes) => bytes,
        Err(e) => return fail(&e.to_string()),
    };
    match enforce_zero_trust_policy(&data, None) {
        Ok(entropy) => {
            println!("scan clean (overall entropy {entropy:.2} bits/byte)");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let first = args.first().map(String::as_str);
    match first {
        Some("keygen") if args.len() == 1 => cmd_keygen(),
        Some("sign") if args.len() == 3 => match (args.get(1), args.get(2)) {
            (Some(priv_hex), Some(message)) => cmd_sign(priv_hex, message),
            _ => fail("sign requires <private_key_hex> <message>"),
        },
        Some("verify") if args.len() == 4 => match (args.get(1), args.get(2), args.get(3)) {
            (Some(pub_hex), Some(sig_hex), Some(message)) => cmd_verify(pub_hex, sig_hex, message),
            _ => fail("verify requires <public_key_hex> <signature_hex> <message>"),
        },
        Some("hash") if args.len() == 2 => match args.get(1) {
            Some(file) => cmd_hash(file),
            None => fail("hash requires <file>"),
        },
        Some("scan") if args.len() == 2 => match args.get(1) {
            Some(file) => cmd_scan(file),
            None => fail("scan requires <file>"),
        },
        _ => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}
