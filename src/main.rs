use aegis_seal::crypto::{hash_file_streaming, verify_signature, SealedSigningKey};
use aegis_seal::scanner::enforce_zero_trust_policy;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Default location of the notary key file. The file IS the credential.
const DEFAULT_KEY_PATH: &str = "./aegis-key.bin";

fn print_usage() {
    eprintln!("aegis-seal — Ed25519 signing, hash-chained ledger, secret/entropy scanner");
    eprintln!("usage:");
    eprintln!("  aegis-seal keygen [--key <path>]");
    eprintln!("  aegis-seal sign [--key <path>] <message>");
    eprintln!("  aegis-seal verify <public_key_hex> <signature_hex> <message>");
    eprintln!("  aegis-seal hash <file>");
    eprintln!("  aegis-seal scan <file>");
    eprintln!("Key custody: keygen writes the 32-byte seed to the key file");
    eprintln!("(default {DEFAULT_KEY_PATH}, owner-only 0600 on Unix) and prints only");
    eprintln!("the public key. The private key is never printed or exported.");
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

/// Splits `[--key <path>] <positional...>` into the key path (default
/// [`DEFAULT_KEY_PATH`]) and the positional arguments, in order.
fn parse_key_option(args: &[String]) -> Result<(PathBuf, Vec<String>), String> {
    let mut key_path = PathBuf::from(DEFAULT_KEY_PATH);
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args.get(i).map(String::as_str) {
            Some("--key") => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--key requires a <path> value".to_string())?;
                key_path = PathBuf::from(value);
                i += 2;
            }
            Some(other) => {
                positional.push(other.to_string());
                i += 1;
            }
            None => break,
        }
    }
    Ok((key_path, positional))
}

fn cmd_keygen(key_path: &Path) -> ExitCode {
    if key_path.exists() {
        return fail(
            "key file already exists; refusing to overwrite an existing notary key \
             (pass --key <path> to create a different one)",
        );
    }
    let (key, _) = SealedSigningKey::generate();
    match key.save_to_file(key_path) {
        Ok(()) => {
            println!("key_file: {}", key_path.display());
            println!("public_key_hex: {}", key.public_key_hex());
            println!("fingerprint: {}", key.public_key_fingerprint());
            println!("The key file is the credential. Back it up offline;");
            println!("it is never printed or exported in text form.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn cmd_sign(key_path: &Path, message: &str) -> ExitCode {
    match SealedSigningKey::load_from_file(key_path) {
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
    let rest: Vec<String> = args.iter().skip(1).cloned().collect();
    match first {
        Some("keygen") => match parse_key_option(&rest) {
            Ok((key_path, positional)) if positional.is_empty() => cmd_keygen(&key_path),
            Ok(_) => fail("keygen takes no positional arguments"),
            Err(e) => fail(&e),
        },
        Some("sign") => match parse_key_option(&rest) {
            Ok((key_path, positional)) if positional.len() == 1 => match positional.first() {
                Some(message) => cmd_sign(&key_path, message),
                None => fail("sign requires <message>"),
            },
            Ok(_) => fail("sign requires exactly one <message>"),
            Err(e) => fail(&e),
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
