// `rsfusa sign` — sign or verify files with HMAC-SHA256.
//fusa:req REQ-SIGN001
//fusa:req REQ-SIGN002
//fusa:req REQ-SIGN003

use crate::types::{EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::Write;

type HmacSha256 = Hmac<Sha256>;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.is_empty() {
        writeln!(
            stderr,
            "rsfusa sign: usage: rsfusa sign [--verify] [--keygen] --key <keyfile> <file>"
        )
        .ok();
        return EXIT_USAGE;
    }

    if args.iter().any(|a| a == "--keygen") {
        return cmd_keygen(args, stdout, stderr);
    }
    if args.iter().any(|a| a == "--verify") {
        return cmd_verify(args, stdout, stderr);
    }
    cmd_sign(args, stdout, stderr)
}

fn cmd_keygen(_args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    // Generate a 32-byte cryptographically-random signing key in-process.
    // A signing key of all zeros (or any predictable value) makes every
    // HMAC trivially forgeable, so on ANY failure to obtain real entropy we
    // MUST fail hard (write no key), never emit a placeholder.
    let key_path = "fusa.key";
    let key = match generate_key() {
        Ok(k) => k,
        Err(e) => {
            writeln!(
                stderr,
                "rsfusa sign keygen: unable to obtain secure entropy: {e}"
            )
            .ok();
            return EXIT_RUNTIME;
        }
    };
    if let Err(e) = std::fs::write(key_path, key) {
        writeln!(stderr, "rsfusa sign keygen: {e}").ok();
        return EXIT_RUNTIME;
    }
    writeln!(stdout, "Key written to {key_path}").ok();
    writeln!(
        stdout,
        "Keep this file secret and never commit it to source control."
    )
    .ok();
    EXIT_OK
}

/// Fills a 32-byte key from the OS CSPRNG (`/dev/urandom`) in-process.
/// Returns an error — rather than a predictable placeholder — if the entropy
/// source is unavailable or returns an obviously invalid (all-zero) key.
fn generate_key() -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")?;
    let mut key = [0u8; 32];
    f.read_exact(&mut key)?;
    if key.iter().all(|&b| b == 0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "entropy source returned an all-zero key",
        ));
    }
    Ok(key)
}

fn cmd_sign(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let key_path = match parse_flag(args, "--key") {
        Some(k) => k,
        None => {
            writeln!(stderr, "rsfusa sign: --key <keyfile> is required").ok();
            return EXIT_USAGE;
        }
    };
    let target = match args
        .iter()
        .find(|a| !a.starts_with("--") && a.as_str() != key_path)
    {
        Some(t) => t.clone(),
        None => {
            writeln!(stderr, "rsfusa sign: target file argument is required").ok();
            return EXIT_USAGE;
        }
    };

    let key = match std::fs::read(&key_path) {
        Ok(k) => k,
        Err(e) => {
            writeln!(stderr, "rsfusa sign: read key {key_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };
    let data = match std::fs::read(&target) {
        Ok(d) => d,
        Err(e) => {
            writeln!(stderr, "rsfusa sign: read {target}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key of any size");
    mac.update(&data);
    let result = mac.finalize().into_bytes();
    let sig_hex = hex::encode(result);

    let sig_path = format!("{target}.sig");
    match std::fs::write(&sig_path, sig_hex + "\n") {
        Ok(_) => {
            writeln!(stdout, "Signature written to {sig_path}").ok();
            EXIT_OK
        }
        Err(e) => {
            writeln!(stderr, "rsfusa sign: write {sig_path}: {e}").ok();
            EXIT_RUNTIME
        }
    }
}

fn cmd_verify(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let key_path = match parse_flag(args, "--key") {
        Some(k) => k,
        None => {
            writeln!(stderr, "rsfusa sign --verify: --key <keyfile> is required").ok();
            return EXIT_USAGE;
        }
    };
    let target = match args
        .iter()
        .find(|a| !a.starts_with("--") && a.as_str() != key_path)
    {
        Some(t) => t.clone(),
        None => {
            writeln!(
                stderr,
                "rsfusa sign --verify: target file argument is required"
            )
            .ok();
            return EXIT_USAGE;
        }
    };

    let key = match std::fs::read(&key_path) {
        Ok(k) => k,
        Err(e) => {
            writeln!(stderr, "rsfusa sign --verify: read key {key_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };
    let data = match std::fs::read(&target) {
        Ok(d) => d,
        Err(e) => {
            writeln!(stderr, "rsfusa sign --verify: read {target}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let sig_path = format!("{target}.sig");
    let sig_hex = match std::fs::read_to_string(&sig_path) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            writeln!(
                stderr,
                "rsfusa sign --verify: read signature {sig_path}: {e}"
            )
            .ok();
            return EXIT_RUNTIME;
        }
    };

    let expected_bytes = match hex::decode(&sig_hex) {
        Ok(b) => b,
        Err(_) => {
            writeln!(
                stderr,
                "rsfusa sign --verify: invalid signature format in {sig_path}"
            )
            .ok();
            return EXIT_RUNTIME;
        }
    };

    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC key");
    mac.update(&data);

    match mac.verify_slice(&expected_bytes) {
        Ok(()) => {
            writeln!(stdout, "Signature VALID: {target}").ok();
            EXIT_OK
        }
        Err(_) => {
            writeln!(stderr, "Signature INVALID: {target}").ok();
            EXIT_GATE_FAIL
        }
    }
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    let prefix = format!("{flag}=");
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(v) = args[i].strip_prefix(&prefix) {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // D001 regression: keygen MUST derive a real 32-byte CSPRNG key and never
    // fall back to a predictable all-zero placeholder.
    #[test]
    fn generate_key_produces_nonzero_32_bytes() {
        let key = generate_key().expect("/dev/urandom should be available in test env");
        assert_eq!(key.len(), 32);
        assert!(
            !key.iter().all(|&b| b == 0),
            "generated key must never be all zeros"
        );
    }
}
