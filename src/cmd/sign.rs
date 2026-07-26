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
    // Generate a 32-byte random key using /dev/urandom
    let key_path = "fusa.key";
    let output = std::process::Command::new("dd")
        .args([
            "if=/dev/urandom",
            &format!("of={key_path}"),
            "bs=32",
            "count=1",
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            writeln!(stdout, "Key written to {key_path}").ok();
            writeln!(
                stdout,
                "Keep this file secret and never commit it to source control."
            )
            .ok();
            EXIT_OK
        }
        _ => {
            // Fallback: write 32 zero bytes (not secure, warn user)
            writeln!(
                stderr,
                "rsfusa sign keygen: /dev/urandom not available; using placeholder key"
            )
            .ok();
            if let Err(e) = std::fs::write(key_path, [0u8; 32]) {
                writeln!(stderr, "rsfusa sign keygen: {e}").ok();
                return EXIT_RUNTIME;
            }
            EXIT_OK
        }
    }
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
