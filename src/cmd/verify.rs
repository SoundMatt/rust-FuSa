// `rsfusa verify` — run cargo test and save test evidence bundle.

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;
use std::path::PathBuf;

pub const EVIDENCE_FILE: &str = ".fusa-evidence.json";

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    writeln!(stdout, "Running cargo test...").ok();

    let output = std::process::Command::new("cargo")
        .arg("test")
        .arg("--")
        .arg("--test-output=immediate")
        .current_dir(&project_root)
        .output();

    let (exit_code, raw_output) = match output {
        Ok(o) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            (o.status.code().unwrap_or(1), combined)
        }
        Err(e) => {
            writeln!(stderr, "rsfusa verify: failed to run cargo test: {e}").ok();
            writeln!(stderr, "rsfusa verify: ensure cargo is in PATH").ok();
            return EXIT_RUNTIME;
        }
    };

    let (passed, failed, ignored) = parse_test_summary(&raw_output);
    let total = passed + failed + ignored;

    let evidence = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "test-evidence",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "ignored": ignored,
        },
        "testRun": {
            "command": "cargo test",
            "exitCode": exit_code,
            "passed": exit_code == 0,
        }
    });

    let out_path = opts.output.unwrap_or_else(|| {
        project_root.join(EVIDENCE_FILE).to_string_lossy().into_owned()
    });

    match std::fs::write(&out_path, serde_json::to_string_pretty(&evidence).unwrap() + "\n") {
        Ok(_) => writeln!(stdout, "Evidence written to {out_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa verify: write {out_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    if exit_code != 0 {
        writeln!(stdout, "Tests FAILED: {failed} failed, {passed} passed").ok();
        return crate::types::EXIT_GATE_FAIL;
    }

    writeln!(stdout, "Tests PASSED: {total} total, {passed} passed, {ignored} ignored").ok();
    EXIT_OK
}

fn parse_test_summary(output: &str) -> (usize, usize, usize) {
    for line in output.lines().rev() {
        if line.contains("test result:") {
            let passed = extract_count(line, "passed");
            let failed = extract_count(line, "failed");
            let ignored = extract_count(line, "ignored");
            return (passed, failed, ignored);
        }
    }
    (0, 0, 0)
}

fn extract_count(line: &str, label: &str) -> usize {
    let pattern = format!(" {label}");
    if let Some(pos) = line.find(&pattern) {
        let before = &line[..pos];
        let num_str: String = before.chars().rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars().rev().collect();
        return num_str.parse().unwrap_or(0);
    }
    0
}

struct Opts {
    dir: Option<PathBuf>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts { dir: None, output: None };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa verify: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--output" => opts.output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--output=") { opts.output = Some(v.to_string()); }
                else {
                    writeln!(stderr, "rsfusa verify: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
