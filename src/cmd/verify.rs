// `rsfusa verify` — run cargo test and save test evidence bundle.
//fusa:req REQ-VERIFY001
//fusa:req REQ-VERIFY002
//fusa:req REQ-VERIFY003
//fusa:req REQ-VERIFY004
//fusa:req REQ-VERIFY005

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;
use std::path::PathBuf;

pub const EVIDENCE_FILE: &str = ".fusa-evidence.json";

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    writeln!(stdout, "Running cargo test...").ok();

    let output = std::process::Command::new("cargo")
        .arg("test")
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

    let summary = parse_test_summary(&raw_output);

    // If cargo test exited non-zero but no "test result:" line was found in its
    // output, the test binaries never ran to completion (e.g. a rejected CLI
    // flag, a build failure, a panic before harness startup). That is not the
    // same thing as "0 tests failed" and must not be reported as such.
    if exit_code != 0 && summary.is_none() {
        writeln!(
            stderr,
            "rsfusa verify: cargo test exited {exit_code} without producing a \"test result:\" summary"
        )
        .ok();
        writeln!(
            stderr,
            "rsfusa verify: the test binaries did not run to completion; see output below"
        )
        .ok();
        writeln!(stderr, "{raw_output}").ok();
        return EXIT_RUNTIME;
    }

    let (passed, failed, ignored) = summary.unwrap_or((0, 0, 0));
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
        project_root
            .join(EVIDENCE_FILE)
            .to_string_lossy()
            .into_owned()
    });

    match std::fs::write(
        &out_path,
        serde_json::to_string_pretty(&evidence).unwrap() + "\n",
    ) {
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

    writeln!(
        stdout,
        "Tests PASSED: {total} total, {passed} passed, {ignored} ignored"
    )
    .ok();
    EXIT_OK
}

/// Parses and sums every `test result:` summary line out of `cargo test`
/// output. `cargo test` emits one such line per test binary (the lib, each
/// integration test file, and the doctest run), so returning only the last
/// line under-reports the real test count for any multi-binary crate.
/// Returns `None` when no such line is present, which means the test
/// binaries never produced a real summary (e.g. they failed to start) —
/// callers must not treat that as "0 tests, 0 failures".
fn parse_test_summary(output: &str) -> Option<(usize, usize, usize)> {
    let mut found = false;
    let (mut passed, mut failed, mut ignored) = (0usize, 0usize, 0usize);
    for line in output.lines() {
        if line.contains("test result:") {
            found = true;
            passed += extract_count(line, "passed");
            failed += extract_count(line, "failed");
            ignored += extract_count(line, "ignored");
        }
    }
    if found {
        Some((passed, failed, ignored))
    } else {
        None
    }
}

fn extract_count(line: &str, label: &str) -> usize {
    let pattern = format!(" {label}");
    if let Some(pos) = line.find(&pattern) {
        let before = &line[..pos];
        let num_str: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        return num_str.parse().unwrap_or(0);
    }
    0
}

struct Opts {
    dir: Option<PathBuf>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        output: None,
    };
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
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.output = Some(v.to_string());
                } else {
                    writeln!(stderr, "rsfusa verify: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_test_summary_reads_real_result_line() {
        let output = "\nrunning 2 tests\ntest one ... ok\ntest two ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(parse_test_summary(output), Some((2, 0, 0)));
    }

    #[test]
    fn parse_test_summary_reads_failures() {
        let output =
            "test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n";
        assert_eq!(parse_test_summary(output), Some((3, 1, 0)));
    }

    // D002 regression: cargo test emits one `test result:` line per binary
    // (lib, each integration test, doctests). All counts must be summed, not
    // just the last line (which is typically the 0-count doctest summary).
    #[test]
    fn parse_test_summary_sums_all_binaries() {
        let output = "\
running 5 tests
test result: ok. 5 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s

running 3 tests
test result: ok. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";
        assert_eq!(parse_test_summary(output), Some((7, 1, 1)));
    }

    // Regression for GitHub issue #46: when cargo test's harness never
    // reaches the point of emitting a "test result:" line — e.g. because it
    // rejected an unrecognized CLI flag (the original --test-output=immediate
    // bug) or a build/compile step failed first — parse_test_summary must
    // return None, not a fake (0, 0, 0). The caller in `run()` uses that None
    // to distinguish "no tests ran" from "genuinely zero failures".
    #[test]
    fn parse_test_summary_returns_none_when_harness_never_ran() {
        let rejected_flag_output =
            "error: Unrecognized option: 'test-output'\nerror: test failed, to rerun pass `--lib`\n";
        assert_eq!(parse_test_summary(rejected_flag_output), None);

        let compile_failure_output =
            "error: this file contains an unclosed delimiter\nerror: could not compile `t` (lib test) due to 1 previous error\n";
        assert_eq!(parse_test_summary(compile_failure_output), None);
    }

    #[test]
    fn extract_count_parses_labeled_number() {
        let line = "test result: ok. 12 passed; 3 failed; 4 ignored; 0 measured; 0 filtered out";
        assert_eq!(extract_count(line, "passed"), 12);
        assert_eq!(extract_count(line, "failed"), 3);
        assert_eq!(extract_count(line, "ignored"), 4);
    }
}
