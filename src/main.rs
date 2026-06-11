// rsfusa — rust-FuSa functional safety toolkit for Rust projects.
// Implements x-FuSa spec v1.9 (§1.1: language=rust, binary=rsfusa).

#![allow(dead_code)]

mod auditpack;
mod cmd;
mod config;
mod engine;
mod lint;
mod qualify;
mod release;
mod report;
mod rules;
mod trace;
mod types;

use std::io::{self, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = run(&args, &mut io::stdout(), &mut io::stderr());
    std::process::exit(code);
}

fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.len() < 2 {
        print_help(stdout);
        return types::EXIT_USAGE;
    }

    let subcmd = &args[1];
    let rest = &args[2..].to_vec();

    match subcmd.as_str() {
        "version" => cmd::version::run(rest, stdout, stderr),
        "capabilities" => cmd::capabilities::run(rest, stdout, stderr),
        "init" => cmd::init::run(rest, stdout, stderr),
        "check" => cmd::check::run(rest, stdout, stderr),
        "report" => cmd::check::run_report(rest, stdout, stderr),
        "trace" => cmd::trace::run(rest, stdout, stderr),
        "qualify" => cmd::qualify::run(rest, stdout, stderr),
        "release" => cmd::release::run(rest, stdout, stderr),
        "audit-pack" => cmd::auditpack::run(rest, stdout, stderr),
        "help" | "--help" | "-h" => {
            print_help(stdout);
            types::EXIT_OK
        }
        other => {
            writeln!(
                stderr,
                "rsfusa: unknown command: {other}\nRun 'rsfusa help' for usage."
            ).ok();
            types::EXIT_USAGE
        }
    }
}

fn print_help(w: &mut dyn Write) {
    writeln!(
        w,
        "{tool} {ver} (spec {spec})",
        tool = types::TOOL_NAME,
        ver = types::VERSION,
        spec = types::SPEC_VERSION
    ).ok();
    writeln!(w, "Functional safety toolkit for Rust projects.").ok();
    writeln!(w).ok();
    writeln!(w, "USAGE:").ok();
    writeln!(w, "    rsfusa <command> [flags]").ok();
    writeln!(w).ok();
    writeln!(w, "COMMANDS:").ok();
    writeln!(w, "    version       Print tool version").ok();
    writeln!(w, "    capabilities  Report supported commands and formats (--format json)").ok();
    writeln!(w, "    init          Create .fusa.json and .fusa-reqs.json").ok();
    writeln!(w, "    check         Run safety checks (exit 1 on ERROR findings)").ok();
    writeln!(w, "    report        Run safety checks and report (always exits 0)").ok();
    writeln!(w, "    trace         Show requirement traceability matrix").ok();
    writeln!(w, "    qualify       Run tool qualification suite").ok();
    writeln!(w, "    release       Generate SBOM, provenance, artifact manifest").ok();
    writeln!(w, "    audit-pack    Bundle evidence into audit-pack.zip").ok();
    writeln!(w).ok();
    writeln!(w, "Common flags: --dir <path>  --format text|json|html|sarif  --output <file>  --strict  --no-color").ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(|s| s.to_string()).collect()
    }

    #[test]
    fn version_text() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa version"), &mut out, &mut err);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("rust-FuSa"));
    }

    #[test]
    fn version_json() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa version --format json"), &mut out, &mut err);
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["tool"], "rust-FuSa");
        assert_eq!(v["specVersion"], "1.9");
    }

    #[test]
    fn capabilities_json() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa capabilities --format json"), &mut out, &mut err);
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kind"], "capabilities");
        assert_eq!(v["language"], "rust");
    }

    #[test]
    fn unknown_command() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa unknowncmd"), &mut out, &mut err);
        assert_eq!(code, 2);
    }

    #[test]
    fn fingerprint_canonical() {
        // §4.2: same (ruleId, file, message) must always hash identically.
        let fp1 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 60 lines");
        let fp2 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 60 lines");
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("sha256:"));
    }

    #[test]
    fn fingerprint_normalizes_digits() {
        // "exceeds 60 lines" and "exceeds 42 lines" should produce same fingerprint.
        let fp1 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 60 lines");
        let fp2 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 42 lines");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn check_on_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa check --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        // Without .fusa.json the tool runs with defaults and may find FUSA001.
        assert!(code == 0 || code == 1);
    }

    #[test]
    fn init_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa init --dir {} --name testproj --standard iso26262",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(dir.path().join(".fusa.json").exists());
        assert!(dir.path().join(".fusa-reqs.json").exists());
    }
}
