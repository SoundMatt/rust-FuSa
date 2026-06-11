// rsfusa — rust-FuSa functional safety toolkit for Rust projects.
// Implements x-FuSa spec v1.9 (§1.1: language=rust, binary=rsfusa).

#![allow(dead_code)]

mod analyze;
mod auditpack;
mod cmd;
mod config;
mod cyber;
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
        // §9.1 MUST commands
        "version"      => cmd::version::run(rest, stdout, stderr),
        "capabilities" => cmd::capabilities::run(rest, stdout, stderr),
        "init"         => cmd::init::run(rest, stdout, stderr),
        "check"        => cmd::check::run(rest, stdout, stderr),
        "report"       => cmd::check::run_report(rest, stdout, stderr),
        "trace"        => cmd::trace::run(rest, stdout, stderr),
        "qualify"      => cmd::qualify::run(rest, stdout, stderr),
        "release"      => cmd::release::run(rest, stdout, stderr),
        "audit-pack"   => cmd::auditpack::run(rest, stdout, stderr),

        // §9.2 SHOULD commands
        "lint"         => cmd::lint::run(rest, stdout, stderr),
        "analyze"      => cmd::analyze::run(rest, stdout, stderr),
        "diff"         => cmd::diff::run(rest, stdout, stderr),
        "verify"       => cmd::verify::run(rest, stdout, stderr),
        "vuln"         => cmd::vuln::run(rest, stdout, stderr),
        "cyber"        => cmd::cyber::run(rest, stdout, stderr),
        "coverage"     => cmd::coverage::run(rest, stdout, stderr),
        "coupling"     => cmd::coupling::run(rest, stdout, stderr),
        "fmea"         => cmd::fmea::run(rest, stdout, stderr),
        "tara"         => cmd::tara::run(rest, stdout, stderr),
        "safety-case"  => cmd::safety_case::run(rest, stdout, stderr),
        "boundary"     => cmd::boundary::run(rest, stdout, stderr),
        "hara"         => cmd::hara::run(rest, stdout, stderr),

        // §9.3 MAY commands — standards gap reports
        "iso26262"     => cmd::standards::run_iso26262(rest, stdout, stderr),
        "iec61508"     => cmd::standards::run_iec61508(rest, stdout, stderr),
        "do178c" | "do178" => cmd::standards::run_do178c(rest, stdout, stderr),
        "iso21434"     => cmd::standards::run_iso21434(rest, stdout, stderr),
        "unece"        => cmd::standards::run_unece(rest, stdout, stderr),
        "misra"        => cmd::standards::run_misra(rest, stdout, stderr),

        // §9.3 MAY commands — tool management
        "disposition"  => cmd::disposition::run(rest, stdout, stderr),
        "badge"        => cmd::badge::run(rest, stdout, stderr),
        "sas"          => cmd::sas::run(rest, stdout, stderr),
        "sci"          => cmd::sci::run(rest, stdout, stderr),
        "impact"       => cmd::impact::run(rest, stdout, stderr),
        "metrics"      => cmd::metrics::run(rest, stdout, stderr),
        "fix"          => cmd::fix::run(rest, stdout, stderr),
        "sign"         => cmd::sign::run(rest, stdout, stderr),
        "req"          => cmd::req::run(rest, stdout, stderr),
        "pr"           => cmd::pr::run(rest, stdout, stderr),
        "template"     => cmd::template::run(rest, stdout, stderr),
        "hooks"        => cmd::hooks::run(rest, stdout, stderr),

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
    writeln!(w, "COMMANDS (§9.1 MUST):").ok();
    writeln!(w, "    version       Print tool version").ok();
    writeln!(w, "    capabilities  Report supported commands and formats").ok();
    writeln!(w, "    init          Create .fusa.json and .fusa-reqs.json").ok();
    writeln!(w, "    check         Run all safety checks (exit 1 on ERROR findings)").ok();
    writeln!(w, "    report        Run safety checks (always exits 0)").ok();
    writeln!(w, "    trace         Show requirement traceability matrix").ok();
    writeln!(w, "    qualify       Run tool qualification suite").ok();
    writeln!(w, "    release       Generate SBOM, provenance, artifact manifest").ok();
    writeln!(w, "    audit-pack    Bundle evidence into audit-pack.zip").ok();
    writeln!(w).ok();
    writeln!(w, "COMMANDS (§9.2 SHOULD):").ok();
    writeln!(w, "    lint          Run LINT* coding standard rules only").ok();
    writeln!(w, "    analyze       Run ANA* static analysis rules only").ok();
    writeln!(w, "    diff          Compare two check reports by fingerprint").ok();
    writeln!(w, "    verify        Run cargo test and save test evidence").ok();
    writeln!(w, "    vuln          Scan dependencies for vulnerabilities").ok();
    writeln!(w, "    cyber         CWE-mapped security analysis → cyber-report.json").ok();
    writeln!(w, "    coverage      Structural coverage report").ok();
    writeln!(w, "    coupling      Module coupling analysis → coupling-report.json").ok();
    writeln!(w, "    fmea          Design FMEA from pub functions → fmea.json + fmea.csv").ok();
    writeln!(w, "    tara          Threat analysis per ISO 21434 → tara.json + tara.md").ok();
    writeln!(w, "    safety-case   Assemble GSN safety case → safety-case.{{json,md,mermaid}}").ok();
    writeln!(w, "    boundary      Dependency graph → boundary.{{dot,mermaid}}").ok();
    writeln!(w, "    hara          Hazard Analysis and Risk Assessment").ok();
    writeln!(w).ok();
    writeln!(w, "COMMANDS (§9.3 MAY):").ok();
    writeln!(w, "    iso26262      ISO 26262 Part 6 gap report").ok();
    writeln!(w, "    iec61508      IEC 61508 Part 3 gap report").ok();
    writeln!(w, "    do178c        DO-178C Annex A gap report").ok();
    writeln!(w, "    iso21434      ISO 21434 gap report").ok();
    writeln!(w, "    unece         UN R.155 gap report").ok();
    writeln!(w, "    misra         MISRA C:2023 coverage mapping").ok();
    writeln!(w, "    disposition   Manage .fusa-dispositions.json").ok();
    writeln!(w, "    badge         Generate SVG status badge").ok();
    writeln!(w, "    sas           Software Accomplishment Summary (DO-178C §11.20)").ok();
    writeln!(w, "    sci           Software Configuration Index (DO-178C §11.16)").ok();
    writeln!(w, "    impact        Impact analysis via git diff").ok();
    writeln!(w, "    metrics       Safety metrics time series").ok();
    writeln!(w, "    fix           Show auto-fixable findings with guidance").ok();
    writeln!(w, "    sign          Sign or verify files with HMAC-SHA256").ok();
    writeln!(w, "    req           Requirement management").ok();
    writeln!(w, "    pr            Software problem reports").ok();
    writeln!(w, "    template      Generate safety documentation templates").ok();
    writeln!(w, "    hooks         Manage git pre-commit hooks").ok();
    writeln!(w).ok();
    writeln!(w, "Common flags: --dir <path>  --format text|json|html|sarif|md  --output <file>  --strict  --no-color").ok();
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
        let fp1 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 60 lines");
        let fp2 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 60 lines");
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("sha256:"));
    }

    #[test]
    fn fingerprint_normalizes_digits() {
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

    #[test]
    fn diff_no_args() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa diff"), &mut out, &mut err);
        assert_eq!(code, 2);
    }
}
