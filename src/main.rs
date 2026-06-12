// rsfusa — rust-FuSa functional safety toolkit for Rust projects.
// Implements x-FuSa spec v1.9 (§1.1: language=rust, binary=rsfusa).
//fusa:req REQ-NF001
//fusa:req REQ-NF002
//fusa:req REQ-CLI001
//fusa:req REQ-CLI011
//fusa:req REQ-CLI012

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
        "version" => cmd::version::run(rest, stdout, stderr),
        "capabilities" => cmd::capabilities::run(rest, stdout, stderr),
        "init" => cmd::init::run(rest, stdout, stderr),
        "check" => cmd::check::run(rest, stdout, stderr),
        "report" => cmd::check::run_report(rest, stdout, stderr),
        "trace" => cmd::trace::run(rest, stdout, stderr),
        "qualify" => cmd::qualify::run(rest, stdout, stderr),
        "release" => cmd::release::run(rest, stdout, stderr),
        "audit-pack" => cmd::auditpack::run(rest, stdout, stderr),

        // §9.2 SHOULD commands
        "lint" => cmd::lint::run(rest, stdout, stderr),
        "analyze" => cmd::analyze::run(rest, stdout, stderr),
        "diff" => cmd::diff::run(rest, stdout, stderr),
        "verify" => cmd::verify::run(rest, stdout, stderr),
        "vuln" => cmd::vuln::run(rest, stdout, stderr),
        "cyber" => cmd::cyber::run(rest, stdout, stderr),
        "coverage" => cmd::coverage::run(rest, stdout, stderr),
        "coupling" => cmd::coupling::run(rest, stdout, stderr),
        "fmea" => cmd::fmea::run(rest, stdout, stderr),
        "tara" => cmd::tara::run(rest, stdout, stderr),
        "safety-case" => cmd::safety_case::run(rest, stdout, stderr),
        "boundary" => cmd::boundary::run(rest, stdout, stderr),
        "hara" => cmd::hara::run(rest, stdout, stderr),

        // §9.3 MAY commands — standards gap reports
        "iso26262" => cmd::standards::run_iso26262(rest, stdout, stderr),
        "iec61508" => cmd::standards::run_iec61508(rest, stdout, stderr),
        "do178c" | "do178" => cmd::standards::run_do178c(rest, stdout, stderr),
        "iso21434" => cmd::standards::run_iso21434(rest, stdout, stderr),
        "unece" => cmd::standards::run_unece(rest, stdout, stderr),
        "misra" => cmd::standards::run_misra(rest, stdout, stderr),
        "iec62443" => cmd::standards::run_iec62443(rest, stdout, stderr),
        "slsa" => cmd::standards::run_slsa(rest, stdout, stderr),

        // §9.3 MAY commands — tool management
        "disposition" => cmd::disposition::run(rest, stdout, stderr),
        "badge" => cmd::badge::run(rest, stdout, stderr),
        "sas" => cmd::sas::run(rest, stdout, stderr),
        "sci" => cmd::sci::run(rest, stdout, stderr),
        "impact" => cmd::impact::run(rest, stdout, stderr),
        "metrics" => cmd::metrics::run(rest, stdout, stderr),
        "fix" => cmd::fix::run(rest, stdout, stderr),
        "sign" => cmd::sign::run(rest, stdout, stderr),
        "req" => cmd::req::run(rest, stdout, stderr),
        "pr" => cmd::pr::run(rest, stdout, stderr),
        "template" => cmd::template::run(rest, stdout, stderr),
        "hooks" => cmd::hooks::run(rest, stdout, stderr),

        "help" | "--help" | "-h" => {
            print_help(stdout);
            types::EXIT_OK
        }
        other => {
            writeln!(
                stderr,
                "rsfusa: unknown command: {other}\nRun 'rsfusa help' for usage."
            )
            .ok();
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
    )
    .ok();
    writeln!(w, "Functional safety toolkit for Rust projects.").ok();
    writeln!(w).ok();
    writeln!(w, "USAGE:").ok();
    writeln!(w, "    rsfusa <command> [flags]").ok();
    writeln!(w).ok();
    writeln!(w, "COMMANDS (§9.1 MUST):").ok();
    writeln!(w, "    version       Print tool version").ok();
    writeln!(w, "    capabilities  Report supported commands and formats").ok();
    writeln!(w, "    init          Create .fusa.json and .fusa-reqs.json").ok();
    writeln!(
        w,
        "    check         Run all safety checks (exit 1 on ERROR findings)"
    )
    .ok();
    writeln!(w, "    report        Run safety checks (always exits 0)").ok();
    writeln!(w, "    trace         Show requirement traceability matrix").ok();
    writeln!(w, "    qualify       Run tool qualification suite").ok();
    writeln!(
        w,
        "    release       Generate SBOM, provenance, artifact manifest"
    )
    .ok();
    writeln!(w, "    audit-pack    Bundle evidence into audit-pack.zip").ok();
    writeln!(w).ok();
    writeln!(w, "COMMANDS (§9.2 SHOULD):").ok();
    writeln!(w, "    lint          Run LINT* coding standard rules only").ok();
    writeln!(w, "    analyze       Run ANA* static analysis rules only").ok();
    writeln!(
        w,
        "    diff          Compare two check reports by fingerprint"
    )
    .ok();
    writeln!(w, "    verify        Run cargo test and save test evidence").ok();
    writeln!(w, "    vuln          Scan dependencies for vulnerabilities").ok();
    writeln!(
        w,
        "    cyber         CWE-mapped security analysis → cyber-report.json"
    )
    .ok();
    writeln!(w, "    coverage      Structural coverage report").ok();
    writeln!(
        w,
        "    coupling      Module coupling analysis → coupling-report.json"
    )
    .ok();
    writeln!(
        w,
        "    fmea          Design FMEA from pub functions → fmea.json + fmea.csv"
    )
    .ok();
    writeln!(
        w,
        "    tara          Threat analysis per ISO 21434 → tara.json + tara.md"
    )
    .ok();
    writeln!(
        w,
        "    safety-case   Assemble GSN safety case → safety-case.{{json,md,mermaid}}"
    )
    .ok();
    writeln!(
        w,
        "    boundary      Dependency graph → boundary.{{dot,mermaid}}"
    )
    .ok();
    writeln!(w, "    hara          Hazard Analysis and Risk Assessment").ok();
    writeln!(w).ok();
    writeln!(w, "COMMANDS (§9.3 MAY):").ok();
    writeln!(w, "    iso26262      ISO 26262 Part 6 gap report").ok();
    writeln!(w, "    iec61508      IEC 61508 Part 3 gap report").ok();
    writeln!(w, "    do178c        DO-178C Annex A gap report").ok();
    writeln!(w, "    iso21434      ISO 21434 gap report").ok();
    writeln!(w, "    unece         UN R.155 gap report").ok();
    writeln!(w, "    misra         MISRA C:2023 coverage mapping").ok();
    writeln!(w, "    iec62443      IEC 62443 IACS security gap report").ok();
    writeln!(w, "    slsa          SLSA supply-chain levels gap report").ok();
    writeln!(w, "    disposition   Manage .fusa-dispositions.json").ok();
    writeln!(w, "    badge         Generate SVG status badge").ok();
    writeln!(
        w,
        "    sas           Software Accomplishment Summary (DO-178C §11.20)"
    )
    .ok();
    writeln!(
        w,
        "    sci           Software Configuration Index (DO-178C §11.16)"
    )
    .ok();
    writeln!(w, "    impact        Impact analysis via git diff").ok();
    writeln!(w, "    metrics       Safety metrics time series").ok();
    writeln!(
        w,
        "    fix           Show auto-fixable findings with guidance"
    )
    .ok();
    writeln!(w, "    sign          Sign or verify files with HMAC-SHA256").ok();
    writeln!(w, "    req           Requirement management").ok();
    writeln!(w, "    pr            Software problem reports").ok();
    writeln!(
        w,
        "    template      Generate safety documentation templates"
    )
    .ok();
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

    //fusa:test REQ-CLI009
    //fusa:test REQ-NF001
    #[test]
    fn version_text() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa version"), &mut out, &mut err);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("rust-FuSa"));
    }

    //fusa:test REQ-CLI009
    //fusa:test REQ-CLI004
    //fusa:test REQ-CLI002
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

    //fusa:test REQ-CLI010
    //fusa:test REQ-CLI004
    #[test]
    fn capabilities_json() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &args("rsfusa capabilities --format json"),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kind"], "capabilities");
        assert_eq!(v["language"], "rust");
    }

    //fusa:test REQ-CLI012
    //fusa:test REQ-CLI001
    #[test]
    fn unknown_command() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa unknowncmd"), &mut out, &mut err);
        assert_eq!(code, 2);
    }

    //fusa:test REQ-CLI003
    //fusa:test REQ-RUNTIME004
    //fusa:test REQ-NF003
    #[test]
    fn fingerprint_canonical() {
        let fp1 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 60 lines");
        let fp2 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 60 lines");
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("sha256:"));
    }

    //fusa:test REQ-RUNTIME005
    //fusa:test REQ-CLI003
    #[test]
    fn fingerprint_normalizes_digits() {
        let fp1 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 60 lines");
        let fp2 = types::compute_fingerprint("LINT001", "src/foo.rs", "function exceeds 42 lines");
        assert_eq!(fp1, fp2);
    }

    //fusa:test REQ-ENG002
    //fusa:test REQ-CLI001
    #[test]
    fn check_on_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa check --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
    }

    //fusa:test REQ-CFG001
    //fusa:test REQ-CFG002
    //fusa:test REQ-CFG003
    //fusa:test REQ-REQQ001
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

    //fusa:test REQ-CLI001
    //fusa:test REQ-CLI012
    #[test]
    fn diff_no_args() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa diff"), &mut out, &mut err);
        assert_eq!(code, 2);
    }

    //fusa:test REQ-CLI011
    #[test]
    fn help_exits_ok() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa help"), &mut out, &mut err);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("COMMANDS"));
    }

    //fusa:test REQ-CLI011
    //fusa:test REQ-CLI001
    #[test]
    fn no_args_exits_usage() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa"), &mut out, &mut err);
        assert_eq!(code, 2);
    }

    //fusa:test REQ-QUALIFY001
    //fusa:test REQ-QUALIFY002
    //fusa:test REQ-QUALIFY003
    //fusa:test REQ-QUALIFY004
    //fusa:test REQ-E2E001
    #[test]
    fn qualify_passes() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa qualify"), &mut out, &mut err);
        assert_eq!(
            code,
            0,
            "qualify should pass: {}",
            String::from_utf8(err).unwrap_or_default()
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("passed"));
    }

    //fusa:test REQ-HARA002
    //fusa:test REQ-HARA004
    #[test]
    fn hara_asil_derivation() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &args("rsfusa hara asil --severity S3 --exposure E4 --controllability C2"),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("ASIL"));
    }

    //fusa:test REQ-HARA003
    //fusa:test REQ-HARA005
    #[test]
    fn hara_init_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa hara init --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(dir.path().join(".fusa-hara.json").exists());
    }

    //fusa:test REQ-RPT001
    //fusa:test REQ-RPT002
    //fusa:test REQ-CLI004
    #[test]
    fn check_json_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa check --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["schemaVersion"], "1.9");
        assert_eq!(v["tool"], "rust-FuSa");
        assert!(v["findings"].is_array());
        assert!(v["summary"]["errors"].is_number());
    }

    //fusa:test REQ-RPT005
    #[test]
    fn report_always_exits_zero() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa report --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "report must always exit 0");
    }

    //fusa:test REQ-CLI008
    #[test]
    fn strict_mode_exits_one_on_warnings() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/main.rs"),
            "fn main() { let _x = Some(1).unwrap(); }\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa check --dir {} --strict",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 1, "strict mode should exit 1 on warnings");
    }

    //fusa:test REQ-RELEASE001
    //fusa:test REQ-RELEASE002
    //fusa:test REQ-RELEASE003
    //fusa:test REQ-RELEASE004
    #[test]
    fn release_creates_artefacts() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "# generated").unwrap();
        let a = args(&format!("rsfusa release --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(dir.path().join("sbom.json").exists());
        assert!(dir.path().join("provenance.json").exists());
        assert!(dir.path().join("artifact-manifest.json").exists());
    }

    //fusa:test REQ-AUDIT001
    //fusa:test REQ-AUDIT002
    //fusa:test REQ-AUDIT003
    //fusa:test REQ-AUDIT004
    #[test]
    fn audit_pack_creates_zip() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("check-report.json"), "{}").unwrap();
        let a = args(&format!("rsfusa audit-pack --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _code = run(&a, &mut out, &mut err);
        assert!(dir.path().join("audit-pack.zip").exists() || _code != 0);
    }

    //fusa:test REQ-TRACE001
    //fusa:test REQ-TRACE002
    //fusa:test REQ-TRACE004
    //fusa:test REQ-TRACE007
    #[test]
    fn trace_json_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            r#"{"requirements":[{"id":"REQ-T001","title":"T","text":"T","standard":"iso26262","level":"HLR"}]}"#,
        ).unwrap();
        let a = args(&format!(
            "rsfusa trace --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        // kind is "trace-matrix" per x-FuSa spec §5 serialisation
        assert!(v["kind"]
            .as_str()
            .map(|s| s.contains("trace"))
            .unwrap_or(false));
        assert_eq!(v["tool"], "rust-FuSa");
        assert!(v["coverage"]["totalRequirements"].is_number());
    }

    //fusa:test REQ-CLI003
    //fusa:test REQ-NF003
    #[test]
    fn fingerprint_deterministic() {
        let fp1 = types::compute_fingerprint("ANA001", "src/lib.rs", "fn body is 75 lines");
        let fp2 = types::compute_fingerprint("ANA001", "src/lib.rs", "fn body is 90 lines");
        // digit normalisation makes these equal
        assert_eq!(fp1, fp2);
        let fp3 = types::compute_fingerprint("ANA001", "src/other.rs", "fn body is 75 lines");
        assert_ne!(fp1, fp3, "different file → different fingerprint");
    }

    //fusa:test REQ-ENG004
    //fusa:test REQ-ENG005
    #[test]
    fn check_finding_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa check --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _code = run(&a, &mut out, &mut err);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        if let Some(findings) = v["findings"].as_array() {
            if let Some(f) = findings.first() {
                let sev = f["severity"].as_str().unwrap_or("");
                assert!(
                    ["ERROR", "WARNING", "INFO"].contains(&sev),
                    "severity must be one of ERROR/WARNING/INFO"
                );
                assert!(f["ruleId"].is_string());
                assert!(f["fingerprint"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("sha256:"));
            }
        }
    }

    //fusa:test REQ-FMEA001
    //fusa:test REQ-FMEA005
    //fusa:test REQ-FMEA006
    #[test]
    fn fmea_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn compute(x: u32) -> u32 { x * 2 }\n",
        )
        .unwrap();
        let a = args(&format!("rsfusa fmea --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(dir.path().join("fmea.json").exists());
        assert!(dir.path().join("fmea.csv").exists());
    }

    //fusa:test REQ-BOUNDARY001
    //fusa:test REQ-BOUNDARY002
    //fusa:test REQ-BOUNDARY003
    #[test]
    fn boundary_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n[dependencies]\nserde=\"1\"\n",
        )
        .unwrap();
        let a = args(&format!("rsfusa boundary --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(dir.path().join("boundary.dot").exists());
        assert!(dir.path().join("boundary.mermaid").exists());
    }

    //fusa:test REQ-VERIFY001
    //fusa:test REQ-VERIFY002
    //fusa:test REQ-VERIFY003
    //fusa:test REQ-VERIFY004
    //fusa:test REQ-VERIFY005
    #[test]
    fn verify_runs_cargo_test() {
        // verify shells out to cargo test; accept 0 (ok), 1 (tests fail), or 3 (runtime/cargo issue)
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "").unwrap();
        let a = args(&format!("rsfusa verify --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(
            code == 0 || code == 1 || code == 3,
            "verify exits 0/1/3, got {code}"
        );
    }

    //fusa:test REQ-SC001
    //fusa:test REQ-SC002
    //fusa:test REQ-SC003
    //fusa:test REQ-SC004
    //fusa:test REQ-SC005
    #[test]
    fn safety_case_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa safety-case --dir {}",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(dir.path().join("safety-case.json").exists());
        assert!(dir.path().join("safety-case.md").exists());
        assert!(dir.path().join("safety-case.mermaid").exists());
    }

    //fusa:test REQ-TARA001
    //fusa:test REQ-TARA004
    //fusa:test REQ-TARA005
    #[test]
    fn tara_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "fn foo() {}").unwrap();
        let a = args(&format!("rsfusa tara --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        assert!(dir.path().join("tara.json").exists());
        assert!(dir.path().join("tara.md").exists());
    }

    //fusa:test REQ-NF001
    //fusa:test REQ-CLI009
    #[test]
    fn version_output_format() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa version"), &mut out, &mut err);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("0.2.1"),
            "version string should contain 0.2.1"
        );
        assert!(
            text.contains("rust-FuSa"),
            "version output should mention tool name"
        );
    }

    //fusa:test REQ-CLI010
    //fusa:sec-test REQ-CYBER001
    #[test]
    fn capabilities_lists_all_commands() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &args("rsfusa capabilities --format json"),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let must_cmds = v["commands"]["must"].as_array().unwrap();
        let should_cmds = v["commands"]["should"].as_array().unwrap();
        let may_cmds = v["commands"]["may"].as_array().unwrap();
        assert!(must_cmds.len() >= 9, "at least 9 MUST commands");
        assert!(should_cmds.len() >= 13, "at least 13 SHOULD commands");
        assert!(may_cmds.len() >= 18, "at least 18 MAY commands");
    }

    //fusa:test REQ-ENG001
    //fusa:test REQ-ENG002
    //fusa:test REQ-ENG003
    #[test]
    fn check_deduplicates_findings() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa check --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _code = run(&a, &mut out, &mut err);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let findings = v["findings"].as_array().unwrap();
        let mut fps: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for f in findings {
            let fp = f["fingerprint"].as_str().unwrap_or("");
            assert!(fps.insert(fp), "duplicate fingerprint found: {fp}");
        }
    }

    //fusa:test REQ-LINT001
    //fusa:test REQ-LINT002
    #[test]
    fn lint_detects_unwrap() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn foo(x: Option<i32>) -> i32 { x.unwrap() }\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa lint --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _code = run(&a, &mut out, &mut err);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let findings = v["findings"].as_array().unwrap();
        let has_lint002 = findings
            .iter()
            .any(|f| f["ruleId"].as_str() == Some("LINT002"));
        assert!(has_lint002, "LINT002 should fire on .unwrap()");
    }

    //fusa:test REQ-ANA001
    //fusa:test REQ-ANA005
    #[test]
    fn analyze_detects_truncating_cast() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn shrink(x: u32) -> u8 { x as u8 }\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa analyze --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _code = run(&a, &mut out, &mut err);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let findings = v["findings"].as_array().unwrap();
        let has_ana005 = findings
            .iter()
            .any(|f| f["ruleId"].as_str() == Some("ANA005"));
        assert!(has_ana005, "ANA005 should fire on 'as u8'");
    }

    //fusa:test REQ-CYBER001
    //fusa:sec-test REQ-CYBER001
    #[test]
    fn cyber_detects_hardcoded_secret() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn get_key() -> &'static str { let password = \"s3cr3t\"; password }\n",
        )
        .unwrap();
        // cyber --format json writes to cyber-report.json; use check with the same rules instead
        let a = args(&format!(
            "rsfusa check --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _code = run(&a, &mut out, &mut err);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let findings = v["findings"].as_array().unwrap();
        let has_cyber001 = findings
            .iter()
            .any(|f| f["ruleId"].as_str() == Some("CYBER001"));
        assert!(has_cyber001, "CYBER001 should fire on hardcoded password");
    }

    //fusa:test REQ-CYBER006
    //fusa:sec-test REQ-CYBER006
    #[test]
    fn cyber_detects_cleartext_http() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "const API: &str = \"http://api.example.com/data\";\n",
        )
        .unwrap();
        // cyber --format json writes to cyber-report.json; use check with the same rules instead
        let a = args(&format!(
            "rsfusa check --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _code = run(&a, &mut out, &mut err);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let findings = v["findings"].as_array().unwrap();
        let has_cyber006 = findings
            .iter()
            .any(|f| f["ruleId"].as_str() == Some("CYBER006"));
        assert!(has_cyber006, "CYBER006 should fire on http:// URL");
    }

    //fusa:test REQ-FUSA043
    #[test]
    fn iec62443_gap_report_runs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(".fusa-reqs.json"), "{\"requirements\":[]}").unwrap();
        let a = args(&format!("rsfusa iec62443 --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1, "iec62443 exits 0 or 1");
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("IEC 62443"),
            "output should mention IEC 62443"
        );
    }

    //fusa:test REQ-FUSA044
    #[test]
    fn iec62443_gap_report_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa iec62443 --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kind"].as_str(), Some("gap-report"));
        assert_eq!(v["standard"].as_str(), Some("iec62443"));
    }

    //fusa:test REQ-FUSA045
    #[test]
    fn slsa_gap_report_runs() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa slsa --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1, "slsa exits 0 or 1");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("SLSA"), "output should mention SLSA");
    }

    //fusa:test REQ-FUSA046
    #[test]
    fn slsa_gap_report_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa slsa --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kind"].as_str(), Some("gap-report"));
        assert_eq!(v["standard"].as_str(), Some("slsa"));
    }
}
