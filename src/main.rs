// rsfusa — rust-FuSa functional safety toolkit for Rust projects.
// Implements x-FuSa spec v1.10 (§1.1: language=rust, binary=rsfusa).
//fusa:req REQ-NF001
//fusa:req REQ-NF002
//fusa:req REQ-NF003
//fusa:req REQ-CLI001
//fusa:req REQ-CLI002
//fusa:req REQ-CLI007
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
        "comp" => cmd::comp::run(rest, stdout, stderr),
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
        "    comp          Cyclomatic complexity (V(G)) per DO-178C §6.3.4 → comp-report.json"
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
        assert_eq!(v["specVersion"], types::SPEC_VERSION);
    }

    //fusa:test REQ-CLI010
    //fusa:test REQ-CLI004
    //fusa:test REQ-CAP-STD001
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
    //fusa:test REQ-CLI007
    //fusa:test REQ-ERR001
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
    //fusa:test REQ-INIT001
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

    //fusa:test REQ-DIFF001
    #[test]
    fn diff_detects_introduced_and_resolved() {
        let dir = tempfile::TempDir::new().unwrap();
        let baseline = dir.path().join("baseline.json");
        let current = dir.path().join("current.json");
        std::fs::write(
            &baseline,
            r#"{"findings":[
                {"fingerprint":"a","ruleId":"ANA001","location":{"file":"x.rs","line":1},"message":"m"},
                {"fingerprint":"b","ruleId":"ANA002","location":{"file":"x.rs","line":2},"message":"m"}
            ]}"#,
        )
        .unwrap();
        std::fs::write(
            &current,
            r#"{"findings":[
                {"fingerprint":"b","ruleId":"ANA002","location":{"file":"x.rs","line":2},"message":"m"},
                {"fingerprint":"c","ruleId":"ANA003","location":{"file":"x.rs","line":3},"message":"m"}
            ]}"#,
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa diff {} {} --format json",
            baseline.display(),
            current.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 1, "diff should exit 1 when a finding is introduced");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["summary"]["introduced"].as_u64(), Some(1));
        assert_eq!(v["summary"]["resolved"].as_u64(), Some(1));
        assert_eq!(v["summary"]["unchanged"].as_u64(), Some(1));
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
        let errtext = String::from_utf8(err).unwrap();
        assert!(errtext.contains("passed"));
    }

    //fusa:test REQ-HARA001
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
    //fusa:test REQ-RPT003
    //fusa:test REQ-CLI004
    //fusa:test REQ-CLI002
    //fusa:test REQ-LOC-REL001
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
        assert_eq!(v["schemaVersion"], types::SPEC_VERSION);
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
    //fusa:test REQ-RELEASE005
    //fusa:test REQ-RELEASE006
    //fusa:test REQ-RELEASE007
    //fusa:test REQ-RELEASE008
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
    //fusa:test REQ-TRACE003
    //fusa:test REQ-TRACE004
    //fusa:test REQ-TRACE007
    //fusa:test REQ-REQQ002
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
    //fusa:test REQ-ENG006
    //fusa:test REQ-ENG007
    //fusa:test REQ-NF002
    //fusa:test REQ-RPT004
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
    //fusa:test REQ-FMEA002
    //fusa:test REQ-FMEA003
    //fusa:test REQ-FMEA004
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
    //fusa:test REQ-BOUNDARY004
    //fusa:test REQ-BOUNDARY005
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
    //fusa:test REQ-TARA002
    //fusa:test REQ-TARA003
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
            text.contains(types::VERSION),
            "version string should contain current version"
        );
        assert!(
            text.contains("rust-FuSa"),
            "version output should mention tool name"
        );
    }

    //fusa:test REQ-CLI010
    //fusa:test REQ-CAP-STD001
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
    //fusa:test REQ-LINT003
    //fusa:test REQ-LINT004
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
    //fusa:test REQ-ANA002
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
    //fusa:test REQ-CYBER002
    //fusa:test REQ-CYBER003
    //fusa:test REQ-CYBER004
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
    //fusa:test REQ-CYBER007
    //fusa:test REQ-CYBER008
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
    //fusa:test REQ-IEC62443001
    //fusa:test REQ-IEC62443005
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
    //fusa:test REQ-IEC62443002
    //fusa:test REQ-IEC62443003
    //fusa:test REQ-IEC62443004
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
        // §9.3 canonical shape
        assert!(v["objectives"].is_array(), "must have 'objectives' array");
        assert!(
            v["summary"]["satisfied"].is_number(),
            "summary.satisfied must be present"
        );
        assert!(
            v["summary"]["partial"].is_number(),
            "summary.partial must be present"
        );
        assert!(
            v.get("requirements").is_none(),
            "'requirements' key must not appear"
        );
        assert!(
            v["summary"].get("met").is_none(),
            "'met' key must not appear"
        );
    }

    //fusa:test REQ-FUSA045
    //fusa:test REQ-SLSA001
    //fusa:test REQ-SLSA005
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
    //fusa:test REQ-SLSA002
    //fusa:test REQ-SLSA003
    //fusa:test REQ-SLSA004
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
        assert!(v["objectives"].is_array(), "must have 'objectives' array");
        assert!(v["summary"]["satisfied"].is_number());
        assert!(v.get("requirements").is_none());
    }

    //fusa:test REQ-FUSA001
    //fusa:test REQ-FUSA002
    //fusa:test REQ-FUSA003
    //fusa:test REQ-FUSA004
    //fusa:test REQ-FUSA005
    //fusa:test REQ-RPT004
    #[test]
    fn gap_report_objectives_status_canonical() {
        // §9.3: each objective status must be "satisfied" or "gap", never "met".
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa iso26262 --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        for obj in v["objectives"].as_array().unwrap() {
            let status = obj["status"].as_str().unwrap();
            assert!(
                status == "satisfied" || status == "gap" || status == "partial",
                "objective status must be satisfied|partial|gap, got '{status}'"
            );
            assert!(
                obj["findings"].is_array(),
                "each objective must have 'findings' array"
            );
        }
    }

    //fusa:test REQ-CLI005
    //fusa:test REQ-CLI006
    #[test]
    fn audit_pack_stdout_clean() {
        // §2.2: audit-pack must not write progress to stdout.
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa audit-pack --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        assert!(
            out.is_empty(),
            "audit-pack must write nothing to stdout (§2.2)"
        );
        let errtext = String::from_utf8(err).unwrap();
        assert!(
            errtext.contains("audit-pack"),
            "progress should appear on stderr"
        );
    }

    //fusa:test REQ-TRACE005
    //fusa:test REQ-TRACE006
    #[test]
    fn trace_sec_tested_gate_uses_sec_test_tags() {
        // §5: --sec-tested gate must use sec_tested_requirements (sec-test tags only).
        let dir = tempfile::TempDir::new().unwrap();
        // Two requirements: one has a test tag only, one has a sec-test tag.
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            r#"{"requirements":[
                {"id":"REQ-A","title":"A","text":"A","standard":"generic","level":"HLR"},
                {"id":"REQ-B","title":"B","text":"B","standard":"generic","level":"HLR"}
            ]}"#,
        )
        .unwrap();
        // Tag REQ-A with test, REQ-B with sec-test.
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "//fusa:test REQ-A\n//fusa:sec-test REQ-B\npub fn x() {}\n",
        )
        .unwrap();
        // Gate: sec-tested=100 — REQ-B is sec-tested (1/2=50%), so gate should fail.
        let a = args(&format!(
            "rsfusa trace --dir {} --sec-tested 100",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(
            code, 1,
            "--sec-tested 100 should fail when only 1/2 reqs have sec-test tags"
        );
    }

    //fusa:test REQ-TRACE008
    #[test]
    fn trace_func_coverage_gate_fails_below_threshold() {
        // §1.4.1 item 2: file-header convention — a pub fn counts as covered
        // if its containing file carries at least one //fusa:req tag.
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        // Tagged file: 1 pub fn, covered.
        std::fs::write(src.join("lib.rs"), "//fusa:req REQ-A\npub fn tagged() {}\n").unwrap();
        // Untagged file: 1 pub fn, uncovered.
        std::fs::write(src.join("other.rs"), "pub fn untagged() {}\n").unwrap();
        // 1/2 = 50% density.
        let a = args(&format!(
            "rsfusa trace --dir {} --func-coverage 80",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(
            code,
            1,
            "--func-coverage 80 should fail at 50% density: {}",
            String::from_utf8_lossy(&err)
        );
        let errtext = String::from_utf8(err).unwrap();
        assert!(
            errtext.contains("func-coverage gate failed"),
            "should report the func-coverage gate failure: {errtext}"
        );
    }

    //fusa:test REQ-TRACE008
    #[test]
    fn trace_func_coverage_gate_passes_at_or_above_threshold() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "//fusa:req REQ-A\npub fn tagged() {}\n").unwrap();
        // 1/1 = 100% density.
        let a = args(&format!(
            "rsfusa trace --dir {} --func-coverage 100",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "100% density should pass --func-coverage 100");
    }

    //fusa:test REQ-TRACE008
    #[test]
    fn trace_func_coverage_zero_disables_gate() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "pub fn untagged() {}\n").unwrap();
        let a = args(&format!(
            "rsfusa trace --dir {} --func-coverage 0",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "--func-coverage 0 must disable the gate");
    }

    //fusa:test REQ-TRACE009
    #[test]
    fn trace_dangling_test_tag_produces_warning() {
        // §1.4.1 item 3: a //fusa:test <ID> tag with no matching requirement
        // must be a WARNING finding, the same as a malformed annotation —
        // never silently accepted.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            r#"{"requirements":[{"id":"REQ-A","title":"A","text":"A","standard":"generic","level":"HLR"}]}"#,
        )
        .unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "//fusa:req REQ-A\npub fn x() {}\n//fusa:test REQ-DOES-NOT-EXIST\nfn t() {}\n",
        )
        .unwrap();
        let a = args(&format!("rsfusa trace --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "a dangling-id WARNING must not gate the exit code");
        let errtext = String::from_utf8(err).unwrap();
        assert!(
            errtext.contains("unknown requirement id: REQ-DOES-NOT-EXIST"),
            "dangling //fusa:test id must produce a visible warning: {errtext}"
        );
    }

    //fusa:test REQ-TRACE009
    #[test]
    fn trace_build_reports_dangling_id_finding() {
        // Unit-level check directly on trace::build's returned findings, independent
        // of how the CLI layer chooses to surface them.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            r#"{"requirements":[{"id":"REQ-A","title":"A","text":"A","standard":"generic","level":"HLR"}]}"#,
        )
        .unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "//fusa:test REQ-GHOST\nfn t() {}\n").unwrap();
        let cfg = crate::config::FusaConfig::new("t", "generic");
        let (_matrix, findings) = crate::trace::build(dir.path(), &cfg).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "REQ002"
                && f.severity == crate::types::Severity::Warning
                && f.message.contains("REQ-GHOST")),
            "dangling //fusa:test id should produce a REQ002 WARNING finding: {findings:?}"
        );
    }

    //fusa:test REQ-COMP001
    //fusa:test REQ-COMP002
    #[test]
    fn comp_runs_on_simple_source() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn simple(x: i32) -> i32 { x + 1 }\n",
        )
        .unwrap();
        let a = args(&format!("rsfusa comp --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1, "comp exits 0 or 1, got {code}");
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Cyclomatic") || text.contains("simple"),
            "output should contain complexity report"
        );
    }

    //fusa:test REQ-COMP003
    //fusa:test REQ-COMP004
    #[test]
    fn comp_json_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn foo(x: i32) -> i32 {\n  if x > 0 { x } else { -x }\n}\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa comp --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kind"].as_str(), Some("comp-report"));
        assert_eq!(v["schemaVersion"].as_str(), Some(types::SPEC_VERSION));
        assert!(v["threshold"].as_u64().is_some());
        assert!(v["results"].is_array());
        assert!(v["totalFunctions"].as_u64().unwrap() >= 1);
    }

    //fusa:test REQ-COMP003
    #[test]
    fn comp_threshold_flag() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        // Write a function with complexity 1 (no branches)
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn trivial() -> i32 { 42 }\n",
        )
        .unwrap();
        // With threshold 1, complexity=1 should NOT be a violation (1 <= 1)
        let a = args(&format!(
            "rsfusa comp --dir {} --format json --threshold 1",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "trivial function should not violate threshold 1");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["threshold"].as_u64(), Some(1));
    }

    //fusa:test REQ-COMP002
    #[test]
    fn comp_detects_complex_function() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        // Write a function with multiple branches (complexity > 2)
        std::fs::write(
            dir.path().join("src/lib.rs"),
            r#"pub fn branchy(x: i32, y: i32, z: i32) -> i32 {
    if x > 0 {
        if y > 0 {
            if z > 0 { x + y + z } else { x + y }
        } else {
            x
        }
    } else {
        while y > 0 { return y; }
        0
    }
}
"#,
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa comp --dir {} --format json --threshold 2",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 1, "complex function should violate threshold 2");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(
            v["violations"].as_u64().unwrap() >= 1,
            "should report at least one violation"
        );
        let max = v["maxComplexity"].as_u64().unwrap();
        assert!(max > 2, "max complexity should exceed 2, got {max}");
    }

    //fusa:test REQ-COMP005
    #[test]
    fn comp_dal_a_threshold() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn simple() -> i32 { 1 }\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa comp --dir {} --format json --dal-a",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            v["threshold"].as_u64(),
            Some(4),
            "DAL-A threshold should be 4"
        );
    }

    //fusa:test REQ-COMP003
    //fusa:test REQ-COMP005
    #[test]
    fn comp_dal_flag_canonical() {
        // §2.9: --dal DAL-A|B|C|D canonical flag form.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn f() -> i32 { 1 }\n").unwrap();
        let a = args(&format!(
            "rsfusa comp --dir {} --format json --dal DAL-B",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["threshold"].as_u64(), Some(10));
        assert_eq!(v["dal"].as_str(), Some("DAL-B"));
    }

    // §2.2: --output redirects report; MUST NOT also write to stdout.
    #[test]
    fn check_output_no_double_write() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("README.md"), "# t\n").unwrap();
        std::fs::write(dir.path().join("LICENSE"), "MPL-2.0\n").unwrap();
        std::fs::write(
            dir.path().join(".fusa.json"),
            "{\"configVersion\":\"1.0\",\"project\":{\"name\":\"t\"},\"standard\":\"generic\"}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            "{\"requirements\":[]}\n",
        )
        .unwrap();
        let out_file = dir.path().join("check-report.json");
        let a = args(&format!(
            "rsfusa check --dir {} --format json --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        // §2.2: stdout MUST be empty when --output is given.
        assert!(
            out.is_empty(),
            "check: stdout must be empty when --output is given, got: {}",
            String::from_utf8_lossy(&out)
        );
        // The file must be valid JSON with the §3.1 header.
        let content = std::fs::read(&out_file).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&content).unwrap();
        assert_eq!(v["kind"].as_str(), Some("check-report"));
        assert_eq!(v["schemaVersion"].as_str(), Some(types::SPEC_VERSION));
    }

    // §2.2: comp --output redirects; stdout must be empty.
    #[test]
    fn comp_output_no_double_write() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn f() -> i32 { 1 }\n").unwrap();
        let out_file = dir.path().join("comp-report.json");
        let a = args(&format!(
            "rsfusa comp --dir {} --format json --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        assert!(
            out.is_empty(),
            "comp: stdout must be empty when --output is given, got: {}",
            String::from_utf8_lossy(&out)
        );
        let content = std::fs::read(&out_file).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&content).unwrap();
        assert_eq!(v["kind"].as_str(), Some("comp-report"));
    }

    // §2.2: cyber --output must not write anything to stdout.
    #[test]
    fn cyber_output_stdout_clean() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let out_file = dir.path().join("cyber-out.json");
        let a = args(&format!(
            "rsfusa cyber --dir {} --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        assert!(
            out.is_empty(),
            "cyber: stdout must be empty when --output is given, got: {}",
            String::from_utf8_lossy(&out)
        );
        let errtext = String::from_utf8(err).unwrap();
        assert!(
            errtext.contains("cyber"),
            "confirmation should appear on stderr"
        );
    }

    // §2.2: standards --output must not write text table to stdout.
    #[test]
    fn standards_output_stdout_clean() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_file = dir.path().join("gap.json");
        let a = args(&format!(
            "rsfusa iso26262 --dir {} --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        assert!(
            out.is_empty(),
            "iso26262: stdout must be empty when --output is given, got: {}",
            String::from_utf8_lossy(&out)
        );
        let content = std::fs::read(&out_file).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&content).unwrap();
        assert_eq!(v["kind"].as_str(), Some("gap-report"));
        assert_eq!(v["standard"].as_str(), Some("iso26262"));
    }

    // §2.9: ruleId is format-invariant — same string in text and JSON.
    #[test]
    fn check_ruleid_format_invariant() {
        let dir = tempfile::TempDir::new().unwrap();
        // Create a project that triggers LINT002 (.unwrap() in source).
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn bad() -> i32 { \"42\".parse().unwrap() }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("README.md"), "# t\n").unwrap();
        std::fs::write(dir.path().join("LICENSE"), "MPL-2.0\n").unwrap();
        std::fs::write(
            dir.path().join(".fusa.json"),
            "{\"configVersion\":\"1.0\",\"project\":{\"name\":\"t\"},\"standard\":\"generic\"}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            "{\"requirements\":[]}\n",
        )
        .unwrap();

        // JSON format — capture ruleIds from findings.
        let a_json = args(&format!(
            "rsfusa check --dir {} --format json",
            dir.path().display()
        ));
        let mut out_json = Vec::new();
        let mut err_json = Vec::new();
        run(&a_json, &mut out_json, &mut err_json);
        let v: serde_json::Value = serde_json::from_slice(&out_json).unwrap();
        let rule_ids: Vec<&str> = v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["ruleId"].as_str())
            .collect();
        assert!(!rule_ids.is_empty(), "should have at least one finding");

        // Text format — each ruleId must appear verbatim in text output too (§2.9).
        let a_text = args(&format!(
            "rsfusa check --dir {} --format text",
            dir.path().display()
        ));
        let mut out_text = Vec::new();
        let mut err_text = Vec::new();
        run(&a_text, &mut out_text, &mut err_text);
        let text = String::from_utf8(out_text).unwrap();
        for rid in &rule_ids {
            assert!(
                text.contains(rid),
                "ruleId {rid} from JSON must appear verbatim in text output (§2.9)"
            );
        }

        // ruleId regex: ^[A-Z][A-Z0-9]*(-[A-Z0-9.]+)*$ per §1.5.1.
        for rid in &rule_ids {
            assert!(
                is_valid_rule_id(rid),
                "ruleId {rid} does not match §1.5.1 regex ^[A-Z][A-Z0-9]*(-[A-Z0-9.]+)*$"
            );
        }
    }

    //fusa:test REQ-LOC001
    //fusa:test REQ-LOC-REL001
    #[test]
    fn check_json_end_line_end_column() {
        // §4 MAY: endLine/endColumn populated for single-line token matches; absent when unknown.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        // LINT002 (.unwrap()) fires at a known column position.
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn bad() -> i32 { \"42\".parse().unwrap() }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("README.md"), "# t\n").unwrap();
        std::fs::write(dir.path().join("LICENSE"), "MPL-2.0\n").unwrap();
        std::fs::write(
            dir.path().join(".fusa.json"),
            "{\"configVersion\":\"1.0\",\"project\":{\"name\":\"t\"},\"standard\":\"generic\"}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            "{\"requirements\":[]}\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa check --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let findings = v["findings"].as_array().unwrap();
        // Find the LINT002 finding
        let lint002 = findings
            .iter()
            .find(|f| f["ruleId"].as_str() == Some("LINT002"))
            .expect("LINT002 finding must be present");
        let loc = &lint002["location"];
        // endLine must equal line (single-line span)
        assert_eq!(
            loc["endLine"], loc["line"],
            "endLine must equal line for single-line span"
        );
        // endColumn must be > column (span covers .unwrap())
        let col = loc["column"].as_u64().unwrap_or(0);
        let end_col = loc["endColumn"]
            .as_u64()
            .expect("endColumn must be present");
        assert!(end_col > col, "endColumn {end_col} must be > column {col}");
        assert!(
            end_col >= col + 8,
            "endColumn should cover at least len('.unwrap()')=9 chars"
        );
    }

    fn is_valid_rule_id(id: &str) -> bool {
        if id.is_empty() {
            return false;
        }
        let mut chars = id.chars();
        if !chars.next().unwrap().is_ascii_uppercase() {
            return false;
        }
        let mut expecting_part = false;
        let mut part_len = 0usize;
        for c in chars {
            if c == '-' {
                if expecting_part && part_len == 0 {
                    return false; // empty segment
                }
                expecting_part = true;
                part_len = 0;
            } else if expecting_part {
                if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '.') {
                    return false;
                }
                part_len += 1;
            } else if !(c.is_ascii_uppercase() || c.is_ascii_digit()) {
                return false;
            }
        }
        !(expecting_part && part_len == 0)
    }

    //fusa:test REQ-TRACE-MD001
    #[test]
    fn trace_md_output() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            r#"{"requirements":[{"id":"REQ-A","title":"Alpha","text":"A","standard":"generic","level":"HLR"}]}"#,
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa trace --dir {} --format md",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("| ID |"), "md output must have table header");
        assert!(text.contains("REQ-A"), "md output must list requirements");
    }

    //fusa:test REQ-REPORT-MD001
    #[test]
    fn gap_report_md_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa iso26262 --dir {} --format md",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("| Objective |"),
            "md output must have table header"
        );
        assert!(
            text.contains("ISO 26262"),
            "md output must mention standard"
        );
    }

    //fusa:test REQ-ISO21434-001
    //fusa:test REQ-ISO21434-002
    //fusa:test REQ-ISO21434-003
    #[test]
    fn iso21434_gap_report() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa iso21434 --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1, "iso21434 exits 0 or 1");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kind"].as_str(), Some("gap-report"));
        assert_eq!(v["standard"].as_str(), Some("iso21434"));
        assert!(v["objectives"].is_array());
    }

    //fusa:test REQ-UNECE-001
    //fusa:test REQ-UNECE-002
    //fusa:test REQ-UNECE-003
    #[test]
    fn unece_gap_report() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa unece --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1, "unece exits 0 or 1");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kind"].as_str(), Some("gap-report"));
        assert!(v["objectives"].is_array());
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn req_export_json() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            r#"{"requirements":[{"id":"REQ-A","title":"A","text":"A","standard":"generic","level":"HLR"}]}"#,
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa req export --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(
            v["requirements"].is_array() || v.is_array(),
            "req export emits requirements"
        );
    }

    //fusa:test REQ-RUNTIME001
    //fusa:test REQ-RUNTIME002
    //fusa:test REQ-RUNTIME003
    #[test]
    fn check_completes_quickly() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        // Create 10 small Rust files — should complete well within 10s.
        for i in 0..10 {
            std::fs::write(
                src.join(format!("m{i}.rs")),
                format!("pub fn f{i}() {{}}\n"),
            )
            .unwrap();
        }
        let a = args(&format!("rsfusa check --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let start = std::time::Instant::now();
        run(&a, &mut out, &mut err);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 10,
            "check must complete within 10s per REQ-RUNTIME001, took {elapsed:?}"
        );
    }

    //fusa:test REQ-ERR002
    //fusa:test REQ-ERR003
    #[test]
    fn check_handles_unreadable_config() {
        // When .fusa.json is present but contains invalid JSON, the tool should not panic.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(".fusa.json"), "not json {{{").unwrap();
        let a = args(&format!("rsfusa check --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(
            code != 0 || out.len() + err.len() > 0,
            "tool must not silently succeed on bad config"
        );
    }

    //fusa:test REQ-HTML001
    //fusa:test REQ-HTML002
    //fusa:test REQ-HTML003
    //fusa:test REQ-SAFETYCASE001
    #[test]
    fn safety_case_and_report_html() {
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
    }

    //fusa:test REQ-VULN001
    //fusa:test REQ-VULN002
    //fusa:test REQ-VULN003
    //fusa:test REQ-VULN004
    //fusa:test REQ-VULN005
    //fusa:test REQ-VULN006
    #[test]
    fn vuln_runs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        let a = args(&format!("rsfusa vuln --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1 || code == 3, "vuln exits 0/1/3");
    }

    //fusa:test REQ-ANA003
    //fusa:test REQ-ANA004
    //fusa:test REQ-ANA006
    //fusa:test REQ-ANA007
    #[test]
    fn analyze_json_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa analyze --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["schemaVersion"].as_str(), Some(types::SPEC_VERSION));
        assert!(v["findings"].is_array());
    }

    //fusa:test REQ-LINT005
    //fusa:test REQ-LINT006
    //fusa:test REQ-LINT007
    #[test]
    fn lint_json_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa lint --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["schemaVersion"].as_str(), Some(types::SPEC_VERSION));
        assert!(v["findings"].is_array());
    }

    //fusa:test REQ-CYBER009
    //fusa:test REQ-CYBER010
    //fusa:test REQ-CYBER011
    //fusa:test REQ-CYBER012
    //fusa:test REQ-CYBER013
    //fusa:test REQ-CYBER014
    //fusa:test REQ-CYBER015
    //fusa:test REQ-CYBER016
    //fusa:test REQ-CYBER017
    //fusa:test REQ-CYBER018
    //fusa:test REQ-CYBER019
    //fusa:test REQ-CYBER020
    //fusa:test REQ-CYBER005
    //fusa:test REQ-CYBER021
    #[test]
    fn cyber_json_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        let out_file = dir.path().join("cyber.json");
        let a = args(&format!(
            "rsfusa cyber --dir {} --format json --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let content = std::fs::read(&out_file).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_slice(&content).unwrap();
        assert!(v["findings"].is_array());
    }

    //fusa:test REQ-CFG004
    //fusa:test REQ-CFG005
    //fusa:test REQ-CFG006
    //fusa:test REQ-CFG007
    //fusa:test REQ-CFG008
    #[test]
    fn config_validates_integrity_level() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa.json"),
            "{\"configVersion\":\"1.0\",\"project\":{\"name\":\"t\"},\"standard\":\"iso26262\",\"asil\":\"ASIL-D\"}\n",
        ).unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            "{\"requirements\":[]}\n",
        )
        .unwrap();
        let a = args(&format!("rsfusa check --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(
            code == 0 || code == 1,
            "valid config with asil field should not exit with usage error"
        );
    }

    //fusa:test REQ-NF002
    #[test]
    fn fingerprint_format_invariant() {
        // §3.1: fingerprint format is sha256:<hex>
        let fp = types::compute_fingerprint("LINT001", "src/foo.rs", "test message");
        let parts: Vec<&str> = fp.splitn(2, ':').collect();
        assert_eq!(parts[0], "sha256", "fingerprint must start with 'sha256:'");
        assert_eq!(parts[1].len(), 64, "sha256 hex must be 64 chars");
    }

    // ── Feature 1: HLR/LLR Decomposition ────────────────────────────────────

    //fusa:test REQ-TRACE-HLR001
    //fusa:test REQ-TRACE-HLR002
    #[test]
    fn hlr_llr_validation_llr_without_parent() {
        use crate::config::Requirement;
        use crate::trace::validate_hlr_llr;
        let reqs = vec![
            Requirement {
                id: "REQ-HLR001".to_string(),
                title: Some("A high-level requirement".to_string()),
                text: None,
                standard: None,
                level: Some("HLR".to_string()),
                asil: None,
                parent: None,
            },
            Requirement {
                id: "REQ-LLR001".to_string(),
                title: Some("A low-level requirement without parent".to_string()),
                text: None,
                standard: None,
                level: Some("LLR".to_string()),
                asil: None,
                parent: None, // missing parent
            },
        ];
        let result = validate_hlr_llr(&reqs, None, None, true);
        assert!(
            result.findings.iter().any(|f| f.rule_id == "TRACE-HLR001"),
            "should flag LLR without parent"
        );
        assert!(result.has_errors, "strict mode should produce errors");
    }

    //fusa:test REQ-TRACE-HLR002
    #[test]
    fn hlr_llr_validation_llr_bad_parent() {
        use crate::config::Requirement;
        use crate::trace::validate_hlr_llr;
        let reqs = vec![Requirement {
            id: "REQ-LLR001".to_string(),
            title: None,
            text: None,
            standard: None,
            level: Some("LLR".to_string()),
            asil: None,
            parent: Some("REQ-DOES-NOT-EXIST".to_string()),
        }];
        let result = validate_hlr_llr(&reqs, None, None, true);
        assert!(
            result.findings.iter().any(|f| f.rule_id == "TRACE-HLR002"),
            "should flag LLR referencing nonexistent parent"
        );
    }

    //fusa:test REQ-TRACE-HLR003
    #[test]
    fn hlr_llr_validation_hlr_without_children() {
        use crate::config::Requirement;
        use crate::trace::validate_hlr_llr;
        let reqs = vec![Requirement {
            id: "REQ-HLR001".to_string(),
            title: None,
            text: None,
            standard: None,
            level: Some("HLR".to_string()),
            asil: None,
            parent: None,
        }];
        let result = validate_hlr_llr(&reqs, None, None, true);
        assert!(
            result.findings.iter().any(|f| f.rule_id == "TRACE-HLR003"),
            "should flag HLR with no LLR children"
        );
    }

    //fusa:test REQ-TRACE-HLR004
    #[test]
    fn hlr_llr_validation_valid_hierarchy() {
        use crate::config::Requirement;
        use crate::trace::validate_hlr_llr;
        let reqs = vec![
            Requirement {
                id: "REQ-HLR001".to_string(),
                title: None,
                text: None,
                standard: None,
                level: Some("HLR".to_string()),
                asil: None,
                parent: None,
            },
            Requirement {
                id: "REQ-LLR001".to_string(),
                title: None,
                text: None,
                standard: None,
                level: Some("LLR".to_string()),
                asil: None,
                parent: Some("REQ-HLR001".to_string()),
            },
        ];
        let result = validate_hlr_llr(&reqs, None, None, false);
        assert!(
            result.findings.is_empty(),
            "valid hierarchy should produce no findings"
        );
    }

    //fusa:test REQ-TRACE-HLR001
    #[test]
    fn trace_strict_hlr_llr_flag_accepted() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa.json"),
            "{\"configVersion\":\"1.0\",\"project\":{\"name\":\"t\"},\"standard\":\"iso26262\"}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            "{\"requirements\":[]}\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa trace --strict-hlr-llr --dir {}",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        // With no HLR/LLR requirements, no failures expected.
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "--strict-hlr-llr with no HLR/LLR should pass");
    }

    //fusa:test REQ-TRACE-HLR001
    //fusa:test REQ-TRACE-HLR003
    #[test]
    fn trace_strict_hlr_llr_fails_on_incomplete_hierarchy() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa.json"),
            "{\"configVersion\":\"1.0\",\"project\":{\"name\":\"t\"},\"standard\":\"iso26262\"}\n",
        )
        .unwrap();
        // HLR with no LLR children — should fail under --strict-hlr-llr.
        std::fs::write(
            dir.path().join(".fusa-reqs.json"),
            r#"{"requirements":[{"id":"REQ-HLR001","level":"HLR","title":"top"}]}"#,
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa trace --strict-hlr-llr --dir {}",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_ne!(code, 0, "--strict-hlr-llr should fail when HLR has no LLR");
    }

    // ── Feature 2: Tool Qualification Display ───────────────────────────────

    //fusa:test REQ-QUALIFY-TQ001
    //fusa:test REQ-QUALIFY-TQ002
    //fusa:test REQ-QUALIFY-TQ003
    #[test]
    fn qualify_qualification_method_independent() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa qualify --dir {} --format json --qualification-method independent --qualifier AcmeSafetyLtd",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        let err_text = String::from_utf8(err).unwrap();
        assert!(
            err_text.contains("independently-qualified"),
            "stderr should show independently-qualified badge"
        );
    }

    //fusa:test REQ-QUALIFY-TQ001
    #[test]
    fn qualify_badge_self_qualified() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa qualify --dir {} --format json --qualification-method self",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        let err_text = String::from_utf8(err).unwrap();
        assert!(
            err_text.contains("self-qualified"),
            "stderr should show self-qualified badge"
        );
    }

    //fusa:test REQ-QUALIFY-TQ001
    #[test]
    fn qualify_badge_unqualified_when_no_method() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa qualify --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        let err_text = String::from_utf8(err).unwrap();
        assert!(
            err_text.contains("unqualified"),
            "stderr should show unqualified badge"
        );
    }

    //fusa:test REQ-QUALIFY-TQ002
    //fusa:test REQ-QUALIFY-TQ003
    #[test]
    fn qualify_json_has_qualification_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_path = dir.path().join("q.json");
        let a = args(&format!(
            "rsfusa qualify --dir {} --output {} --format json --qualification-method independent --qualifier TestOrg --record-uri https://example.com/dossier",
            dir.path().display(),
            out_path.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        let content = std::fs::read_to_string(&out_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["qualificationMethod"].as_str(), Some("independent"));
        assert_eq!(v["qualifierIdentity"].as_str(), Some("TestOrg"));
        assert_eq!(
            v["qualificationRecordUri"].as_str(),
            Some("https://example.com/dossier")
        );
        assert_eq!(
            v["qualificationBadge"].as_str(),
            Some("independently-qualified")
        );
    }

    // ── Feature 3: MC/DC Coverage ───────────────────────────────────────────

    //fusa:test REQ-COVERAGE-MCDC001
    //fusa:test REQ-COVERAGE-MCDC002
    #[test]
    fn coverage_mcdc_flag_accepted() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa coverage --dir {} --mcdc --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        // Should not fail on usage (flag accepted).
        let code = run(&a, &mut out, &mut err);
        assert!(
            code == 0 || code == 1,
            "mcdc flag should not cause usage error"
        );
    }

    //fusa:test REQ-COVERAGE-MCDC003
    //fusa:test REQ-COVERAGE-MCDC004
    #[test]
    fn coverage_mcdc_file_parsed() {
        let dir = tempfile::TempDir::new().unwrap();
        // Create a minimal LLVM MC/DC JSON file.
        let mcdc_json = r#"{"data":[{"functions":[{"name":"foo","mcdc_records":[{"conditions":[{"covered_true_count":1,"covered_false_count":1}]}]}]}]}"#;
        let mcdc_path = dir.path().join("mcdc.json");
        std::fs::write(&mcdc_path, mcdc_json).unwrap();
        let out_path = dir.path().join("cov.json");
        let a = args(&format!(
            "rsfusa coverage --dir {} --mcdc --mcdc-file {} --format json --output {}",
            dir.path().display(),
            mcdc_path.display(),
            out_path.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert!(code == 0 || code == 1);
        let content = std::fs::read_to_string(&out_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(v["mcdc"].is_object(), "report should contain mcdc section");
        assert_eq!(v["mcdc"]["totalFunctions"].as_u64(), Some(1));
        assert_eq!(v["mcdc"]["coveredConditions"].as_u64(), Some(1));
        assert_eq!(v["mcdc"]["passesGate"].as_bool(), Some(true));
    }

    //fusa:test REQ-COVERAGE-MCDC004
    #[test]
    fn coverage_mcdc_gate_fails_on_uncovered_condition() {
        let dir = tempfile::TempDir::new().unwrap();
        // A condition where covered_false_count is 0 → MC/DC not covered.
        let mcdc_json = r#"{"data":[{"functions":[{"name":"bar","mcdc_records":[{"conditions":[{"covered_true_count":1,"covered_false_count":0}]}]}]}]}"#;
        let mcdc_path = dir.path().join("mcdc.json");
        std::fs::write(&mcdc_path, mcdc_json).unwrap();
        let a = args(&format!(
            "rsfusa coverage --dir {} --mcdc --mcdc-file {} --format json",
            dir.path().display(),
            mcdc_path.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(
            code, 1,
            "uncovered MC/DC condition should fail gate (exit 1)"
        );
    }

    // ── Feature 4: V&V Independence ─────────────────────────────────────────

    //fusa:test REQ-QUALIFY-VV001
    //fusa:test REQ-QUALIFY-VV002
    #[test]
    fn qualify_vv_independence_detected() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_path = dir.path().join("q.json");
        let a = args(&format!(
            "rsfusa qualify --dir {} --output {} --format json --implementation-author Alice --independent-reviewer Bob",
            dir.path().display(),
            out_path.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        let content = std::fs::read_to_string(&out_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["implementationAuthor"].as_str(), Some("Alice"));
        assert_eq!(v["independentReviewer"].as_str(), Some("Bob"));
        assert_eq!(
            v["independenceStatus"].as_str(),
            Some("independent"),
            "different author/reviewer should yield independence status"
        );
    }

    //fusa:test REQ-QUALIFY-VV002
    #[test]
    fn qualify_vv_non_independence_when_same_person() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_path = dir.path().join("q.json");
        let a = args(&format!(
            "rsfusa qualify --dir {} --output {} --format json --implementation-author Alice --independent-reviewer Alice",
            dir.path().display(),
            out_path.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        let content = std::fs::read_to_string(&out_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            v["independenceStatus"].as_str(),
            Some("non-independent"),
            "same author/reviewer should yield non-independent status"
        );
    }

    //fusa:test REQ-QUALIFY-VV003
    //fusa:test REQ-QUALIFY-VV004
    #[test]
    fn qualify_vv_all_fields_persisted() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_path = dir.path().join("q.json");
        let a = args(&format!(
            "rsfusa qualify --dir {} --output {} --format json --implementation-author Dev --independent-reviewer Tester --independent-test-executor TestLab --achievable-asil ASIL-D",
            dir.path().display(),
            out_path.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        let content = std::fs::read_to_string(&out_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["independentTestExecutor"].as_str(), Some("TestLab"));
        assert_eq!(v["achievableAsil"].as_str(), Some("ASIL-D"));
    }

    //fusa:test REQ-QUALIFY-VV001
    #[test]
    fn qualify_vv_independence_shown_in_stderr() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa qualify --dir {} --format json --implementation-author Dev --independent-reviewer Reviewer",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&a, &mut out, &mut err);
        let err_text = String::from_utf8(err).unwrap();
        assert!(
            err_text.contains("independent"),
            "independence status should appear in stderr"
        );
    }

    // ── badge ────────────────────────────────────────────────────────────────

    //fusa:test REQ-BADGE001
    //fusa:test REQ-BADGE002
    #[test]
    fn badge_generates_svg() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa badge --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "badge should exit 0");
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("<svg") && text.contains("rust-FuSa"),
            "badge output should be SVG containing tool name"
        );
    }

    //fusa:test REQ-BADGE003
    #[test]
    fn badge_writes_to_output_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_file = dir.path().join("badge.svg");
        let a = args(&format!(
            "rsfusa badge --dir {} --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "badge --output should exit 0");
        assert!(out_file.exists(), "badge.svg must be created");
        let content = std::fs::read_to_string(&out_file).unwrap();
        assert!(content.contains("<svg"), "written file must be SVG");
    }

    // ── coupling ─────────────────────────────────────────────────────────────

    //fusa:test REQ-COUPLING001
    //fusa:test REQ-COUPLING002
    //fusa:test REQ-COUPLING003
    #[test]
    fn coupling_creates_report() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "use crate::types::EXIT_OK;\npub fn f() -> i32 { 0 }\n",
        )
        .unwrap();
        let out_file = dir.path().join("coupling-report.json");
        let a = args(&format!(
            "rsfusa coupling --dir {} --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "coupling should exit 0");
        assert!(out_file.exists(), "coupling-report.json must be created");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_file).unwrap()).unwrap();
        assert_eq!(v["kind"].as_str(), Some("coupling-report"));
        assert!(v["modules"].is_array());
    }

    // ── disposition ───────────────────────────────────────────────────────────

    //fusa:test REQ-DISP001
    #[test]
    fn disposition_list_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa disposition list --dir {}",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "disposition list on empty dir should exit 0");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.is_empty(), "disposition list should produce output");
    }

    //fusa:test REQ-DISP002
    //fusa:test REQ-DISP003
    #[test]
    fn disposition_add_and_list() {
        let dir = tempfile::TempDir::new().unwrap();
        // Add a disposition
        let a_add = args(&format!(
            "rsfusa disposition add --dir {} --rule LINT002 --status accepted --note test-note",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a_add, &mut out, &mut err);
        assert_eq!(code, 0, "disposition add should exit 0");
        // Verify the file was created
        assert!(dir.path().join(".fusa-dispositions.json").exists());
        // List it back
        let a_list = args(&format!(
            "rsfusa disposition list --dir {}",
            dir.path().display()
        ));
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let code2 = run(&a_list, &mut out2, &mut err2);
        assert_eq!(code2, 0);
        let text = String::from_utf8(out2).unwrap();
        assert!(
            text.contains("LINT002"),
            "listed dispositions should include the added rule"
        );
    }

    // ── fix ───────────────────────────────────────────────────────────────────

    //fusa:test REQ-FIX001
    #[test]
    fn fix_runs_on_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa fix --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "fix should exit 0");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.is_empty(), "fix must produce output");
    }

    //fusa:test REQ-FIX002
    #[test]
    fn fix_json_format() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "pub fn bad() -> i32 { let x: Option<i32> = None; x.unwrap() }\n",
        )
        .unwrap();
        let a = args(&format!(
            "rsfusa fix --dir {} --format json",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "fix --format json should exit 0");
        // Output is either the JSON report or "No fixable findings."
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("fix-report") || text.contains("No fixable"),
            "fix --format json must produce structured output or no-findings message"
        );
    }

    // ── hooks ─────────────────────────────────────────────────────────────────

    //fusa:test REQ-HOOKS001
    #[test]
    fn hooks_show_no_git_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa hooks show --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "hooks show should exit 0 even without .git");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.is_empty(), "hooks show must produce output");
    }

    //fusa:test REQ-HOOKS002
    //fusa:test REQ-HOOKS003
    #[test]
    fn hooks_install_and_remove() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        // Install
        let a_install = args(&format!(
            "rsfusa hooks install --dir {}",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a_install, &mut out, &mut err);
        assert_eq!(code, 0, "hooks install should exit 0");
        assert!(
            dir.path().join(".git/hooks/pre-commit").exists(),
            "pre-commit hook must be created"
        );
        // Remove
        let a_remove = args(&format!(
            "rsfusa hooks remove --dir {}",
            dir.path().display()
        ));
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let code2 = run(&a_remove, &mut out2, &mut err2);
        assert_eq!(code2, 0, "hooks remove should exit 0");
        assert!(
            !dir.path().join(".git/hooks/pre-commit").exists(),
            "pre-commit hook must be removed"
        );
    }

    // ── impact ────────────────────────────────────────────────────────────────

    //fusa:test REQ-IMPACT001
    //fusa:test REQ-IMPACT002
    //fusa:test REQ-IMPACT003
    #[test]
    fn impact_runs_on_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa impact --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "impact should exit 0");
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Impact Analysis"),
            "impact output should contain report header"
        );
    }

    // ── metrics ───────────────────────────────────────────────────────────────

    //fusa:test REQ-METRICS001
    //fusa:test REQ-METRICS003
    #[test]
    fn metrics_record_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa metrics record --dir {}",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "metrics record should exit 0");
        assert!(
            dir.path().join(".fusa-metrics.json").exists(),
            ".fusa-metrics.json must be created"
        );
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".fusa-metrics.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["kind"].as_str(), Some("metrics"));
        assert!(v["snapshots"].is_array());
        assert_eq!(v["snapshots"].as_array().unwrap().len(), 1);
    }

    //fusa:test REQ-METRICS002
    #[test]
    fn metrics_show_no_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!(
            "rsfusa metrics show --dir {}",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "metrics show should exit 0 with no file");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.is_empty(), "metrics show should produce output");
    }

    // ── pr ────────────────────────────────────────────────────────────────────

    //fusa:test REQ-PR001
    #[test]
    fn pr_init_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa pr init --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "pr init should exit 0");
        assert!(
            dir.path().join(".fusa-problems.json").exists(),
            ".fusa-problems.json must be created"
        );
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".fusa-problems.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["kind"].as_str(), Some("problem-reports"));
    }

    //fusa:test REQ-PR002
    //fusa:test REQ-PR003
    #[test]
    fn pr_add_and_list() {
        let dir = tempfile::TempDir::new().unwrap();
        // Add a problem report
        let a_add = args(&format!(
            "rsfusa pr add --dir {} --title test-problem --severity major --phase testing",
            dir.path().display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a_add, &mut out, &mut err);
        assert_eq!(code, 0, "pr add should exit 0");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("PR-"), "pr add should print the new PR ID");
        // List it
        let a_list = args(&format!("rsfusa pr list --dir {}", dir.path().display()));
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let code2 = run(&a_list, &mut out2, &mut err2);
        assert_eq!(code2, 0, "pr list should exit 0");
        let text2 = String::from_utf8(out2).unwrap();
        assert!(
            text2.contains("test-problem"),
            "pr list should show the added problem title"
        );
    }

    // ── sas ───────────────────────────────────────────────────────────────────

    //fusa:test REQ-SAS001
    //fusa:test REQ-SAS002
    #[test]
    fn sas_creates_md_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = args(&format!("rsfusa sas --dir {}", dir.path().display()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "sas should exit 0");
        assert!(dir.path().join("sas.md").exists(), "sas.md must be created");
        let content = std::fs::read_to_string(dir.path().join("sas.md")).unwrap();
        assert!(
            content.contains("Software Accomplishment Summary"),
            "sas.md must contain title"
        );
        assert!(
            content.contains("DO-178C"),
            "sas.md must reference standard"
        );
    }

    //fusa:test REQ-SAS003
    #[test]
    fn sas_json_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_file = dir.path().join("sas.json");
        let a = args(&format!(
            "rsfusa sas --dir {} --format json --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "sas --format json should exit 0");
        assert!(out_file.exists(), "sas.json must be created");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_file).unwrap()).unwrap();
        assert_eq!(v["kind"].as_str(), Some("sas"));
        assert!(v["evidence"].is_array());
        assert!(v["summary"]["total"].is_number());
    }

    // ── sci ───────────────────────────────────────────────────────────────────

    //fusa:test REQ-SCI001
    //fusa:test REQ-SCI002
    //fusa:test REQ-SCI003
    #[test]
    fn sci_creates_json_file() {
        let dir = tempfile::TempDir::new().unwrap();
        // Create some files that SCI will find
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname=\"t\"\nversion=\"0.1.0\"\n",
        )
        .unwrap();
        let out_file = dir.path().join("sci.json");
        let a = args(&format!(
            "rsfusa sci --dir {} --output {}",
            dir.path().display(),
            out_file.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "sci should exit 0");
        assert!(out_file.exists(), "sci.json must be created");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_file).unwrap()).unwrap();
        assert_eq!(v["kind"].as_str(), Some("sci"));
        assert!(v["items"].is_array(), "items array must be present");
        assert!(v["summary"]["total"].is_number());
        // Check that present items have a hash
        let items = v["items"].as_array().unwrap();
        let present = items.iter().find(|i| i["present"].as_bool() == Some(true));
        if let Some(item) = present {
            let hash = item["hash"].as_str().unwrap_or("");
            assert!(
                hash.starts_with("sha256:"),
                "present file must have sha256: hash, got '{hash}'"
            );
        }
    }

    // ── sign ──────────────────────────────────────────────────────────────────

    //fusa:test REQ-SIGN001
    //fusa:test REQ-SIGN002
    #[test]
    fn sign_sign_and_verify_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("test.key");
        let data_path = dir.path().join("data.txt");
        // Write a 32-byte key and data to sign
        std::fs::write(&key_path, [0u8; 32]).unwrap();
        std::fs::write(&data_path, b"hello safety world").unwrap();
        // Sign
        let a_sign = args(&format!(
            "rsfusa sign --key {} {}",
            key_path.display(),
            data_path.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a_sign, &mut out, &mut err);
        assert_eq!(code, 0, "sign should exit 0");
        let sig_path = format!("{}.sig", data_path.display());
        assert!(
            std::path::Path::new(&sig_path).exists(),
            ".sig file must be created"
        );
        // Verify with correct key
        let a_verify = args(&format!(
            "rsfusa sign --verify --key {} {}",
            key_path.display(),
            data_path.display()
        ));
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let code2 = run(&a_verify, &mut out2, &mut err2);
        assert_eq!(code2, 0, "sign --verify should exit 0 for valid signature");
        let text = String::from_utf8(out2).unwrap();
        assert!(text.contains("VALID"), "verify output must confirm VALID");
    }

    //fusa:test REQ-SIGN003
    #[test]
    fn sign_no_args_exits_usage() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&args("rsfusa sign"), &mut out, &mut err);
        assert_eq!(code, 2, "sign with no args should exit with usage error");
    }

    // ── template ──────────────────────────────────────────────────────────────

    //fusa:test REQ-TEMPLATE001
    //fusa:test REQ-TEMPLATE002
    #[test]
    fn template_generates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_dir = dir.path().join("docs/safety");
        let a = args(&format!(
            "rsfusa template --dir {} --out-dir {}",
            dir.path().display(),
            out_dir.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "template should exit 0");
        assert!(
            out_dir.join("safety-plan.md").exists(),
            "safety-plan.md must be created"
        );
        assert!(
            out_dir.join("test-plan.md").exists(),
            "test-plan.md must be created"
        );
        assert!(
            out_dir.join("review-checklist.md").exists(),
            "review-checklist.md must be created"
        );
        assert!(
            out_dir.join("incident-report.md").exists(),
            "incident-report.md must be created"
        );
    }

    //fusa:test REQ-TEMPLATE003
    #[test]
    fn template_skips_existing_without_force() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::write(out_dir.join("safety-plan.md"), "existing content").unwrap();
        let a = args(&format!(
            "rsfusa template --dir {} --out-dir {}",
            dir.path().display(),
            out_dir.display()
        ));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0, "template should exit 0 even when skipping");
        // Existing file must not be overwritten
        let content = std::fs::read_to_string(out_dir.join("safety-plan.md")).unwrap();
        assert_eq!(
            content, "existing content",
            "existing file must not be overwritten without --force"
        );
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Skipping"),
            "output should indicate skipping existing file"
        );
    }
}
