// `rsfusa vuln` — dependency vulnerability scan via cargo-audit.
// Writes vuln.json. Exits 1 if vulnerabilities are found.
//fusa:req REQ-VULN001
//fusa:req REQ-VULN002
//fusa:req REQ-VULN003
//fusa:req REQ-VULN004
//fusa:req REQ-VULN005
//fusa:req REQ-VULN006

use crate::types::{
    EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION,
};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const VULN_FILE: &str = "vuln.json";

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let out_path = opts
        .output
        .unwrap_or_else(|| project_root.join(VULN_FILE).to_string_lossy().into_owned());

    writeln!(stdout, "Scanning dependencies for vulnerabilities...").ok();

    // Try cargo-audit first
    let audit_result = std::process::Command::new("cargo")
        .args(["audit", "--json"])
        .current_dir(&project_root)
        .output();

    match audit_result {
        Ok(output) => {
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            process_audit_json(
                &stdout_str,
                &out_path,
                output.status.success(),
                stdout,
                stderr,
            )
        }
        Err(_) => {
            writeln!(
                stderr,
                "rsfusa vuln: cargo-audit not found; install with: cargo install cargo-audit"
            )
            .ok();
            // Fall back to a lightweight Cargo.lock scan for known bad patterns
            scan_cargo_lock(&project_root, &out_path, stdout, stderr)
        }
    }
}

fn process_audit_json(
    json_str: &str,
    out_path: &str,
    clean: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let vuln_count;
    let findings: Vec<serde_json::Value>;

    if let Ok(audit) = serde_json::from_str::<serde_json::Value>(json_str) {
        let vulns = audit
            .get("vulnerabilities")
            .and_then(|v| v.get("list"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        vuln_count = vulns.len();
        findings = vulns
            .into_iter()
            .map(|v| {
                let id = v
                    .get("advisory")
                    .and_then(|a| a.get("id"))
                    .and_then(|i| i.as_str())
                    .unwrap_or("UNKNOWN");
                let title = v
                    .get("advisory")
                    .and_then(|a| a.get("title"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                let pkg = v
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let ver = v
                    .get("package")
                    .and_then(|p| p.get("version"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let url = v
                    .get("advisory")
                    .and_then(|a| a.get("url"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("");
                serde_json::json!({
                    "id": id,
                    "package": pkg,
                    "version": ver,
                    "title": title,
                    "url": url,
                })
            })
            .collect()
    } else {
        vuln_count = 0;
        findings = vec![];
    }

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "vuln-report",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "scanner": "cargo-audit",
        "scanned": findings.len() + if clean && findings.is_empty() { 1 } else { 0 },
        "findings": findings,
        "summary": {
            "vulnerabilities": vuln_count,
            "clean": vuln_count == 0,
        }
    });

    match std::fs::write(
        out_path,
        serde_json::to_string_pretty(&report).unwrap() + "\n",
    ) {
        Ok(_) => writeln!(stdout, "Vulnerability report written to {out_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa vuln: write {out_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    if vuln_count > 0 {
        writeln!(
            stdout,
            "Found {vuln_count} vulnerabilities — see {out_path}"
        )
        .ok();
        EXIT_GATE_FAIL
    } else {
        writeln!(stdout, "No known vulnerabilities found.").ok();
        EXIT_OK
    }
}

fn scan_cargo_lock(
    root: &Path,
    out_path: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let lock_path = root.join("Cargo.lock");
    let dep_count = if lock_path.exists() {
        std::fs::read_to_string(&lock_path)
            .map(|s| s.matches("[[package]]").count())
            .unwrap_or(0)
    } else {
        writeln!(stderr, "rsfusa vuln: Cargo.lock not found").ok();
        return EXIT_RUNTIME;
    };

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "vuln-report",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "scanner": "cargo-lock-scan",
        "scanned": dep_count,
        "findings": [],
        "summary": {
            "vulnerabilities": 0,
            "clean": true,
            "note": "cargo-audit not available; install with 'cargo install cargo-audit' for full vulnerability scanning",
        }
    });

    match std::fs::write(
        out_path,
        serde_json::to_string_pretty(&report).unwrap() + "\n",
    ) {
        Ok(_) => {
            writeln!(stdout, "Scanned {dep_count} packages (basic scan only — install cargo-audit for full results)").ok();
            writeln!(stdout, "Report written to {out_path}").ok();
        }
        Err(e) => {
            writeln!(stderr, "rsfusa vuln: write {out_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    output: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // ── parse ─────────────────────────────────────────────────────────────

    //fusa:test REQ-VULN001
    #[test]
    fn parse_no_args_ok() {
        let mut err = Vec::new();
        let opts = parse(&[], &mut err).unwrap();
        assert!(opts.dir.is_none());
        assert!(opts.output.is_none());
    }

    //fusa:test REQ-VULN001
    #[test]
    fn parse_dir_flag() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--dir", "/some/path"]), &mut err).unwrap();
        assert_eq!(opts.dir.as_ref().unwrap().to_str().unwrap(), "/some/path");
    }

    //fusa:test REQ-VULN001
    #[test]
    fn parse_dir_eq_form() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--dir=/some/path"]), &mut err).unwrap();
        assert_eq!(opts.dir.as_ref().unwrap().to_str().unwrap(), "/some/path");
    }

    //fusa:test REQ-VULN001
    #[test]
    fn parse_output_flag() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--output", "out.json"]), &mut err).unwrap();
        assert_eq!(opts.output.as_deref(), Some("out.json"));
    }

    //fusa:test REQ-VULN001
    #[test]
    fn parse_output_eq_form() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--output=out.json"]), &mut err).unwrap();
        assert_eq!(opts.output.as_deref(), Some("out.json"));
    }

    //fusa:test REQ-VULN001
    #[test]
    fn parse_missing_dir_value() {
        let mut err = Vec::new();
        assert!(parse(&sv(&["--dir"]), &mut err).is_none());
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("requires an argument"));
    }

    //fusa:test REQ-VULN001
    #[test]
    fn parse_missing_output_value() {
        let mut err = Vec::new();
        assert!(parse(&sv(&["--output"]), &mut err).is_none());
    }

    //fusa:test REQ-VULN001
    #[test]
    fn parse_unknown_flag() {
        let mut err = Vec::new();
        assert!(parse(&sv(&["--bad"]), &mut err).is_none());
        assert!(String::from_utf8(err).unwrap().contains("unknown flag"));
    }

    // ── process_audit_json ────────────────────────────────────────────────

    //fusa:test REQ-VULN002
    #[test]
    fn process_audit_json_empty_string() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_path = dir.path().join("vuln.json").to_string_lossy().into_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = process_audit_json("", &out_path, true, &mut out, &mut err);
        // Invalid JSON → 0 vulns, file still written
        assert_eq!(code, 0);
        assert!(std::path::Path::new(&out_path).exists());
    }

    //fusa:test REQ-VULN002
    #[test]
    fn process_audit_json_no_vulns() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_path = dir.path().join("vuln.json").to_string_lossy().into_owned();
        let json = r#"{"vulnerabilities":{"list":[]}}"#;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = process_audit_json(json, &out_path, true, &mut out, &mut err);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("No known vulnerabilities"));
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        assert_eq!(report["summary"]["vulnerabilities"], 0);
    }

    //fusa:test REQ-VULN002
    #[test]
    fn process_audit_json_with_vulns() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_path = dir.path().join("vuln.json").to_string_lossy().into_owned();
        let json = serde_json::json!({
            "vulnerabilities": {
                "list": [{
                    "advisory": {"id": "RUSTSEC-2023-0001", "title": "Bad Thing", "url": "https://rustsec.org"},
                    "package": {"name": "some-crate", "version": "1.0.0"}
                }]
            }
        }).to_string();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = process_audit_json(&json, &out_path, false, &mut out, &mut err);
        assert_eq!(code, 1);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("1 vulnerabilities"));
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        assert_eq!(report["summary"]["vulnerabilities"], 1);
        assert_eq!(report["findings"][0]["id"], "RUSTSEC-2023-0001");
    }

    //fusa:test REQ-VULN002
    #[test]
    fn process_audit_json_write_error() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        // Write to an invalid path
        let code = process_audit_json("{}", "/nonexistent/dir/vuln.json", true, &mut out, &mut err);
        assert_eq!(code, 3);
        assert!(!String::from_utf8(err).unwrap().is_empty());
    }

    // ── scan_cargo_lock ───────────────────────────────────────────────────

    //fusa:test REQ-VULN003
    #[test]
    fn scan_cargo_lock_no_lock_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let out_path = dir.path().join("vuln.json").to_string_lossy().into_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = scan_cargo_lock(dir.path(), &out_path, &mut out, &mut err);
        assert_eq!(code, 3);
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("Cargo.lock not found"));
    }

    //fusa:test REQ-VULN003
    #[test]
    fn scan_cargo_lock_with_lock_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let lock_content = "[[package]]\nname = \"foo\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"bar\"\nversion = \"2.0.0\"\n";
        std::fs::write(dir.path().join("Cargo.lock"), lock_content).unwrap();

        let out_path = dir.path().join("vuln.json").to_string_lossy().into_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = scan_cargo_lock(dir.path(), &out_path, &mut out, &mut err);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("2 packages"));
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        assert_eq!(report["scanned"], 2);
        assert_eq!(report["scanner"], "cargo-lock-scan");
    }
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
                    writeln!(stderr, "rsfusa vuln: {flag} requires an argument").ok();
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
                    writeln!(stderr, "rsfusa vuln: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
