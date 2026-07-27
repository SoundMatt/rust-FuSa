// `rsfusa diff <baseline.json> <current.json>` — compare two check reports.
// Exits 1 if new findings are introduced (§4.2 fingerprint-based).

use crate::types::{
    EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION,
};
use std::collections::{HashMap, HashSet};
use std::io::Write;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let baseline = match load_report(&opts.baseline, stderr) {
        Some(r) => r,
        None => return EXIT_RUNTIME,
    };
    let current = match load_report(&opts.current, stderr) {
        Some(r) => r,
        None => return EXIT_RUNTIME,
    };

    let baseline_fps: HashSet<String> = baseline
        .iter()
        .filter_map(|f| {
            f.get("fingerprint")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    let current_fps: HashSet<String> = current
        .iter()
        .filter_map(|f| {
            f.get("fingerprint")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    let current_map: HashMap<String, &serde_json::Value> = current
        .iter()
        .filter_map(|f| {
            f.get("fingerprint")
                .and_then(|v| v.as_str())
                .map(|fp| (fp.to_string(), f))
        })
        .collect();
    let baseline_map: HashMap<String, &serde_json::Value> = baseline
        .iter()
        .filter_map(|f| {
            f.get("fingerprint")
                .and_then(|v| v.as_str())
                .map(|fp| (fp.to_string(), f))
        })
        .collect();

    let introduced: Vec<_> = current_fps
        .difference(&baseline_fps)
        .filter_map(|fp| current_map.get(fp))
        .collect();
    let resolved: Vec<_> = baseline_fps
        .difference(&current_fps)
        .filter_map(|fp| baseline_map.get(fp))
        .collect();
    let unchanged = baseline_fps.intersection(&current_fps).count();

    if opts.format.as_deref() == Some("json") {
        let out = serde_json::json!({
            "schemaVersion": SPEC_VERSION,
            "kind": "diff-report",
            "tool": TOOL_NAME,
            "toolVersion": VERSION,
            "language": LANGUAGE,
            "generatedAt": chrono::Utc::now().to_rfc3339(),
            "baseline": opts.baseline,
            "current": opts.current,
            "summary": {
                "introduced": introduced.len(),
                "resolved": resolved.len(),
                "unchanged": unchanged,
            },
            "introduced": introduced,
            "resolved": resolved,
        });
        writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap()).ok();
    } else {
        writeln!(
            stdout,
            "Diff: {} introduced  {} resolved  {} unchanged",
            introduced.len(),
            resolved.len(),
            unchanged
        )
        .ok();
        if !introduced.is_empty() {
            writeln!(stdout, "\nIntroduced:").ok();
            for f in &introduced {
                let rule = f.get("ruleId").and_then(|v| v.as_str()).unwrap_or("?");
                let file = f
                    .get("location")
                    .and_then(|v| v.get("file"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let line = f
                    .get("location")
                    .and_then(|v| v.get("line"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let msg = f.get("message").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(stdout, "  + [{rule}] {file}:{line}: {msg}").ok();
            }
        }
        if !resolved.is_empty() {
            writeln!(stdout, "\nResolved:").ok();
            for f in &resolved {
                let rule = f.get("ruleId").and_then(|v| v.as_str()).unwrap_or("?");
                let file = f
                    .get("location")
                    .and_then(|v| v.get("file"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let line = f
                    .get("location")
                    .and_then(|v| v.get("line"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let msg = f.get("message").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(stdout, "  - [{rule}] {file}:{line}: {msg}").ok();
            }
        }
    }

    if !introduced.is_empty() {
        EXIT_GATE_FAIL
    } else {
        EXIT_OK
    }
}

fn load_report(path: &str, stderr: &mut dyn Write) -> Option<Vec<serde_json::Value>> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) => {
            writeln!(stderr, "rsfusa diff: read {path}: {e}").ok();
            return None;
        }
    };
    let v: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            writeln!(stderr, "rsfusa diff: parse {path}: {e}").ok();
            return None;
        }
    };
    let findings = v
        .get("findings")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    Some(findings)
}

struct Opts {
    baseline: String,
    current: String,
    format: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // ── parse ─────────────────────────────────────────────────────────────

    //fusa:test REQ-LOC001
    #[test]
    fn parse_no_args_returns_none() {
        let mut err = Vec::new();
        assert!(parse(&s(&[]), &mut err).is_none());
        assert!(String::from_utf8(err).unwrap().contains("usage"));
    }

    //fusa:test REQ-LOC001
    #[test]
    fn parse_one_arg_returns_none() {
        let mut err = Vec::new();
        assert!(parse(&s(&["baseline.json"]), &mut err).is_none());
    }

    //fusa:test REQ-LOC001
    #[test]
    fn parse_two_args_ok() {
        let mut err = Vec::new();
        let opts = parse(&s(&["baseline.json", "current.json"]), &mut err).unwrap();
        assert_eq!(opts.baseline, "baseline.json");
        assert_eq!(opts.current, "current.json");
        assert!(opts.format.is_none());
    }

    //fusa:test REQ-LOC001
    #[test]
    fn parse_format_flag() {
        let mut err = Vec::new();
        let opts = parse(&s(&["b.json", "c.json", "--format", "json"]), &mut err).unwrap();
        assert_eq!(opts.format.as_deref(), Some("json"));
    }

    //fusa:test REQ-LOC001
    #[test]
    fn parse_format_eq_form() {
        let mut err = Vec::new();
        let opts = parse(&s(&["b.json", "c.json", "--format=json"]), &mut err).unwrap();
        assert_eq!(opts.format.as_deref(), Some("json"));
    }

    //fusa:test REQ-LOC001
    #[test]
    fn parse_unknown_flag_returns_none() {
        let mut err = Vec::new();
        assert!(parse(&s(&["b.json", "c.json", "--unknown"]), &mut err).is_none());
        assert!(String::from_utf8(err).unwrap().contains("unknown flag"));
    }

    //fusa:test REQ-LOC001
    #[test]
    fn parse_format_missing_value_returns_none() {
        let mut err = Vec::new();
        assert!(parse(&s(&["b.json", "c.json", "--format"]), &mut err).is_none());
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("requires an argument"));
    }

    // ── load_report ───────────────────────────────────────────────────────

    //fusa:test REQ-LOC001
    #[test]
    fn load_report_missing_file_returns_none() {
        let mut err = Vec::new();
        assert!(load_report("/nonexistent/path.json", &mut err).is_none());
        assert!(!String::from_utf8(err).unwrap().is_empty());
    }

    //fusa:test REQ-LOC001
    #[test]
    fn load_report_invalid_json_returns_none() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "not json").unwrap();
        let mut err = Vec::new();
        assert!(load_report(tmp.path().to_str().unwrap(), &mut err).is_none());
    }

    //fusa:test REQ-LOC001
    #[test]
    fn load_report_valid_findings() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let json = r#"{"findings":[{"fingerprint":"abc","ruleId":"R1","message":"msg"}]}"#;
        std::fs::write(tmp.path(), json).unwrap();
        let mut err = Vec::new();
        let findings = load_report(tmp.path().to_str().unwrap(), &mut err).unwrap();
        assert_eq!(findings.len(), 1);
    }

    //fusa:test REQ-LOC001
    #[test]
    fn load_report_empty_findings_key() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), r#"{"findings":[]}"#).unwrap();
        let mut err = Vec::new();
        let findings = load_report(tmp.path().to_str().unwrap(), &mut err).unwrap();
        assert!(findings.is_empty());
    }

    //fusa:test REQ-LOC001
    #[test]
    fn load_report_no_findings_key() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), r#"{"other":"stuff"}"#).unwrap();
        let mut err = Vec::new();
        let findings = load_report(tmp.path().to_str().unwrap(), &mut err).unwrap();
        assert!(findings.is_empty());
    }

    // ── run ───────────────────────────────────────────────────────────────

    fn make_report(fps: &[&str]) -> String {
        let findings: Vec<serde_json::Value> = fps
            .iter()
            .map(|fp| {
                serde_json::json!({
                    "fingerprint": fp,
                    "ruleId": "R1",
                    "message": "test finding",
                    "location": {"file": "src/foo.rs", "line": 1}
                })
            })
            .collect();
        serde_json::to_string(&serde_json::json!({"findings": findings})).unwrap()
    }

    //fusa:test REQ-LOC001
    #[test]
    fn run_no_args_returns_usage() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&[], &mut out, &mut err);
        assert_eq!(code, 2);
    }

    //fusa:test REQ-LOC001
    #[test]
    fn run_missing_file_returns_runtime() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &s(&["/nonexistent/a.json", "/nonexistent/b.json"]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 3);
    }

    //fusa:test REQ-LOC001
    #[test]
    fn run_no_new_findings_returns_ok() {
        let base = tempfile::NamedTempFile::new().unwrap();
        let curr = tempfile::NamedTempFile::new().unwrap();
        let report = make_report(&["fp1", "fp2"]);
        std::fs::write(base.path(), &report).unwrap();
        std::fs::write(curr.path(), &report).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &s(&[base.path().to_str().unwrap(), curr.path().to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("0 introduced"));
        assert!(text.contains("0 resolved"));
    }

    //fusa:test REQ-LOC001
    #[test]
    fn run_introduced_findings_returns_gate_fail() {
        let base = tempfile::NamedTempFile::new().unwrap();
        let curr = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(base.path(), make_report(&["fp1"])).unwrap();
        std::fs::write(curr.path(), make_report(&["fp1", "fp2"])).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &s(&[base.path().to_str().unwrap(), curr.path().to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("1 introduced"));
    }

    //fusa:test REQ-LOC001
    #[test]
    fn run_resolved_findings_text() {
        let base = tempfile::NamedTempFile::new().unwrap();
        let curr = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(base.path(), make_report(&["fp1", "fp2"])).unwrap();
        std::fs::write(curr.path(), make_report(&["fp1"])).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &s(&[base.path().to_str().unwrap(), curr.path().to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("1 resolved"));
    }

    //fusa:test REQ-LOC001
    #[test]
    fn run_json_format_output() {
        let base = tempfile::NamedTempFile::new().unwrap();
        let curr = tempfile::NamedTempFile::new().unwrap();
        let report = make_report(&["fp1"]);
        std::fs::write(base.path(), &report).unwrap();
        std::fs::write(curr.path(), &report).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &s(&[
                base.path().to_str().unwrap(),
                curr.path().to_str().unwrap(),
                "--format=json",
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["kind"], "diff-report");
        assert_eq!(v["summary"]["introduced"], 0);
    }

    //fusa:test REQ-LOC001
    #[test]
    fn run_introduced_shown_in_text() {
        let base = tempfile::NamedTempFile::new().unwrap();
        let curr = tempfile::NamedTempFile::new().unwrap();
        let finding = serde_json::json!({
            "fingerprint": "new_fp",
            "ruleId": "RULE001",
            "message": "some message",
            "location": {"file": "src/bar.rs", "line": 5}
        });
        std::fs::write(base.path(), r#"{"findings":[]}"#).unwrap();
        std::fs::write(
            curr.path(),
            serde_json::to_string(&serde_json::json!({"findings": [finding]})).unwrap(),
        )
        .unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let _code = run(
            &s(&[base.path().to_str().unwrap(), curr.path().to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Introduced"));
    }
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut positional = Vec::new();
    let mut format = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa diff: --format requires an argument").ok();
                    return None;
                }
                i += 1;
                format = Some(args[i].clone());
            }
            other => {
                if let Some(v) = other.strip_prefix("--format=") {
                    format = Some(v.to_string());
                } else if !other.starts_with("--") {
                    positional.push(other.to_string());
                } else {
                    writeln!(stderr, "rsfusa diff: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    if positional.len() < 2 {
        writeln!(
            stderr,
            "rsfusa diff: usage: rsfusa diff <baseline.json> <current.json>"
        )
        .ok();
        return None;
    }
    Some(Opts {
        baseline: positional[0].clone(),
        current: positional[1].clone(),
        format,
    })
}
