// `rsfusa diff <baseline.json> <current.json>` — compare two check reports.
// Exits 1 if new findings are introduced (§4.2 fingerprint-based).

use crate::types::{EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
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

    let baseline_fps: HashSet<String> = baseline.iter()
        .filter_map(|f| f.get("fingerprint").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();
    let current_fps: HashSet<String> = current.iter()
        .filter_map(|f| f.get("fingerprint").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();

    let current_map: HashMap<String, &serde_json::Value> = current.iter()
        .filter_map(|f| {
            f.get("fingerprint").and_then(|v| v.as_str())
                .map(|fp| (fp.to_string(), f))
        })
        .collect();
    let baseline_map: HashMap<String, &serde_json::Value> = baseline.iter()
        .filter_map(|f| {
            f.get("fingerprint").and_then(|v| v.as_str())
                .map(|fp| (fp.to_string(), f))
        })
        .collect();

    let introduced: Vec<_> = current_fps.difference(&baseline_fps)
        .filter_map(|fp| current_map.get(fp))
        .collect();
    let resolved: Vec<_> = baseline_fps.difference(&current_fps)
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
        writeln!(stdout, "Diff: {} introduced  {} resolved  {} unchanged",
            introduced.len(), resolved.len(), unchanged).ok();
        if !introduced.is_empty() {
            writeln!(stdout, "\nIntroduced:").ok();
            for f in &introduced {
                let rule = f.get("ruleId").and_then(|v| v.as_str()).unwrap_or("?");
                let file = f.get("location").and_then(|v| v.get("file")).and_then(|v| v.as_str()).unwrap_or("?");
                let line = f.get("location").and_then(|v| v.get("line")).and_then(|v| v.as_u64()).unwrap_or(0);
                let msg = f.get("message").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(stdout, "  + [{rule}] {file}:{line}: {msg}").ok();
            }
        }
        if !resolved.is_empty() {
            writeln!(stdout, "\nResolved:").ok();
            for f in &resolved {
                let rule = f.get("ruleId").and_then(|v| v.as_str()).unwrap_or("?");
                let file = f.get("location").and_then(|v| v.get("file")).and_then(|v| v.as_str()).unwrap_or("?");
                let line = f.get("location").and_then(|v| v.get("line")).and_then(|v| v.as_u64()).unwrap_or(0);
                let msg = f.get("message").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(stdout, "  - [{rule}] {file}:{line}: {msg}").ok();
            }
        }
    }

    if !introduced.is_empty() { EXIT_GATE_FAIL } else { EXIT_OK }
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
    let findings = v.get("findings")
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
        writeln!(stderr, "rsfusa diff: usage: rsfusa diff <baseline.json> <current.json>").ok();
        return None;
    }
    Some(Opts { baseline: positional[0].clone(), current: positional[1].clone(), format })
}
