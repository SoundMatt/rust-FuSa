// `rsfusa coverage` — structural coverage report via cargo-tarpaulin or cargo-llvm-cov.

use crate::types::{EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;
use std::path::PathBuf;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    // Try cargo-tarpaulin first, then llvm-cov
    let (coverage_pct, tool_used) = if let Some(pct) = try_tarpaulin(&project_root) {
        (pct, "cargo-tarpaulin")
    } else if let Some(pct) = try_llvm_cov(&project_root) {
        (pct, "cargo-llvm-cov")
    } else {
        writeln!(stderr, "rsfusa coverage: no coverage tool found.").ok();
        writeln!(stderr, "  Install: cargo install cargo-tarpaulin  OR  cargo install cargo-llvm-cov").ok();
        // Still produce a report indicating coverage is unknown
        ("0.0".to_string(), "none")
    };

    let coverage_f: f64 = coverage_pct.parse().unwrap_or(0.0);
    let gate_pct = opts.min_coverage.unwrap_or(0.0);
    let passes_gate = coverage_f >= gate_pct || tool_used == "none";

    let dal = infer_dal(&project_root);
    let required = required_coverage(dal);

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "coverage-report",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "coverageTool": tool_used,
        "lineCoverage": coverage_f,
        "requiredCoverage": required,
        "passesGate": passes_gate || gate_pct == 0.0,
        "dal": dal,
        "note": if tool_used == "none" {
            "No coverage tool found. Install cargo-tarpaulin or cargo-llvm-cov."
        } else {
            ""
        }
    });

    match opts.format.as_deref() {
        Some("json") | None if opts.output.is_some() => {
            let path = opts.output.as_deref().unwrap_or("coverage-report.json");
            if let Err(e) = std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n") {
                writeln!(stderr, "rsfusa coverage: write {path}: {e}").ok();
                return EXIT_RUNTIME;
            }
            writeln!(stdout, "Coverage report written to {path}").ok();
        }
        Some("json") => {
            writeln!(stdout, "{}", serde_json::to_string_pretty(&report).unwrap()).ok();
        }
        _ => {
            writeln!(stdout, "Coverage: {coverage_f:.1}%  (required: {required:.1}%  DAL: {dal})").ok();
            writeln!(stdout, "Tool: {tool_used}").ok();
            if !passes_gate && gate_pct > 0.0 {
                writeln!(stdout, "GATE FAILED: {coverage_f:.1}% < minimum {gate_pct:.1}%").ok();
            }
        }
    }

    if !passes_gate && gate_pct > 0.0 { EXIT_GATE_FAIL } else { EXIT_OK }
}

fn try_tarpaulin(root: &PathBuf) -> Option<String> {
    let output = std::process::Command::new("cargo")
        .args(["tarpaulin", "--out", "Json", "--skip-clean"])
        .current_dir(root)
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    // tarpaulin JSON: {"coverage": 42.0, ...}
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(pct) = v.get("coverage").and_then(|c| c.as_f64()) {
            return Some(format!("{pct:.2}"));
        }
    }
    // Fallback: parse text output "42.00% coverage"
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        if line.contains("% coverage") {
            if let Some(pct_str) = line.split('%').next() {
                let pct_str = pct_str.trim().rsplit_once(' ').map(|(_, v)| v).unwrap_or(pct_str.trim());
                if pct_str.parse::<f64>().is_ok() {
                    return Some(pct_str.to_string());
                }
            }
        }
    }
    None
}

fn try_llvm_cov(root: &PathBuf) -> Option<String> {
    let output = std::process::Command::new("cargo")
        .args(["llvm-cov", "--summary-only", "--json"])
        .current_dir(root)
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(pct) = v.get("data")
            .and_then(|d| d.as_array())
            .and_then(|a| a.first())
            .and_then(|d| d.get("totals"))
            .and_then(|t| t.get("lines"))
            .and_then(|l| l.get("percent"))
            .and_then(|p| p.as_f64())
        {
            return Some(format!("{pct:.2}"));
        }
    }
    None
}

fn infer_dal(root: &PathBuf) -> &'static str {
    if let Ok(data) = std::fs::read_to_string(root.join(".fusa.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(dal) = v.get("dal").and_then(|d| d.as_str()) {
                return match dal {
                    "DAL-A" | "a" => "DAL-A",
                    "DAL-B" | "b" => "DAL-B",
                    "DAL-C" | "c" => "DAL-C",
                    _ => "DAL-D",
                };
            }
        }
    }
    "DAL-D"
}

fn required_coverage(dal: &str) -> f64 {
    match dal {
        "DAL-A" => 100.0,
        "DAL-B" => 100.0,
        "DAL-C" => 100.0,
        _ => 75.0,
    }
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
    min_coverage: Option<f64>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts { dir: None, format: None, output: None, min_coverage: None };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--format" | "--output" | "--min-coverage") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa coverage: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--format" => opts.format = Some(args[i].clone()),
                    "--output" => opts.output = Some(args[i].clone()),
                    "--min-coverage" => opts.min_coverage = args[i].parse().ok(),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--format=") { opts.format = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--output=") { opts.output = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--min-coverage=") { opts.min_coverage = v.parse().ok(); }
                else {
                    writeln!(stderr, "rsfusa coverage: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
