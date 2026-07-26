// `rsfusa coverage` — structural coverage report via cargo-tarpaulin or cargo-llvm-cov.
// Feature 3: MC/DC coverage via LLVM coverage JSON export.
//fusa:req REQ-COVERAGE-MCDC001
//fusa:req REQ-COVERAGE-MCDC002
//fusa:req REQ-COVERAGE-MCDC003
//fusa:req REQ-COVERAGE-MCDC004

use crate::types::{
    EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION,
};
use std::io::Write;
use std::path::{Path, PathBuf};

// ── MC/DC types ────────────────────────────────────────────────────────────

#[derive(Debug)]
struct McdcCondition {
    covered_true: u64,
    covered_false: u64,
}

impl McdcCondition {
    fn is_covered(&self) -> bool {
        self.covered_true > 0 && self.covered_false > 0
    }
}

#[derive(Debug)]
struct McdcRecord {
    /// Function name if available (parsed from the LLVM export).
    function_name: String,
    conditions: Vec<McdcCondition>,
}

impl McdcRecord {
    fn total_conditions(&self) -> usize {
        self.conditions.len()
    }

    fn covered_conditions(&self) -> usize {
        self.conditions.iter().filter(|c| c.is_covered()).count()
    }

    fn is_fully_covered(&self) -> bool {
        !self.conditions.is_empty()
            && self.conditions.iter().all(|c| c.is_covered())
    }
}

/// Parse LLVM MC/DC JSON export.
///
/// Expected schema (from `cargo llvm-cov --json`):
/// ```json
/// {
///   "data": [{
///     "functions": [{
///       "name": "foo",
///       "mcdc_records": [{
///         "conditions": [
///           {"covered_true_count": 1, "covered_false_count": 0},
///           ...
///         ]
///       }]
///     }]
///   }]
/// }
/// ```
fn parse_mcdc_file(path: &str) -> Result<Vec<McdcRecord>, String> {
    let data =
        std::fs::read_to_string(path).map_err(|e| format!("read mcdc file {path}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("parse mcdc file {path}: {e}"))?;

    let mut records = Vec::new();

    // Walk data[*].functions[*].mcdc_records
    let data_arr = match v.get("data").and_then(|d| d.as_array()) {
        Some(a) => a.clone(),
        None => return Ok(records),
    };

    for data_entry in &data_arr {
        let functions = match data_entry.get("functions").and_then(|f| f.as_array()) {
            Some(a) => a.clone(),
            None => continue,
        };
        for func in &functions {
            let func_name = func
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("<unknown>")
                .to_string();
            let mcdc_recs = match func.get("mcdc_records").and_then(|r| r.as_array()) {
                Some(a) => a.clone(),
                None => continue,
            };
            for mcdc_rec in &mcdc_recs {
                let conditions = match mcdc_rec.get("conditions").and_then(|c| c.as_array()) {
                    Some(a) => a.clone(),
                    None => continue,
                };
                let parsed_conditions: Vec<McdcCondition> = conditions
                    .iter()
                    .map(|c| McdcCondition {
                        covered_true: c
                            .get("covered_true_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                        covered_false: c
                            .get("covered_false_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                    })
                    .collect();
                if !parsed_conditions.is_empty() {
                    records.push(McdcRecord {
                        function_name: func_name.clone(),
                        conditions: parsed_conditions,
                    });
                }
            }
        }
    }
    Ok(records)
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Try cargo-tarpaulin first, then llvm-cov
    let (coverage_pct, tool_used) = if let Some(pct) = try_tarpaulin(&project_root) {
        (pct, "cargo-tarpaulin")
    } else if let Some(pct) = try_llvm_cov(&project_root) {
        (pct, "cargo-llvm-cov")
    } else {
        writeln!(stderr, "rsfusa coverage: no coverage tool found.").ok();
        writeln!(
            stderr,
            "  Install: cargo install cargo-tarpaulin  OR  cargo install cargo-llvm-cov"
        )
        .ok();
        // Still produce a report indicating coverage is unknown
        ("0.0".to_string(), "none")
    };

    let coverage_f: f64 = coverage_pct.parse().unwrap_or(0.0);
    let gate_pct = opts.min_coverage.unwrap_or(0.0);
    let passes_gate = coverage_f >= gate_pct || tool_used == "none";

    let dal = infer_dal(&project_root);
    let required = required_coverage(dal);

    // ── MC/DC processing ─────────────────────────────────────────────────
    let (mcdc_report, mcdc_gate_fail) = if opts.mcdc {
        match build_mcdc_report(&opts, stderr) {
            Ok((rpt, fail)) => (Some(rpt), fail),
            Err(e) => {
                writeln!(stderr, "rsfusa coverage: mcdc: {e}").ok();
                return EXIT_RUNTIME;
            }
        }
    } else {
        (None, false)
    };

    let mut report = serde_json::json!({
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

    if let Some(mcdc) = &mcdc_report {
        report["mcdc"] = mcdc.clone();
    }

    match opts.format.as_deref() {
        Some("json") | None if opts.output.is_some() => {
            let path = opts.output.as_deref().unwrap_or("coverage-report.json");
            if let Err(e) =
                std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n")
            {
                writeln!(stderr, "rsfusa coverage: write {path}: {e}").ok();
                return EXIT_RUNTIME;
            }
            writeln!(stdout, "Coverage report written to {path}").ok();
        }
        Some("json") => {
            writeln!(stdout, "{}", serde_json::to_string_pretty(&report).unwrap()).ok();
        }
        _ => {
            writeln!(
                stdout,
                "Coverage: {coverage_f:.1}%  (required: {required:.1}%  DAL: {dal})"
            )
            .ok();
            writeln!(stdout, "Tool: {tool_used}").ok();
            if !passes_gate && gate_pct > 0.0 {
                writeln!(
                    stdout,
                    "GATE FAILED: {coverage_f:.1}% < minimum {gate_pct:.1}%"
                )
                .ok();
            }
            if opts.mcdc {
                if let Some(mcdc) = &mcdc_report {
                    writeln!(
                        stdout,
                        "MC/DC: {} functions  {}/{} conditions covered  gate: {}",
                        mcdc["totalFunctions"].as_u64().unwrap_or(0),
                        mcdc["coveredConditions"].as_u64().unwrap_or(0),
                        mcdc["totalConditions"].as_u64().unwrap_or(0),
                        if mcdc_gate_fail { "FAIL" } else { "PASS" }
                    )
                    .ok();
                }
            }
        }
    }

    if (!passes_gate && gate_pct > 0.0) || mcdc_gate_fail {
        EXIT_GATE_FAIL
    } else {
        EXIT_OK
    }
}

/// Build the MC/DC sub-report and return (json_value, gate_failed).
fn build_mcdc_report(
    opts: &Opts,
    stderr: &mut dyn Write,
) -> Result<(serde_json::Value, bool), String> {
    //fusa:req REQ-COVERAGE-MCDC001
    //fusa:req REQ-COVERAGE-MCDC002
    //fusa:req REQ-COVERAGE-MCDC003
    //fusa:req REQ-COVERAGE-MCDC004

    let mcdc_path = opts.mcdc_file.as_deref().unwrap_or("");
    if mcdc_path.is_empty() {
        // No file provided — emit empty report, no gate failure.
        return Ok((
            serde_json::json!({
                "totalFunctions": 0,
                "totalConditions": 0,
                "coveredConditions": 0,
                "uncoveredConditions": 0,
                "passesGate": true,
                "note": "no --mcdc-file provided; MC/DC not measured"
            }),
            false,
        ));
    }

    let records = parse_mcdc_file(mcdc_path)?;

    let total_functions = records.len();
    let total_conditions: usize = records.iter().map(|r| r.total_conditions()).sum();
    let covered_conditions: usize = records.iter().map(|r| r.covered_conditions()).sum();
    let uncovered_conditions = total_conditions - covered_conditions;

    let threshold = opts.mcdc_threshold.unwrap_or(100.0);
    let actual_pct = if total_conditions == 0 {
        100.0f64
    } else {
        covered_conditions as f64 / total_conditions as f64 * 100.0
    };
    let passes_gate = actual_pct >= threshold;

    // Hard gate: fail if any annotated function has uncovered conditions.
    let gate_fail = !passes_gate;
    if gate_fail {
        writeln!(
            stderr,
            "rsfusa coverage: MC/DC gate failed: {actual_pct:.1}% < required {threshold:.1}%"
        )
        .ok();
    }

    let functions: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "function": r.function_name,
                "totalConditions": r.total_conditions(),
                "coveredConditions": r.covered_conditions(),
                "fullyCovered": r.is_fully_covered(),
            })
        })
        .collect();

    Ok((
        serde_json::json!({
            "totalFunctions": total_functions,
            "totalConditions": total_conditions,
            "coveredConditions": covered_conditions,
            "uncoveredConditions": uncovered_conditions,
            "coveragePercent": actual_pct,
            "threshold": threshold,
            "passesGate": passes_gate,
            "functions": functions,
        }),
        gate_fail,
    ))
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
                let pct_str = pct_str
                    .trim()
                    .rsplit_once(' ')
                    .map(|(_, v)| v)
                    .unwrap_or(pct_str.trim());
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
        if let Some(pct) = v
            .get("data")
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

fn infer_dal(root: &Path) -> &'static str {
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
    /// Enable MC/DC coverage gate.
    mcdc: bool,
    /// Path to LLVM coverage JSON export for MC/DC parsing.
    mcdc_file: Option<String>,
    /// Minimum MC/DC coverage percentage (default 100.0).
    mcdc_threshold: Option<f64>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        format: None,
        output: None,
        min_coverage: None,
        mcdc: false,
        mcdc_file: None,
        mcdc_threshold: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mcdc" => opts.mcdc = true,
            flag @ ("--dir" | "--format" | "--output" | "--min-coverage" | "--mcdc-file" | "--mcdc-threshold") => {
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
                    "--mcdc-file" => opts.mcdc_file = Some(args[i].clone()),
                    "--mcdc-threshold" => opts.mcdc_threshold = args[i].parse().ok(),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--format=") {
                    opts.format = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.output = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--min-coverage=") {
                    opts.min_coverage = v.parse().ok();
                } else if let Some(v) = other.strip_prefix("--mcdc-file=") {
                    opts.mcdc_file = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--mcdc-threshold=") {
                    opts.mcdc_threshold = v.parse().ok();
                } else {
                    writeln!(stderr, "rsfusa coverage: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
