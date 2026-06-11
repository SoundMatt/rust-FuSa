// `rsfusa metrics [record|show]` — safety metrics time series.

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

pub const METRICS_FILE: &str = ".fusa-metrics.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetricSnapshot {
    timestamp: String,
    error_count: u64,
    warning_count: u64,
    coverage_pct: f64,
    traced_requirements: u64,
    total_requirements: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetricsFile {
    schema_version: String,
    kind: String,
    tool: String,
    tool_version: String,
    language: String,
    snapshots: Vec<MetricSnapshot>,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("show");
    let rest = if args.is_empty() { &[] } else { &args[1..] };

    let dir = parse_dir(rest);
    let project_root = dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    let metrics_path = project_root.join(METRICS_FILE);

    match subcmd {
        "record" => cmd_record(&metrics_path, rest, &project_root, stdout, stderr),
        "show" => cmd_show(&metrics_path, rest, stdout, stderr),
        other => {
            writeln!(stderr, "rsfusa metrics: unknown subcommand: {other}").ok();
            writeln!(stderr, "Usage: rsfusa metrics [record|show] [--dir <path>]").ok();
            EXIT_USAGE
        }
    }
}

fn cmd_record(path: &PathBuf, args: &[String], root: &PathBuf, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let label = parse_flag(args, "--label");

    // Collect current metrics from available report files
    let (errors, warnings) = read_check_report(root);
    let coverage = read_coverage(root);
    let (traced, total) = read_trace(root);

    let mut file_data = load_or_empty(path);
    file_data.snapshots.push(MetricSnapshot {
        timestamp: chrono::Utc::now().to_rfc3339(),
        error_count: errors,
        warning_count: warnings,
        coverage_pct: coverage,
        traced_requirements: traced,
        total_requirements: total,
        label,
    });

    let json = serde_json::to_string_pretty(&file_data).expect("serialize metrics");
    match std::fs::write(path, json + "\n") {
        Ok(_) => {
            writeln!(stdout, "Metrics recorded: {} errors, {} warnings, {:.1}% coverage",
                errors, warnings, coverage).ok();
            EXIT_OK
        }
        Err(e) => {
            writeln!(stderr, "rsfusa metrics record: {e}").ok();
            EXIT_RUNTIME
        }
    }
}

fn cmd_show(path: &PathBuf, args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let format = parse_flag(args, "--format").unwrap_or_else(|| "text".to_string());

    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => {
            writeln!(stdout, "No metrics file. Run 'rsfusa metrics record' first.").ok();
            return EXIT_OK;
        }
    };

    if format == "json" {
        writeln!(stdout, "{data}").ok();
        return EXIT_OK;
    }

    let file_data: MetricsFile = match serde_json::from_str(&data) {
        Ok(f) => f,
        Err(e) => {
            writeln!(stderr, "rsfusa metrics show: parse: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    writeln!(stdout, "{} snapshots", file_data.snapshots.len()).ok();
    writeln!(stdout, "{:<26} {:>6} {:>8} {:>8} {:>8} {}",
        "Timestamp", "Errors", "Warnings", "Coverage", "Traced", "Label").ok();
    writeln!(stdout, "{}", "-".repeat(80)).ok();
    for s in &file_data.snapshots {
        writeln!(stdout, "{:<26} {:>6} {:>8} {:>7.1}% {:>8} {}",
            &s.timestamp[..19],
            s.error_count,
            s.warning_count,
            s.coverage_pct,
            format!("{}/{}", s.traced_requirements, s.total_requirements),
            s.label.as_deref().unwrap_or(""),
        ).ok();
    }
    EXIT_OK
}

fn read_check_report(root: &PathBuf) -> (u64, u64) {
    if let Ok(data) = std::fs::read_to_string(root.join("check-report.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            let errors = v["summary"]["errors"].as_u64().unwrap_or(0);
            let warnings = v["summary"]["warnings"].as_u64().unwrap_or(0);
            return (errors, warnings);
        }
    }
    (0, 0)
}

fn read_coverage(root: &PathBuf) -> f64 {
    if let Ok(data) = std::fs::read_to_string(root.join("coverage-report.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            return v["lineCoverage"].as_f64().unwrap_or(0.0);
        }
    }
    0.0
}

fn read_trace(root: &PathBuf) -> (u64, u64) {
    if let Ok(data) = std::fs::read_to_string(root.join("trace.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            let traced = v["coverage"]["tracedRequirements"].as_u64().unwrap_or(0);
            let total = v["coverage"]["totalRequirements"].as_u64().unwrap_or(0);
            return (traced, total);
        }
    }
    (0, 0)
}

fn load_or_empty(path: &PathBuf) -> MetricsFile {
    if let Ok(data) = std::fs::read_to_string(path) {
        if let Ok(f) = serde_json::from_str::<MetricsFile>(&data) {
            return f;
        }
    }
    MetricsFile {
        schema_version: SPEC_VERSION.to_string(),
        kind: "metrics".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        snapshots: vec![],
    }
}

fn parse_dir(args: &[String]) -> Option<PathBuf> {
    parse_flag(args, "--dir").map(PathBuf::from)
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    let prefix = format!("{flag}=");
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() { return Some(args[i + 1].clone()); }
        if let Some(v) = args[i].strip_prefix(&prefix) { return Some(v.to_string()); }
        i += 1;
    }
    None
}
