// `rsfusa hara [show|init|asil]` — Hazard Analysis and Risk Assessment management.
//fusa:req REQ-HARA001
//fusa:req REQ-HARA002
//fusa:req REQ-HARA003
//fusa:req REQ-HARA004
//fusa:req REQ-HARA005

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

pub const HARA_FILE: &str = ".fusa-hara.json";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Hazard {
    hazard_id: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    situation: Option<String>,
    severity: String,
    exposure: String,
    controllability: String,
    asil: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mitigation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HaraFile {
    schema_version: String,
    kind: String,
    tool: String,
    tool_version: String,
    language: String,
    generated_at: String,
    hazards: Vec<Hazard>,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("show");
    let rest = if args.is_empty() { &[] } else { &args[1..] };

    let dir = parse_dir(rest);
    let project_root =
        dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let hara_path = project_root.join(HARA_FILE);

    match subcmd {
        "init" => cmd_init(&hara_path, stdout, stderr),
        "show" => cmd_show(&hara_path, rest, stdout, stderr),
        "asil" => cmd_asil(rest, stdout, stderr),
        other => {
            writeln!(stderr, "rsfusa hara: unknown subcommand: {other}").ok();
            writeln!(stderr, "Usage: rsfusa hara [show|init|asil] [--dir <path>]").ok();
            EXIT_USAGE
        }
    }
}

fn cmd_init(path: &PathBuf, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if path.exists() {
        writeln!(stdout, "{} already exists", path.display()).ok();
        return EXIT_OK;
    }
    let hara = HaraFile {
        schema_version: SPEC_VERSION.to_string(),
        kind: "hara".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        hazards: vec![Hazard {
            hazard_id: "HAZ-001".to_string(),
            description: "Example: Software produces incorrect output under load".to_string(),
            situation: Some("High-rate input processing".to_string()),
            severity: "S2".to_string(),
            exposure: "E3".to_string(),
            controllability: "C2".to_string(),
            asil: "ASIL-B".to_string(),
            mitigation: Some("Input rate limiting and output validation".to_string()),
        }],
    };
    let json = serde_json::to_string_pretty(&hara).unwrap();
    match std::fs::write(path, json + "\n") {
        Ok(_) => {
            writeln!(stdout, "Created {}", path.display()).ok();
            EXIT_OK
        }
        Err(e) => {
            writeln!(stderr, "rsfusa hara init: {e}").ok();
            EXIT_RUNTIME
        }
    }
}

fn cmd_show(
    path: &PathBuf,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let format = parse_format(args);
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) => {
            writeln!(stderr, "rsfusa hara show: read {}: {e}", path.display()).ok();
            writeln!(stderr, "Run 'rsfusa hara init' to create a template.").ok();
            return EXIT_RUNTIME;
        }
    };
    let hara: HaraFile = match serde_json::from_str(&data) {
        Ok(h) => h,
        Err(e) => {
            writeln!(stderr, "rsfusa hara show: parse {}: {e}", path.display()).ok();
            return EXIT_RUNTIME;
        }
    };

    if format == "json" {
        writeln!(stdout, "{data}").ok();
        return EXIT_OK;
    }

    writeln!(stdout, "HARA ({} hazards)", hara.hazards.len()).ok();
    writeln!(
        stdout,
        "{:<10} {:<45} {:<3} {:<3} {:<3} {:<8}",
        "ID", "Description", "S", "E", "C", "ASIL"
    )
    .ok();
    writeln!(stdout, "{}", "-".repeat(80)).ok();
    for h in &hara.hazards {
        writeln!(
            stdout,
            "{:<10} {:<45} {:<3} {:<3} {:<3} {:<8}",
            h.hazard_id,
            truncate(&h.description, 44),
            h.severity,
            h.exposure,
            h.controllability,
            h.asil
        )
        .ok();
    }
    EXIT_OK
}

fn cmd_asil(args: &[String], stdout: &mut dyn Write, _stderr: &mut dyn Write) -> i32 {
    // Derive ASIL from S/E/C: rsfusa hara asil --severity S3 --exposure E4 --controllability C2
    let s = parse_flag(args, "--severity").unwrap_or_else(|| "S1".to_string());
    let e = parse_flag(args, "--exposure").unwrap_or_else(|| "E1".to_string());
    let c = parse_flag(args, "--controllability").unwrap_or_else(|| "C1".to_string());

    let s_num: u8 = s.trim_start_matches('S').parse().unwrap_or(1);
    let e_num: u8 = e.trim_start_matches('E').parse().unwrap_or(1);
    let c_num: u8 = c.trim_start_matches('C').parse().unwrap_or(1);

    // ISO 26262 ASIL lookup table
    let asil = iso26262_asil(s_num, e_num, c_num);

    if parse_format(args) == "json" {
        let out = serde_json::json!({
            "severity": s, "exposure": e, "controllability": c, "asil": asil
        });
        writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap()).ok();
    } else {
        writeln!(stdout, "S={s}  E={e}  C={c}  →  ASIL = {asil}").ok();
    }
    EXIT_OK
}

fn iso26262_asil(s: u8, e: u8, c: u8) -> &'static str {
    // ISO 26262 Part 3 Table 4
    let score = s as u16 * e as u16 * c as u16;
    match (s, score) {
        (1, _) => "QM",
        (2, 0..=2) => "QM",
        (2, 3..=4) => "ASIL-A",
        (2, 5..=8) => "ASIL-B",
        (2, _) => "ASIL-B",
        (3, 0..=2) => "QM",
        (3, 3..=4) => "ASIL-A",
        (3, 5..=6) => "ASIL-B",
        (3, 7..=8) => "ASIL-C",
        (3, _) => "ASIL-D",
        (4, 0..=2) => "ASIL-A",
        (4, 3..=4) => "ASIL-B",
        (4, 5..=6) => "ASIL-C",
        (4, _) => "ASIL-D",
        _ => "ASIL-D",
    }
}

fn parse_dir(args: &[String]) -> Option<PathBuf> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--dir" && i + 1 < args.len() {
            return Some(PathBuf::from(&args[i + 1]));
        }
        if let Some(v) = args[i].strip_prefix("--dir=") {
            return Some(PathBuf::from(v));
        }
        i += 1;
    }
    None
}

fn parse_format(args: &[String]) -> String {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--format" && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        if let Some(v) = args[i].strip_prefix("--format=") {
            return v.to_string();
        }
        i += 1;
    }
    "text".to_string()
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    let prefix = format!("{flag}=");
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(v) = args[i].strip_prefix(&prefix) {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
