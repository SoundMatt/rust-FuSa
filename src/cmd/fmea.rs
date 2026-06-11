// `rsfusa fmea` — Design Failure Mode and Effects Analysis from pub fn declarations.
// Writes fmea.json and fmea.csv.
//fusa:req REQ-FMEA001
//fusa:req REQ-FMEA002
//fusa:req REQ-FMEA003
//fusa:req REQ-FMEA004
//fusa:req REQ-FMEA005
//fusa:req REQ-FMEA006

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use walkdir::WalkDir;

pub const FMEA_JSON: &str = "fmea.json";
pub const FMEA_CSV: &str = "fmea.csv";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FmeaEntry {
    function: String,
    module: String,
    failure_mode: String,
    effect: String,
    severity: String,
    detection_method: String,
    risk: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    requirements: Vec<String>,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let asil_level = read_asil(&project_root);
    let mut entries: Vec<FmeaEntry> = Vec::new();

    let src_dir = project_root.join("src");
    let scan_root = if src_dir.exists() {
        src_dir
    } else {
        project_root.clone()
    };

    for entry in WalkDir::new(&scan_root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(&project_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !is_pub_fn(trimmed) {
                continue;
            }

            let fn_name = extract_fn_name(trimmed).unwrap_or_else(|| "unknown".to_string());
            if fn_name == "main" || fn_name.starts_with("test_") || fn_name.starts_with("bench_") {
                continue;
            }

            // Collect //fusa:req annotations from preceding lines
            let mut requirements = Vec::new();
            let mut j = i.saturating_sub(5);
            while j < i {
                let prev = lines[j].trim();
                if prev.contains("//fusa:req") {
                    for req in extract_req_ids(prev) {
                        requirements.push(req);
                    }
                }
                j += 1;
            }

            let return_type = extract_return_type(trimmed);
            let (failure_mode, effect) = failure_mode_from_signature(trimmed, &return_type);
            let severity = asil_to_severity(&asil_level);
            let detection_method = if !requirements.is_empty() {
                "Requirement-traced unit test"
            } else {
                "Unit test"
            };
            let risk = compute_risk(&severity, detection_method);

            entries.push(FmeaEntry {
                function: fn_name,
                module: rel.clone(),
                failure_mode,
                effect,
                severity,
                detection_method: detection_method.to_string(),
                risk,
                requirements,
            });
        }
    }

    if entries.is_empty() {
        writeln!(stdout, "No public functions found for FMEA analysis.").ok();
        writeln!(
            stdout,
            "Annotate public functions with //fusa:req <ID> for traceability."
        )
        .ok();
    }

    let json_path = opts
        .json_output
        .unwrap_or_else(|| project_root.join(FMEA_JSON).to_string_lossy().into_owned());
    let csv_path = opts
        .csv_output
        .unwrap_or_else(|| project_root.join(FMEA_CSV).to_string_lossy().into_owned());

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "fmea",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "asilLevel": asil_level,
        "entries": entries,
        "summary": { "functions": entries.len() }
    });

    match std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&report).unwrap() + "\n",
    ) {
        Ok(_) => writeln!(stdout, "FMEA written to {json_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa fmea: write {json_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    // Write CSV
    let mut csv = String::from(
        "Function,Module,FailureMode,Effect,Severity,DetectionMethod,Risk,Requirements\n",
    );
    if let Some(arr) = report["entries"].as_array() {
        for e in arr {
            let reqs = e["requirements"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join("|")
                })
                .unwrap_or_default();
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                csv_escape(e["function"].as_str().unwrap_or("")),
                csv_escape(e["module"].as_str().unwrap_or("")),
                csv_escape(e["failureMode"].as_str().unwrap_or("")),
                csv_escape(e["effect"].as_str().unwrap_or("")),
                e["severity"].as_str().unwrap_or(""),
                csv_escape(e["detectionMethod"].as_str().unwrap_or("")),
                e["risk"].as_str().unwrap_or(""),
                csv_escape(&reqs),
            ));
        }
    }

    match std::fs::write(&csv_path, csv) {
        Ok(_) => writeln!(stdout, "FMEA CSV written to {csv_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa fmea: write {csv_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    EXIT_OK
}

fn is_pub_fn(line: &str) -> bool {
    line.starts_with("pub fn ")
        || line.starts_with("pub async fn ")
        || line.starts_with("pub unsafe fn ")
        || line.starts_with("pub extern ")
}

fn extract_fn_name(line: &str) -> Option<String> {
    let after = line.find("fn ")?;
    let rest = &line[after + 3..];
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn extract_return_type(line: &str) -> String {
    if line.contains("-> Result<") {
        return "Result".to_string();
    }
    if line.contains("-> Option<") {
        return "Option".to_string();
    }
    if line.contains("-> bool") {
        return "bool".to_string();
    }
    if line.contains("-> i32") || line.contains("-> i64") || line.contains("-> usize") {
        return "integer".to_string();
    }
    if line.contains("-> String") || line.contains("-> &str") {
        return "string".to_string();
    }
    "void".to_string()
}

fn failure_mode_from_signature(line: &str, ret: &str) -> (String, String) {
    match ret {
        "Result" => (
            "Returns Err when Ok expected".to_string(),
            "Caller receives unexpected error; may abort operation".to_string(),
        ),
        "Option" => (
            "Returns None when Some expected".to_string(),
            "Caller may unwrap None and panic".to_string(),
        ),
        "bool" => (
            "Returns incorrect boolean value".to_string(),
            "Incorrect conditional branch taken".to_string(),
        ),
        "integer" => (
            "Returns incorrect integer value (overflow or truncation)".to_string(),
            "Downstream computation produces incorrect result".to_string(),
        ),
        _ => {
            if line.contains("unsafe") {
                (
                    "Memory safety violation".to_string(),
                    "Undefined behaviour; potential system crash or security breach".to_string(),
                )
            } else {
                (
                    "Function does not perform intended action".to_string(),
                    "Incorrect system state".to_string(),
                )
            }
        }
    }
}

fn asil_to_severity(asil: &str) -> String {
    match asil {
        "D" | "ASIL-D" => "S4".to_string(),
        "C" | "ASIL-C" => "S3".to_string(),
        "B" | "ASIL-B" => "S2".to_string(),
        "A" | "ASIL-A" | "SIL-4" | "SIL-3" => "S2".to_string(),
        _ => "S1".to_string(),
    }
}

fn compute_risk(severity: &str, detection: &str) -> String {
    let d_score = if detection.contains("Requirement") {
        1
    } else {
        2
    };
    let s_score = match severity {
        "S4" => 4,
        "S3" => 3,
        "S2" => 2,
        _ => 1,
    };
    match s_score * d_score {
        v if v >= 6 => "HIGH".to_string(),
        v if v >= 3 => "MEDIUM".to_string(),
        _ => "LOW".to_string(),
    }
}

fn extract_req_ids(line: &str) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(pos) = line.find("//fusa:req") {
        let rest = &line[pos + 10..].trim_start_matches(|c| c == ':' || c == ' ');
        for id in rest.split_whitespace() {
            ids.push(id.to_string());
        }
    }
    ids
}

fn read_asil(root: &PathBuf) -> String {
    if let Ok(data) = std::fs::read_to_string(root.join(".fusa.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(a) = v.get("asil").and_then(|v| v.as_str()) {
                return a.to_uppercase();
            }
        }
    }
    "UNCLASSIFIED".to_string()
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

struct Opts {
    dir: Option<PathBuf>,
    json_output: Option<String>,
    csv_output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        json_output: None,
        csv_output: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--output" | "--csv") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa fmea: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--output" => opts.json_output = Some(args[i].clone()),
                    "--csv" => opts.csv_output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.json_output = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--csv=") {
                    opts.csv_output = Some(v.to_string());
                } else {
                    writeln!(stderr, "rsfusa fmea: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
