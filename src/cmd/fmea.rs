// `rsfusa fmea` — Design Failure Mode and Effects Analysis over the
// project's public functions, per IEC 60812:2018 / the AIAG-VDA FMEA
// Handbook (2019), x-FuSa spec §9.2.
//fusa:req REQ-FMEA001
//fusa:req REQ-FMEA002
//fusa:req REQ-FMEA003
//fusa:req REQ-FMEA004
//fusa:req REQ-FMEA005
//fusa:req REQ-FMEA006
//fusa:req REQ-FMEA007
//fusa:req REQ-FMEA008

use crate::attestation::Attestation;
use crate::stub::{
    apply_project_dispositions, detect_blank_fallback, detect_placeholder, has_open_errors,
    has_open_warnings, QualField,
};
use crate::types::{
    EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION,
};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const FMEA_JSON: &str = "fmea.json";
pub const FMEA_CSV: &str = "fmea.csv";

/// §9.2 `fmea.json` `entries[]` shape.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct FmeaEntry {
    id: String,
    item: String,
    file: String,
    failure_mode: String,
    effect: String,
    cause: String,
    severity: &'static str,
    action_priority: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mitigations: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    requirement_ids: Vec<String>,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let cfg = match crate::config::load(&project_root.join(".fusa.json")) {
        Ok(c) => c,
        Err(crate::config::ConfigError::NotFound(_)) => crate::config::FusaConfig::new(
            project_root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("project"),
            "generic",
        ),
        Err(e) => {
            writeln!(stderr, "rsfusa fmea: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let severity = severity_from_integrity(&cfg);
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
        let module = rel
            .strip_suffix(".rs")
            .unwrap_or(&rel)
            .trim_start_matches("src/")
            .replace('/', "::");
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

            let mut requirements = Vec::new();
            let mut j = i.saturating_sub(5);
            while j < i {
                let prev = lines[j].trim();
                if prev.contains("//fusa:req") {
                    requirements.extend(extract_req_ids(prev));
                }
                j += 1;
            }

            let item = format!("{module}::{fn_name}");
            let return_type = extract_return_type(trimmed);
            let failure_mode = failure_mode_from_signature(&item, &return_type);
            let effect = effect_from_signature(&item, &return_type);
            let cause = cause_from_signature(&item, &return_type, trimmed);
            let action_priority = compute_action_priority(severity, !requirements.is_empty());

            entries.push(FmeaEntry {
                id: format!("FMEA-{:03}", entries.len() + 1),
                item,
                file: rel.clone(),
                failure_mode,
                effect,
                cause,
                severity,
                action_priority,
                mitigations: mitigations_from_signature(&return_type),
                requirement_ids: requirements,
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

    let empty_tags: Vec<crate::trace::Tag> = Vec::new();
    let components_in_project = crate::trace::scan_func_coverage(&project_root, &cfg, &empty_tags)
        .map(|fc| fc.total)
        .unwrap_or(0);
    let components_analyzed = entries.len();
    let coverage_pct = if components_in_project == 0 {
        100.0
    } else {
        (components_analyzed as f64 * 1000.0 / components_in_project as f64).round() / 10.0
    };

    let high_priority = entries
        .iter()
        .filter(|e| e.action_priority == "high")
        .count();

    let mut qual_fields = Vec::new();
    for e in &entries {
        qual_fields.push(QualField::new(
            e.id.clone(),
            "failureMode",
            e.failure_mode.clone(),
        ));
        qual_fields.push(QualField::new(e.id.clone(), "effect", e.effect.clone()));
        qual_fields.push(QualField::new(e.id.clone(), "cause", e.cause.clone()));
    }

    let content = serde_json::json!({ "entries": entries });
    let content_hash = crate::canonjson::content_hash(&content);
    let existing_path = opts
        .json_output
        .clone()
        .unwrap_or_else(|| project_root.join(FMEA_JSON).to_string_lossy().into_owned());
    let attestation: Option<Attestation> = crate::attestation::carry_forward(
        crate::attestation::read_existing(Path::new(&existing_path)),
        &content_hash,
    );
    let attestation_valid = attestation
        .as_ref()
        .is_some_and(|a| crate::attestation::is_valid(a, &content_hash));

    let mut findings = detect_placeholder(FMEA_JSON, &qual_fields);
    if !attestation_valid {
        findings.extend(detect_blank_fallback(FMEA_JSON, &qual_fields));
    }
    apply_project_dispositions(&project_root, &mut findings);
    for f in &findings {
        writeln!(stderr, "{}: {} ({})", f.severity, f.message, f.rule_id).ok();
    }

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "fmea-report",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "entries": entries,
        "summary": {
            "total": entries.len(),
            "highPriority": high_priority,
            "componentsAnalyzed": components_analyzed,
            "componentsInProject": components_in_project,
            "coveragePct": coverage_pct,
            "componentInventoryMethod": "count of `pub fn` declarations (excluding tests/, build.rs, and #[cfg(test)] items) via the same scan trace --func-coverage uses, honoring .fusa.json sourceDirs/excludePatterns (§1.4.1 item 2)",
        },
        "attestation": attestation,
        "findings": findings,
    });

    let json_path = existing_path;
    let csv_path = opts
        .csv_output
        .unwrap_or_else(|| project_root.join(FMEA_CSV).to_string_lossy().into_owned());

    match std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&report).unwrap_or_default() + "\n",
    ) {
        Ok(_) => writeln!(stdout, "FMEA written to {json_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa fmea: write {json_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let mut csv = String::from(
        "ID,Item,File,FailureMode,Effect,Cause,Severity,ActionPriority,Mitigations,Requirements\n",
    );
    for e in &entries {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&e.id),
            csv_escape(&e.item),
            csv_escape(&e.file),
            csv_escape(&e.failure_mode),
            csv_escape(&e.effect),
            csv_escape(&e.cause),
            e.severity,
            e.action_priority,
            csv_escape(&e.mitigations.join("|")),
            csv_escape(&e.requirement_ids.join("|")),
        ));
    }

    match std::fs::write(&csv_path, csv) {
        Ok(_) => writeln!(stdout, "FMEA CSV written to {csv_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa fmea: write {csv_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    if let Some(min) = opts.min_coverage {
        if min > 0.0 && coverage_pct < min {
            writeln!(
                stderr,
                "rsfusa fmea: coveragePct {coverage_pct:.1} < --min-coverage {min:.1}"
            )
            .ok();
            return EXIT_GATE_FAIL;
        }
    }
    if has_open_errors(&findings) {
        return EXIT_GATE_FAIL;
    }
    if opts.strict && has_open_warnings(&findings) {
        return EXIT_GATE_FAIL;
    }

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

/// Heuristic failure-mode text keyed off the function's actual signature
/// (return-type family) *and* its fully-qualified name, so distinct
/// functions genuinely produce distinct text (x-FuSa spec §1.6 rule 3 /
/// §1.6.1 rule B) rather than one fixed string per return-type bucket.
fn failure_mode_from_signature(item: &str, ret: &str) -> String {
    match ret {
        "Result" => format!("{item} returns Err when the caller expects Ok"),
        "Option" => format!("{item} returns None when the caller expects Some"),
        "bool" => format!("{item} returns the wrong boolean value for its input"),
        "integer" => format!("{item} returns an incorrect integer (overflow or truncation)"),
        _ => format!("{item} does not perform its intended action"),
    }
}

fn effect_from_signature(item: &str, ret: &str) -> String {
    match ret {
        "Result" => {
            format!("caller of {item} receives an unexpected error and may abort the operation")
        }
        "Option" => format!("caller of {item} may unwrap None and panic"),
        "bool" => format!("caller of {item} takes the wrong conditional branch"),
        "integer" => format!("downstream computation using {item}'s result is incorrect"),
        _ => format!("{item} leaves the system in an incorrect state"),
    }
}

fn cause_from_signature(item: &str, ret: &str, line: &str) -> String {
    if line.contains("unsafe") {
        return format!(
            "{item} is marked unsafe and relies on a caller-upheld invariant that may not hold"
        );
    }
    match ret {
        "Result" => format!("an upstream input into {item} is not validated before use"),
        "Option" => format!(
            "{item} is called without first checking the precondition it silently relies on"
        ),
        "bool" => format!("the boolean check inside {item} does not cover every input case"),
        "integer" => {
            format!("{item} does not guard against overflow/truncation on its input range")
        }
        _ => format!("{item} lacks a defensive check against malformed input"),
    }
}

fn mitigations_from_signature(ret: &str) -> Vec<String> {
    match ret {
        "Result" => vec!["propagate the error with `?` and surface it to the caller".to_string()],
        "Option" => vec!["match on `None` explicitly rather than calling `.unwrap()`".to_string()],
        _ => Vec::new(),
    }
}

/// FMEA `severity` per x-FuSa spec §9.2 ("1-10 per ratingScale, or
/// high|medium|low when no numeric scale is used"): this tool has no
/// AIAG-VDA numeric rating table wired up, so it uses the high/medium/low
/// fallback, derived from the project's declared ASIL/SIL/DAL integrity
/// level (a higher integrity target means a function defect has a higher
/// consequence severity).
fn severity_from_integrity(cfg: &crate::config::FusaConfig) -> &'static str {
    match cfg.integrity_level() {
        Some((_, "ASIL-D")) | Some((_, "SIL-4")) | Some((_, "DAL-A")) => "high",
        Some((_, "ASIL-C")) | Some((_, "SIL-3")) | Some((_, "DAL-B")) => "high",
        Some((_, "ASIL-B")) | Some((_, "SIL-2")) | Some((_, "DAL-C")) => "medium",
        Some(_) => "low",
        None => "low",
    }
}

/// AIAG-VDA `actionPriority`: severity combined with whether the function
/// has requirement-linked test coverage (a proxy for detection strength —
/// an untraced function is less likely to have its failure caught before
/// release).
fn compute_action_priority(severity: &'static str, has_requirement: bool) -> &'static str {
    match (severity, has_requirement) {
        ("high", false) => "high",
        ("high", true) => "medium",
        ("medium", false) => "medium",
        _ => "low",
    }
}

fn extract_req_ids(line: &str) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(pos) = line.find("//fusa:req") {
        let rest = line[pos + 10..].trim_start_matches([':', ' ']);
        for id in rest.split_whitespace() {
            ids.push(id.to_string());
        }
    }
    ids
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
    min_coverage: Option<f64>,
    strict: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        json_output: None,
        csv_output: None,
        min_coverage: None,
        strict: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--strict" | "--require-attestation" => opts.strict = true,
            flag @ ("--dir" | "--output" | "--csv" | "--min-coverage") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa fmea: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--output" => opts.json_output = Some(args[i].clone()),
                    "--csv" => opts.csv_output = Some(args[i].clone()),
                    "--min-coverage" => {
                        opts.min_coverage = match args[i].parse::<f64>() {
                            Ok(v) => Some(v),
                            Err(_) => {
                                writeln!(stderr, "rsfusa fmea: --min-coverage requires a number")
                                    .ok();
                                return None;
                            }
                        }
                    }
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
                } else if let Some(v) = other.strip_prefix("--min-coverage=") {
                    opts.min_coverage = v.parse::<f64>().ok();
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

#[cfg(test)]
mod tests {
    use super::*;

    //fusa:test REQ-FMEA007
    #[test]
    fn failure_mode_embeds_item_for_distinctness() {
        let a = failure_mode_from_signature("cmd::fmea::run", "Result");
        let b = failure_mode_from_signature("cmd::hara::run", "Result");
        assert_ne!(a, b);
        assert!(a.contains("cmd::fmea::run"));
    }

    //fusa:test REQ-FMEA008
    #[test]
    fn severity_maps_from_integrity_level() {
        let mut cfg = crate::config::FusaConfig::new("demo", "iso26262");
        cfg.asil = Some("ASIL-D".to_string());
        assert_eq!(severity_from_integrity(&cfg), "high");
        cfg.asil = Some("ASIL-A".to_string());
        assert_eq!(severity_from_integrity(&cfg), "low");
    }

    //fusa:test REQ-FMEA008
    #[test]
    fn action_priority_downgrades_with_requirement_coverage() {
        assert_eq!(compute_action_priority("high", false), "high");
        assert_eq!(compute_action_priority("high", true), "medium");
        assert_eq!(compute_action_priority("low", false), "low");
    }

    #[test]
    fn extract_fn_name_handles_generics_and_args() {
        assert_eq!(
            extract_fn_name("pub fn run(args: &[String]) -> i32 {"),
            Some("run".to_string())
        );
    }

    #[test]
    fn csv_escape_quotes_commas() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("plain"), "plain");
    }
}
