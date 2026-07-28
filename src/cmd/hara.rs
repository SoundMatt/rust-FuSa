// `rsfusa hara [show|init|asil]` — Hazard Analysis and Risk Assessment
// management, per ISO 26262-3:2018 Clause 6 and x-FuSa spec §1.2.5/§9.2.
//
// `.fusa-hara.json` is an **input** file (like `.fusa-reqs.json`): a project
// author writes/maintains it; `hara` validates and reports on it, scaffolding
// an empty template (never dummy rows, §1.6 rule 1) when absent.
//fusa:req REQ-HARA001
//fusa:req REQ-HARA002
//fusa:req REQ-HARA003
//fusa:req REQ-HARA004
//fusa:req REQ-HARA005
//fusa:req REQ-HARA006
//fusa:req REQ-HARA007
//fusa:req REQ-HARA008

use crate::attestation::Attestation;
use crate::config::load_reqs;
use crate::stub::{
    apply_project_dispositions, detect_blank_fallback, detect_placeholder, has_open_errors,
    has_open_warnings, QualField,
};
use crate::types::{
    EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const HARA_FILE: &str = ".fusa-hara.json";

/// §1.2.5 `operationalSituations[]` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationalSituation {
    pub id: String,
    #[serde(default)]
    pub description: String,
}

/// §1.2.5 `hazards[].risk` — ISO 26262-3 §6.4.3-6.4.5 S/E/C plus the derived
/// ASIL (§6.4.6, Table 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Risk {
    pub severity: String,
    pub exposure: String,
    pub controllability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asil: Option<String>,
}

/// §1.2.5 `hazards[]` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hazard {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub situations: Vec<String>,
    pub risk: Risk,
    #[serde(default)]
    pub safety_goals: Vec<String>,
}

/// §1.2.5 `safetyGoals[]` entry. `fssrRefs` is MUST, >=1 entry — a safety
/// goal with no decomposing requirement is exactly the traceability gap
/// ISO 26262-8 Clause 6 exists to prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyGoal {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub hazards: Vec<String>,
    pub asil: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_state: Option<String>,
    #[serde(default)]
    pub fssr_refs: Vec<String>,
}

/// §1.2.5 `.fusa-hara.json` schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HaraFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default)]
    pub operational_situations: Vec<OperationalSituation>,
    #[serde(default)]
    pub hazards: Vec<Hazard>,
    #[serde(default)]
    pub safety_goals: Vec<SafetyGoal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("show");
    let rest = if args.is_empty() { &[] } else { &args[1..] };

    let dir = parse_dir(rest);
    let project_root =
        dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let hara_path = project_root.join(HARA_FILE);

    match subcmd {
        "init" => cmd_init(&project_root, &hara_path, stdout, stderr),
        "show" => cmd_show(&project_root, &hara_path, rest, stdout, stderr),
        "asil" => cmd_asil(rest, stdout, stderr),
        other => {
            writeln!(stderr, "rsfusa hara: unknown subcommand: {other}").ok();
            writeln!(stderr, "Usage: rsfusa hara [show|init|asil] [--dir <path>]").ok();
            EXIT_USAGE
        }
    }
}

fn cmd_init(
    project_root: &Path,
    path: &PathBuf,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if path.exists() {
        writeln!(stdout, "{} already exists", path.display()).ok();
        return EXIT_OK;
    }
    let cfg = crate::config::load(&project_root.join(".fusa.json")).ok();
    let project = cfg.as_ref().map(|c| c.project.name.clone());
    let standard = cfg.as_ref().map(|c| c.standard.clone());

    // §1.6 rule 1: an empty, honestly-incomplete scaffold — never dummy rows.
    let hara = HaraFile {
        project,
        standard,
        created_at: Some(chrono::Utc::now().to_rfc3339()),
        operational_situations: Vec::new(),
        hazards: Vec::new(),
        safety_goals: Vec::new(),
        attestation: None,
    };
    let json = serde_json::to_string_pretty(&hara).unwrap_or_default();
    match std::fs::write(path, json + "\n") {
        Ok(_) => {
            writeln!(stdout, "Created {}", path.display()).ok();
            writeln!(
                stdout,
                "Populate operationalSituations/hazards/safetyGoals per ISO 26262-3 Clause 6."
            )
            .ok();
            EXIT_OK
        }
        Err(e) => {
            writeln!(stderr, "rsfusa hara init: {e}").ok();
            EXIT_RUNTIME
        }
    }
}

fn cmd_show(
    project_root: &Path,
    path: &PathBuf,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let format = parse_format(args);
    let strict = args
        .iter()
        .any(|a| a == "--strict" || a == "--require-attestation");

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

    let reqs = load_reqs(&project_root.join(".fusa-reqs.json")).ok();
    let known_reqs: HashSet<&str> = reqs
        .as_ref()
        .map(|r| r.requirements.iter().map(|x| x.id.as_str()).collect())
        .unwrap_or_default();
    let reqs_file_present = reqs.is_some();

    let (asil_findings, corrected_hazards) = derive_and_check_asil(&hara);
    let (ref_findings, dangling) =
        check_referential_integrity(&hara, &known_reqs, reqs_file_present);

    let completeness = compute_completeness(&hara, dangling);

    let content = serde_json::json!({
        "operationalSituations": hara.operational_situations,
        "hazards": corrected_hazards,
        "safetyGoals": hara.safety_goals,
    });
    let content_hash = crate::canonjson::content_hash(&content);

    let mut qual_fields = Vec::new();
    for s in &hara.operational_situations {
        qual_fields.push(QualField::new(
            s.id.clone(),
            "situationDescription",
            s.description.clone(),
        ));
    }
    for h in &hara.hazards {
        qual_fields.push(QualField::new(
            h.id.clone(),
            "hazardDescription",
            h.description.clone(),
        ));
    }
    for g in &hara.safety_goals {
        qual_fields.push(QualField::new(
            g.id.clone(),
            "safetyGoalDescription",
            g.description.clone(),
        ));
        if let Some(ss) = &g.safe_state {
            qual_fields.push(QualField::new(g.id.clone(), "safeState", ss.clone()));
        }
    }

    let mut findings = asil_findings;
    findings.extend(ref_findings);
    findings.extend(detect_placeholder(HARA_FILE, &qual_fields));
    let attestation_valid = hara
        .attestation
        .as_ref()
        .is_some_and(|a| crate::attestation::is_valid(a, &content_hash));
    if !attestation_valid {
        findings.extend(detect_blank_fallback(HARA_FILE, &qual_fields));
    }
    apply_project_dispositions(project_root, &mut findings);

    if format.as_deref() == Some("json") {
        let doc = serde_json::json!({
            "schemaVersion": SPEC_VERSION,
            "kind": "hara-report",
            "tool": TOOL_NAME,
            "toolVersion": VERSION,
            "language": LANGUAGE,
            "generatedAt": chrono::Utc::now().to_rfc3339(),
            "operationalSituations": hara.operational_situations,
            "hazards": corrected_hazards,
            "safetyGoals": hara.safety_goals,
            "completeness": completeness,
            "attestation": hara.attestation,
            "findings": findings,
        });
        writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&doc).unwrap_or_default()
        )
        .ok();
    } else {
        writeln!(stdout, "HARA ({} hazards)", hara.hazards.len()).ok();
        writeln!(
            stdout,
            "{:<10} {:<45} {:<3} {:<3} {:<3} {:<8}",
            "ID", "Description", "S", "E", "C", "ASIL"
        )
        .ok();
        writeln!(stdout, "{}", "-".repeat(80)).ok();
        for h in &corrected_hazards {
            writeln!(
                stdout,
                "{:<10} {:<45} {:<3} {:<3} {:<3} {:<8}",
                h.id,
                truncate(&h.description, 44),
                h.risk.severity,
                h.risk.exposure,
                h.risk.controllability,
                h.risk.asil.as_deref().unwrap_or("-"),
            )
            .ok();
        }
        for f in &findings {
            writeln!(stderr, "{}: {} ({})", f.severity, f.message, f.rule_id).ok();
        }
    }

    if has_open_errors(&findings) {
        return EXIT_GATE_FAIL;
    }
    if strict && has_open_warnings(&findings) {
        return EXIT_GATE_FAIL;
    }
    EXIT_OK
}

/// §1.2.5: `risk.asil` MUST be derived from severity x exposure x
/// controllability (ISO 26262-3 Table 4) when `standard` is `iso26262`,
/// never accepted as an arbitrary author-supplied value. Returns findings
/// for any hazard whose stored value disagrees, and the hazard list with
/// `risk.asil` corrected to the derived value.
fn derive_and_check_asil(hara: &HaraFile) -> (Vec<crate::types::Finding>, Vec<Hazard>) {
    use crate::types::{Category, Finding, Location, Severity};

    let is_iso26262 = hara.standard.as_deref() == Some("iso26262") || hara.standard.is_none();
    let mut findings = Vec::new();
    let mut out = Vec::with_capacity(hara.hazards.len());
    for h in &hara.hazards {
        let mut h = h.clone();
        if is_iso26262 {
            if let Some(derived) = iso26262_asil_from_risk(&h.risk) {
                if h.risk.asil.as_deref() != Some(derived) {
                    findings.push(Finding::new(
                        "HARA002",
                        Severity::Warning,
                        format!(
                            "hazard {}: risk.asil {:?} disagrees with the value derived from S={}/E={}/C={} ({derived}); using the derived value",
                            h.id, h.risk.asil, h.risk.severity, h.risk.exposure, h.risk.controllability
                        ),
                        Location::new(HARA_FILE),
                        Category::Safety,
                        "let the tool derive risk.asil rather than hand-editing it",
                    ));
                }
                h.risk.asil = Some(derived.to_string());
            }
        }
        out.push(h);
    }
    (findings, out)
}

fn iso26262_asil_from_risk(risk: &Risk) -> Option<&'static str> {
    let s: u8 = risk.severity.trim_start_matches('S').parse().ok()?;
    let e: u8 = risk.exposure.trim_start_matches('E').parse().ok()?;
    let c: u8 = risk.controllability.trim_start_matches('C').parse().ok()?;
    Some(iso26262_asil(s, e, c))
}

/// Referential integrity (§1.2.5 MUST): every cross-reference must resolve.
/// `hazards[].situations`/`hazards[].safetyGoals`/`safetyGoals[].hazards` are
/// checked against the file's own collections; `safetyGoals[].fssrRefs` is
/// checked against the project's `.fusa-reqs.json` (§1.4.1's dangling-
/// reference rule).
fn check_referential_integrity(
    hara: &HaraFile,
    known_reqs: &HashSet<&str>,
    reqs_file_present: bool,
) -> (Vec<crate::types::Finding>, usize) {
    use crate::types::{Category, Finding, Location, Severity};

    let situation_ids: HashSet<&str> = hara
        .operational_situations
        .iter()
        .map(|s| s.id.as_str())
        .collect();
    let hazard_ids: HashSet<&str> = hara.hazards.iter().map(|h| h.id.as_str()).collect();
    let goal_ids: HashSet<&str> = hara.safety_goals.iter().map(|g| g.id.as_str()).collect();

    let mut findings = Vec::new();
    let mut dangling = 0usize;

    for h in &hara.hazards {
        for sid in &h.situations {
            if !situation_ids.contains(sid.as_str()) {
                dangling += 1;
                findings.push(Finding::new(
                    "HARA001",
                    Severity::Warning,
                    format!(
                        "hazard {} references unknown operational situation {sid:?}",
                        h.id
                    ),
                    Location::new(HARA_FILE),
                    Category::Safety,
                    "add the situation to operationalSituations[] or fix the id",
                ));
            }
        }
        for gid in &h.safety_goals {
            if !goal_ids.contains(gid.as_str()) {
                dangling += 1;
                findings.push(Finding::new(
                    "HARA001",
                    Severity::Warning,
                    format!("hazard {} references unknown safety goal {gid:?}", h.id),
                    Location::new(HARA_FILE),
                    Category::Safety,
                    "add the goal to safetyGoals[] or fix the id",
                ));
            }
        }
    }
    for g in &hara.safety_goals {
        for hid in &g.hazards {
            if !hazard_ids.contains(hid.as_str()) {
                dangling += 1;
                findings.push(Finding::new(
                    "HARA001",
                    Severity::Warning,
                    format!("safety goal {} references unknown hazard {hid:?}", g.id),
                    Location::new(HARA_FILE),
                    Category::Safety,
                    "add the hazard to hazards[] or fix the id",
                ));
            }
        }
        if g.fssr_refs.is_empty() {
            findings.push(Finding::new(
                "REQ002",
                Severity::Warning,
                format!("safety goal {} has no fssrRefs (MUST, >=1 entry per x-FuSa spec §1.2.5)", g.id),
                Location::new(HARA_FILE),
                Category::Requirement,
                "decompose the safety goal into at least one functional safety requirement in .fusa-reqs.json",
            ));
        }
        for rid in &g.fssr_refs {
            let resolves = reqs_file_present && known_reqs.contains(rid.as_str());
            if !resolves {
                dangling += 1;
                findings.push(Finding::new(
                    "REQ002",
                    Severity::Warning,
                    format!(
                        "safety goal {} fssrRefs references unknown requirement id {rid:?}",
                        g.id
                    ),
                    Location::new(HARA_FILE),
                    Category::Requirement,
                    "add the requirement to .fusa-reqs.json or fix the id",
                ));
            }
        }
    }
    (findings, dangling)
}

fn compute_completeness(hara: &HaraFile, dangling_references: usize) -> Value {
    let total_hazards = hara.hazards.len();
    let hazards_with_asil = hara
        .hazards
        .iter()
        .filter(|h| h.risk.asil.is_some())
        .count();
    let hazards_with_safety_goal = hara
        .hazards
        .iter()
        .filter(|h| !h.safety_goals.is_empty())
        .count();
    let total_safety_goals = hara.safety_goals.len();
    let safety_goals_with_fssr_refs = hara
        .safety_goals
        .iter()
        .filter(|g| !g.fssr_refs.is_empty())
        .count();
    serde_json::json!({
        "totalHazards": total_hazards,
        "hazardsWithAsil": hazards_with_asil,
        "hazardsWithSafetyGoal": hazards_with_safety_goal,
        "totalSafetyGoals": total_safety_goals,
        "safetyGoalsWithFssrRefs": safety_goals_with_fssr_refs,
        "danglingReferences": dangling_references,
    })
}

fn cmd_asil(args: &[String], stdout: &mut dyn Write, _stderr: &mut dyn Write) -> i32 {
    // Derive ASIL from S/E/C: rsfusa hara asil --severity S3 --exposure E4 --controllability C2
    let s = parse_flag(args, "--severity").unwrap_or_else(|| "S1".to_string());
    let e = parse_flag(args, "--exposure").unwrap_or_else(|| "E1".to_string());
    let c = parse_flag(args, "--controllability").unwrap_or_else(|| "C1".to_string());

    let s_num: u8 = s.trim_start_matches('S').parse().unwrap_or(1);
    let e_num: u8 = e.trim_start_matches('E').parse().unwrap_or(1);
    let c_num: u8 = c.trim_start_matches('C').parse().unwrap_or(1);

    let asil = iso26262_asil(s_num, e_num, c_num);

    if parse_format(args).as_deref() == Some("json") {
        let out = serde_json::json!({
            "severity": s, "exposure": e, "controllability": c, "asil": asil
        });
        writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_default()
        )
        .ok();
    } else {
        writeln!(stdout, "S={s}  E={e}  C={c}  →  ASIL = {asil}").ok();
    }
    EXIT_OK
}

/// ISO 26262-3:2018 Table 4, reproduced verbatim (severity is S0-S3 per
/// x-FuSa spec §1.2.5 — there is no S4). Earlier revisions of this function
/// approximated the table with a `severity x exposure x controllability`
/// score threshold; that product model does not actually match the
/// standard's discrete table at every combination (e.g. it under-rates
/// S3/E2/C2, which Table 4 rates ASIL-A, not QM), so this is now the literal
/// table rather than an approximation of it — this function's result is
/// used verbatim as `hazards[].risk.asil` (§1.2.5 MUST), so an approximation
/// error here would silently misstate a hazard's integrity level.
fn iso26262_asil(s: u8, e: u8, c: u8) -> &'static str {
    match (s, e, c) {
        (1, 1, _) => "QM",
        (1, 2, _) => "QM",
        (1, 3, 1) | (1, 3, 2) => "QM",
        (1, 3, 3) => "ASIL-A",
        (1, 4, 1) => "QM",
        (1, 4, 2) => "ASIL-A",
        (1, 4, 3) => "ASIL-B",
        (2, 1, _) => "QM",
        (2, 2, 1) | (2, 2, 2) => "QM",
        (2, 2, 3) => "ASIL-A",
        (2, 3, 1) => "QM",
        (2, 3, 2) => "ASIL-A",
        (2, 3, 3) => "ASIL-B",
        (2, 4, 1) => "ASIL-A",
        (2, 4, 2) => "ASIL-B",
        (2, 4, 3) => "ASIL-C",
        (3, 1, 1) | (3, 1, 2) => "QM",
        (3, 1, 3) => "ASIL-A",
        (3, 2, 1) => "QM",
        (3, 2, 2) => "ASIL-A",
        (3, 2, 3) => "ASIL-B",
        (3, 3, 1) => "ASIL-A",
        (3, 3, 2) => "ASIL-B",
        (3, 3, 3) => "ASIL-C",
        (3, 4, 1) => "ASIL-B",
        (3, 4, 2) => "ASIL-C",
        (3, 4, 3) => "ASIL-D",
        // S0 (no injuries) or any out-of-range value: fail-safe to QM
        // rather than guessing a higher integrity level.
        _ => "QM",
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

fn parse_format(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--format" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(v) = args[i].strip_prefix("--format=") {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hara() -> HaraFile {
        HaraFile {
            project: Some("demo".to_string()),
            standard: Some("iso26262".to_string()),
            created_at: Some("2026-07-28T00:00:00Z".to_string()),
            operational_situations: vec![OperationalSituation {
                id: "OS-001".to_string(),
                description: "High-rate input processing".to_string(),
            }],
            hazards: vec![Hazard {
                id: "H-001".to_string(),
                description: "Software produces incorrect output under high input load".to_string(),
                source: Some("code review".to_string()),
                situations: vec!["OS-001".to_string()],
                risk: Risk {
                    severity: "S2".to_string(),
                    exposure: "E3".to_string(),
                    controllability: "C2".to_string(),
                    asil: Some("ASIL-A".to_string()),
                },
                safety_goals: vec!["SG-001".to_string()],
            }],
            safety_goals: vec![SafetyGoal {
                id: "SG-001".to_string(),
                description: "The system shall not produce incorrect output under load".to_string(),
                hazards: vec!["H-001".to_string()],
                asil: "ASIL-A".to_string(),
                safe_state: Some("reject input and raise an alarm".to_string()),
                fssr_refs: vec!["REQ-FO-001".to_string()],
            }],
            attestation: None,
        }
    }

    //fusa:test REQ-HARA002
    #[test]
    fn iso26262_asil_table_matches_known_points() {
        // Table 4: S3/E4/C3 -> ASIL-D (the worst case in the table).
        assert_eq!(iso26262_asil(3, 4, 3), "ASIL-D");
        // Table 4: S3/E2/C2 -> ASIL-A (a case a naive S*E*C product model
        // under-rates — this is exactly why the table is literal, not a
        // score threshold).
        assert_eq!(iso26262_asil(3, 2, 2), "ASIL-A");
        // Table 4: S2/E1 is always QM regardless of controllability.
        assert_eq!(iso26262_asil(2, 1, 3), "QM");
        // Out-of-range severity (e.g. an invalid "S4") fails safe to QM
        // rather than guessing a higher integrity level.
        assert_eq!(iso26262_asil(4, 4, 4), "QM");
    }

    //fusa:test REQ-HARA006
    #[test]
    fn asil_derivation_agrees_with_correct_hazard() {
        let hara = sample_hara();
        let (findings, corrected) = derive_and_check_asil(&hara);
        assert!(
            findings.is_empty(),
            "expected no disagreement findings: {findings:?}"
        );
        assert_eq!(corrected[0].risk.asil.as_deref(), Some("ASIL-A"));
    }

    //fusa:test REQ-HARA006
    #[test]
    fn asil_derivation_flags_and_corrects_disagreement() {
        let mut hara = sample_hara();
        hara.hazards[0].risk.asil = Some("ASIL-D".to_string());
        let (findings, corrected) = derive_and_check_asil(&hara);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "HARA002");
        assert_eq!(corrected[0].risk.asil.as_deref(), Some("ASIL-A"));
    }

    //fusa:test REQ-HARA007
    #[test]
    fn referential_integrity_clean_file_has_no_dangling_refs() {
        let hara = sample_hara();
        let known = ["REQ-FO-001"].into_iter().collect();
        let (findings, dangling) = check_referential_integrity(&hara, &known, true);
        assert_eq!(dangling, 0, "{findings:?}");
        assert!(findings.is_empty());
    }

    //fusa:test REQ-HARA007
    #[test]
    fn referential_integrity_flags_dangling_situation() {
        let mut hara = sample_hara();
        hara.hazards[0].situations = vec!["OS-999".to_string()];
        let known = ["REQ-FO-001"].into_iter().collect();
        let (findings, dangling) = check_referential_integrity(&hara, &known, true);
        assert_eq!(dangling, 1);
        assert!(findings.iter().any(|f| f.rule_id == "HARA001"));
    }

    //fusa:test REQ-HARA007
    #[test]
    fn referential_integrity_flags_missing_fssr_refs() {
        let mut hara = sample_hara();
        hara.safety_goals[0].fssr_refs.clear();
        let known: HashSet<&str> = HashSet::new();
        let (findings, _) = check_referential_integrity(&hara, &known, true);
        assert!(findings.iter().any(|f| f.rule_id == "REQ002"));
    }

    //fusa:test REQ-HARA007
    #[test]
    fn referential_integrity_flags_dangling_fssr_ref() {
        let hara = sample_hara();
        let known: HashSet<&str> = HashSet::new();
        let (findings, dangling) = check_referential_integrity(&hara, &known, true);
        assert_eq!(dangling, 1);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "REQ002" && f.message.contains("REQ-FO-001")));
    }

    //fusa:test REQ-HARA007
    #[test]
    fn completeness_counts_match_sample() {
        let hara = sample_hara();
        let c = compute_completeness(&hara, 0);
        assert_eq!(c["totalHazards"], 1);
        assert_eq!(c["hazardsWithAsil"], 1);
        assert_eq!(c["safetyGoalsWithFssrRefs"], 1);
    }

    //fusa:test REQ-HARA008
    #[test]
    fn init_scaffold_has_empty_arrays_not_dummy_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HARA_FILE);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = cmd_init(dir.path(), &path, &mut out, &mut err);
        assert_eq!(code, EXIT_OK);
        let data = std::fs::read_to_string(&path).unwrap();
        let hara: HaraFile = serde_json::from_str(&data).unwrap();
        assert!(hara.hazards.is_empty());
        assert!(hara.operational_situations.is_empty());
        assert!(hara.safety_goals.is_empty());
    }
}
