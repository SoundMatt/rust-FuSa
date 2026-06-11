// Standards gap reports: iso26262, iec61508, do178c, iso21434, unece, misra.
// Each maps evidence files to standard requirements and reports gaps.

use crate::types::{EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;
use std::path::PathBuf;

struct Requirement {
    id: &'static str,
    title: &'static str,
    evidence_file: Option<&'static str>,
    required: bool,
}

macro_rules! req {
    ($id:expr, $title:expr, $file:expr, $req:expr) => {
        Requirement { id: $id, title: $title, evidence_file: $file, required: $req }
    };
}

const ISO26262_REQS: &[Requirement] = &[
    req!("ISO26262-6.5.4",  "Software requirements specification",     Some(".fusa-reqs.json"),          true),
    req!("ISO26262-6.6.1",  "Software architectural design",           Some("boundary.mermaid"),          true),
    req!("ISO26262-6.7",    "Software unit design and implementation", Some("check-report.json"),         true),
    req!("ISO26262-6.8",    "Software unit verification",              Some(".fusa-evidence.json"),        true),
    req!("ISO26262-6.9",    "Software integration and verification",   Some(".fusa-evidence.json"),        true),
    req!("ISO26262-6.4.6",  "Use of restricted language subset",       Some("check-report.json"),         true),
    req!("ISO26262-6.4.4",  "Data coupling analysis",                  Some("coupling-report.json"),      true),
    req!("ISO26262-6.10",   "Qualification of software components",    Some("qualify-report.json"),       true),
    req!("ISO26262-6.11",   "FMEA (dFMEA)",                            Some("fmea.json"),                 false),
    req!("ISO26262-8.6",    "Software safety analysis",                Some("check-report.json"),         true),
    req!("ISO26262-8.7",    "Traceability",                            Some("trace.json"),                true),
    req!("ISO26262-8.8",    "Configuration management (SBOM)",         Some("sbom.json"),                 true),
    req!("ISO26262-8.9",    "Documentation and evidence archive",      Some("audit-pack.zip"),            true),
];

const IEC61508_REQS: &[Requirement] = &[
    req!("IEC61508-2.1",    "Safety requirements specification",       Some(".fusa-reqs.json"),           true),
    req!("IEC61508-3.4.1",  "Software design",                         Some("boundary.mermaid"),          true),
    req!("IEC61508-3.4.2",  "Coding standards compliance",             Some("check-report.json"),         true),
    req!("IEC61508-3.4.3",  "Unit testing",                            Some(".fusa-evidence.json"),        true),
    req!("IEC61508-3.4.4",  "Static analysis",                         Some("check-report.json"),         true),
    req!("IEC61508-3.4.5",  "Traceability",                            Some("trace.json"),                true),
    req!("IEC61508-3.6.4",  "FMEA",                                    Some("fmea.json"),                 false),
    req!("IEC61508-3.7",    "Software qualification testing",          Some("qualify-report.json"),       true),
    req!("IEC61508-3.8",    "Software validation",                     Some(".fusa-evidence.json"),        true),
    req!("IEC61508-3.9",    "Configuration management",                Some("sbom.json"),                 true),
];

const DO178C_REQS: &[Requirement] = &[
    req!("DO178C-A.1",  "System requirements",             Some(".fusa-reqs.json"),      true),
    req!("DO178C-A.2",  "Software requirements",           Some(".fusa-reqs.json"),      true),
    req!("DO178C-A.3",  "Software design description",     Some("boundary.mermaid"),     true),
    req!("DO178C-A.4",  "Source code",                     None,                          true),
    req!("DO178C-A.5",  "Software test cases",             Some(".fusa-evidence.json"),   true),
    req!("DO178C-A.6",  "Software test results",           Some(".fusa-evidence.json"),   true),
    req!("DO178C-A.7",  "Software coverage analysis",      Some("coverage-report.json"), false),
    req!("DO178C-A.8",  "SBOM / SCI",                      Some("sbom.json"),             true),
    req!("DO178C-A.9",  "SAS",                             Some("sas.md"),                false),
    req!("DO178C-11.16","Software Configuration Index",    Some("sci.json"),              false),
    req!("DO178C-11.20","Software Accomplishment Summary", Some("sas.md"),                false),
];

const ISO21434_REQS: &[Requirement] = &[
    req!("ISO21434-9.3",   "TARA",                               Some("tara.json"),          true),
    req!("ISO21434-11.1",  "Cybersecurity requirements",         Some(".fusa-reqs.json"),    true),
    req!("ISO21434-11.4",  "Cybersecurity code review",          Some("cyber-report.json"),  true),
    req!("ISO21434-11.4.3","Vulnerability analysis (TARA)",      Some("tara.json"),          true),
    req!("ISO21434-12",    "Cybersecurity testing",              Some(".fusa-evidence.json"), true),
    req!("ISO21434-13",    "Vulnerability monitoring (SBOM)",    Some("vuln.json"),           true),
    req!("ISO21434-14",    "Incident response plan",             None,                         false),
];

const UNECE_REQS: &[Requirement] = &[
    req!("R155-7.2.1",  "Cybersecurity management system",     None,                          false),
    req!("R155-7.3.1",  "Threat analysis (TARA)",              Some("tara.json"),             true),
    req!("R155-7.3.2",  "Security by design",                  Some("cyber-report.json"),     true),
    req!("R155-7.3.3",  "Secure communication",                Some("cyber-report.json"),     true),
    req!("R155-7.3.4",  "Secure storage",                      Some("check-report.json"),     true),
    req!("R155-7.3.5",  "Dependency vulnerability tracking",   Some("vuln.json"),             true),
    req!("R155-7.3.6",  "Software update capability",          None,                          false),
    req!("R155-Annex5", "Audit evidence",                       Some("audit-pack.zip"),        true),
];

const MISRA_REQS: &[Requirement] = &[
    req!("MISRA-C-2.1",  "Code shall not be unreachable",              Some("check-report.json"), true),
    req!("MISRA-C-2.7",  "No unused parameters",                       Some("check-report.json"), false),
    req!("MISRA-C-10.1", "Implicit conversion is not performed",       Some("check-report.json"), true),
    req!("MISRA-C-12.2", "Right shift of signed integers",             Some("check-report.json"), true),
    req!("MISRA-C-13.6", "Side effects in sizeof not performed",       None,                       false),
    req!("MISRA-C-17.7", "Return value of non-void function used",     Some("check-report.json"), true),
    req!("MISRA-C-22.1", "Resources shall be freed in inverse order",  Some("check-report.json"), false),
    req!("RUST-MISRA",   "Rust-specific: no unsafe without justification", Some("check-report.json"), true),
];

pub fn run_iso26262(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_gap_report("iso26262", "ISO 26262 Part 6", ISO26262_REQS, args, stdout, stderr)
}

pub fn run_iec61508(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_gap_report("iec61508", "IEC 61508 Part 3", IEC61508_REQS, args, stdout, stderr)
}

pub fn run_do178c(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_gap_report("do178c", "DO-178C Annex A", DO178C_REQS, args, stdout, stderr)
}

pub fn run_iso21434(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_gap_report("iso21434", "ISO 21434", ISO21434_REQS, args, stdout, stderr)
}

pub fn run_unece(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_gap_report("unece-r155", "UN R.155", UNECE_REQS, args, stdout, stderr)
}

pub fn run_misra(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_gap_report("misra", "MISRA C:2023 / Rust safety rules", MISRA_REQS, args, stdout, stderr)
}

fn run_gap_report(
    standard_id: &str,
    standard_name: &str,
    requirements: &[Requirement],
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let opts = match parse(args, stderr, standard_id) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    let mut items: Vec<serde_json::Value> = Vec::new();
    let mut gap_count = 0usize;
    let mut required_gaps = 0usize;

    for req in requirements {
        let present = req.evidence_file
            .map(|f| project_root.join(f).exists())
            .unwrap_or(false);

        let status = if present { "met" } else { "gap" };
        if status == "gap" { gap_count += 1; }
        if status == "gap" && req.required { required_gaps += 1; }

        items.push(serde_json::json!({
            "id": req.id,
            "title": req.title,
            "evidenceFile": req.evidence_file,
            "required": req.required,
            "status": status,
        }));
    }

    let total = requirements.len();
    let met = total - gap_count;

    if opts.format == "json" {
        let report = serde_json::json!({
            "schemaVersion": SPEC_VERSION,
            "kind": "gap-report",
            "tool": TOOL_NAME,
            "toolVersion": VERSION,
            "language": LANGUAGE,
            "generatedAt": chrono::Utc::now().to_rfc3339(),
            "standard": standard_id,
            "standardName": standard_name,
            "requirements": items,
            "summary": {
                "total": total,
                "met": met,
                "gaps": gap_count,
                "requiredGaps": required_gaps,
            }
        });
        let json = serde_json::to_string_pretty(&report).unwrap();
        match opts.output.as_deref() {
            Some(path) => {
                if let Err(e) = std::fs::write(path, json + "\n") {
                    writeln!(stderr, "rsfusa {standard_id}: write {path}: {e}").ok();
                    return EXIT_RUNTIME;
                }
                writeln!(stdout, "Gap report written to {path}").ok();
            }
            None => { writeln!(stdout, "{json}").ok(); }
        }
    } else {
        writeln!(stdout, "{standard_name} Compliance Gap Report").ok();
        writeln!(stdout, "{}", "=".repeat(50)).ok();
        writeln!(stdout, "{:<18} {:<44} {}", "Requirement", "Title", "Status").ok();
        writeln!(stdout, "{}", "-".repeat(80)).ok();
        for item in &items {
            let status_str = if item["status"] == "met" { "MET" } else { "GAP" };
            writeln!(stdout, "{:<18} {:<44} {}",
                item["id"].as_str().unwrap_or(""),
                truncate(item["title"].as_str().unwrap_or(""), 43),
                status_str
            ).ok();
        }
        writeln!(stdout, "{}", "-".repeat(80)).ok();
        writeln!(stdout, "Total: {total}  Met: {met}  Gaps: {gap_count}  Required gaps: {required_gaps}").ok();

        if let Some(path) = opts.output.as_deref() {
            let report = serde_json::json!({
                "schemaVersion": SPEC_VERSION,
                "kind": "gap-report",
                "tool": TOOL_NAME,
                "toolVersion": VERSION,
                "language": LANGUAGE,
                "generatedAt": chrono::Utc::now().to_rfc3339(),
                "standard": standard_id,
                "standardName": standard_name,
                "requirements": items,
                "summary": { "total": total, "met": met, "gaps": gap_count, "requiredGaps": required_gaps }
            });
            if let Err(e) = std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n") {
                writeln!(stderr, "rsfusa {standard_id}: write {path}: {e}").ok();
                return EXIT_RUNTIME;
            }
            writeln!(stdout, "Gap report written to {path}").ok();
        }
    }

    if required_gaps > 0 { EXIT_GATE_FAIL } else { EXIT_OK }
}

struct Opts {
    dir: Option<PathBuf>,
    format: String,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write, cmd: &str) -> Option<Opts> {
    let mut opts = Opts { dir: None, format: "text".to_string(), output: None };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--format" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa {cmd}: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--format" => opts.format = args[i].clone(),
                    "--output" => opts.output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--format=") { opts.format = v.to_string(); }
                else if let Some(v) = other.strip_prefix("--output=") { opts.output = Some(v.to_string()); }
                else {
                    writeln!(stderr, "rsfusa {cmd}: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max - 1]) }
}
