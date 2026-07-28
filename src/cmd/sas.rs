// `rsfusa sas` — Software Accomplishment Summary per DO-178C §11.20,
// x-FuSa spec §9.3. Reports on which of DO-178C's twenty §11 life-cycle
// data items this project has real evidence for.
//fusa:req REQ-SC002
//fusa:req REQ-SAS001
//fusa:req REQ-SAS002
//fusa:req REQ-SAS003
//fusa:req REQ-SAS004

use crate::attestation::Attestation;
use crate::config::load;
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

pub const SAS_MD: &str = "sas.md";
pub const SAS_JSON: &str = "sas.json";

/// One DO-178C §11 life-cycle data item. `file` is a heuristic evidence
/// candidate this tool can check for automatically; several §11 items
/// (plans, standards documents, object code, SCM records) are process
/// artifacts no CLI can detect from repo contents alone — for those `file`
/// is `None` and the item is honestly reported `present: false` rather than
/// guessed.
struct ChecklistItem {
    item: &'static str,
    clause: &'static str,
    file: Option<&'static str>,
}

const CHECKLIST: &[ChecklistItem] = &[
    ChecklistItem {
        item: "Plan for Software Aspects of Certification (PSAC)",
        clause: "11.1",
        file: None,
    },
    ChecklistItem {
        item: "Software Development Plan (SDP)",
        clause: "11.2",
        file: None,
    },
    ChecklistItem {
        item: "Software Verification Plan (SVP)",
        clause: "11.3",
        file: None,
    },
    ChecklistItem {
        item: "Software Configuration Management Plan (SCMP)",
        clause: "11.4",
        file: None,
    },
    ChecklistItem {
        item: "Software Quality Assurance Plan (SQAP)",
        clause: "11.5",
        file: None,
    },
    ChecklistItem {
        item: "Software Requirements Standards",
        clause: "11.6",
        file: None,
    },
    ChecklistItem {
        item: "Software Design Standards",
        clause: "11.7",
        file: None,
    },
    ChecklistItem {
        item: "Software Code Standards",
        clause: "11.8",
        file: None,
    },
    ChecklistItem {
        item: "Software Requirements Data",
        clause: "11.9",
        file: Some(".fusa-reqs.json"),
    },
    ChecklistItem {
        item: "Design Description",
        clause: "11.10",
        file: Some("boundary.mermaid"),
    },
    ChecklistItem {
        item: "Source Code",
        clause: "11.11",
        file: Some("src"),
    },
    ChecklistItem {
        item: "Executable Object Code",
        clause: "11.12",
        file: None,
    },
    ChecklistItem {
        item: "Software Verification Cases and Procedures",
        clause: "11.13",
        file: Some(".fusa-evidence.json"),
    },
    ChecklistItem {
        item: "Software Verification Results",
        clause: "11.14",
        file: Some("check-report.json"),
    },
    ChecklistItem {
        item: "Software Life Cycle Environment Configuration Index",
        clause: "11.15",
        file: Some("Cargo.lock"),
    },
    ChecklistItem {
        item: "Software Configuration Index (SCI)",
        clause: "11.16",
        file: Some("sci.json"),
    },
    ChecklistItem {
        item: "Problem Reports",
        clause: "11.17",
        file: Some(".fusa-problems.json"),
    },
    ChecklistItem {
        item: "Software Configuration Management Records",
        clause: "11.18",
        file: None,
    },
    ChecklistItem {
        item: "Software Quality Assurance Records",
        clause: "11.19",
        file: Some("qualify-report.json"),
    },
    ChecklistItem {
        item: "Software Accomplishment Summary (SAS)",
        clause: "11.20",
        file: Some("sas.md"),
    },
];

/// §9.3 `sas.json` `checklist[]` entry.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct ChecklistEntry {
    item: &'static str,
    clause: &'static str,
    present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<&'static str>,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let cfg = load(&project_root.join(".fusa.json")).ok();
    let project = cfg
        .as_ref()
        .map(|c| c.project.name.as_str())
        .unwrap_or("unknown");
    let version = cfg
        .as_ref()
        .map(|c| c.project.version.as_str())
        .unwrap_or("0.0.0");
    let standard = cfg
        .as_ref()
        .map(|c| c.standard.as_str())
        .unwrap_or("generic");
    let dal = cfg
        .as_ref()
        .and_then(|c| c.dal.as_deref())
        .or_else(|| cfg.as_ref().and_then(|c| c.asil.as_deref()))
        .unwrap_or("unclassified");

    let mut checklist: Vec<ChecklistEntry> = Vec::new();
    for item in CHECKLIST {
        let present = item.file.is_some_and(|f| project_root.join(f).exists());
        checklist.push(ChecklistEntry {
            item: item.item,
            clause: item.clause,
            present,
            evidence: if present { item.file } else { None },
        });
    }
    let present_count = checklist.iter().filter(|c| c.present).count();

    let mut qual_fields = Vec::new();
    for c in &checklist {
        qual_fields.push(QualField::new(c.clause, "item", c.item.to_string()));
    }

    let content = serde_json::json!({ "checklist": checklist });
    let content_hash = crate::canonjson::content_hash(&content);
    let json_path = project_root.join(SAS_JSON).to_string_lossy().into_owned();
    let attestation: Option<Attestation> = crate::attestation::carry_forward(
        crate::attestation::read_existing(Path::new(&json_path)),
        &content_hash,
    );
    let attestation_valid = attestation
        .as_ref()
        .is_some_and(|a| crate::attestation::is_valid(a, &content_hash));

    let mut findings = detect_placeholder(SAS_JSON, &qual_fields);
    if !attestation_valid {
        findings.extend(detect_blank_fallback(SAS_JSON, &qual_fields));
    }
    apply_project_dispositions(&project_root, &mut findings);
    for f in &findings {
        writeln!(stderr, "{}: {} ({})", f.severity, f.message, f.rule_id).ok();
    }

    let now = chrono::Utc::now();

    if opts.format.as_deref() == Some("json") {
        let report = serde_json::json!({
            "schemaVersion": SPEC_VERSION,
            "kind": "sas",
            "tool": TOOL_NAME,
            "toolVersion": VERSION,
            "language": LANGUAGE,
            "generatedAt": now.to_rfc3339(),
            "project": project,
            "version": version,
            "standard": standard,
            "dal": dal,
            "checklist": checklist,
            "summary": { "total": CHECKLIST.len(), "present": present_count },
            "attestation": attestation,
            "findings": findings,
        });
        let path_str = opts.output.clone().unwrap_or(json_path);
        if let Err(e) = std::fs::write(
            &path_str,
            serde_json::to_string_pretty(&report).unwrap_or_default() + "\n",
        ) {
            writeln!(stderr, "rsfusa sas: write {path_str}: {e}").ok();
            return EXIT_RUNTIME;
        }
        writeln!(stdout, "SAS written to {path_str}").ok();
    } else {
        let mut md = format!(
            "# Software Accomplishment Summary (SAS)\n\n\
             **DO-178C §11.20**\n\n\
             | Field | Value |\n\
             |-------|-------|\n\
             | Project | {project} |\n\
             | Version | {version} |\n\
             | Standard | {standard} |\n\
             | DAL/ASIL | {dal} |\n\
             | Generated | {} |\n\
             | Tool | {} {} (spec {}) |\n\n",
            now.format("%Y-%m-%dT%H:%M:%SZ"),
            TOOL_NAME,
            VERSION,
            SPEC_VERSION
        );

        md.push_str("## Software Life Cycle Data (DO-178C §11)\n\n");
        md.push_str("| Clause | Data Item | Evidence | Status |\n");
        md.push_str("|--------|-----------|----------|--------|\n");
        for c in &checklist {
            let status = if c.present {
                ":white_check_mark: Present"
            } else {
                ":x: Missing"
            };
            let evidence = c
                .evidence
                .map(|e| format!("`{e}`"))
                .unwrap_or_else(|| "—".to_string());
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                c.clause, c.item, evidence, status
            ));
        }

        md.push_str(&format!(
            "\n## Conformance Statement\n\n\
             {present_count} of {} §11 data items have automatically-detected evidence in this repository.\n\n\
             This SAS was generated automatically by {TOOL_NAME} {VERSION}. \
             A qualified safety engineer must review and sign this document before submission.\n",
            CHECKLIST.len()
        ));

        let out_path = opts
            .output
            .clone()
            .unwrap_or_else(|| project_root.join(SAS_MD).to_string_lossy().into_owned());
        if let Err(e) = std::fs::write(&out_path, &md) {
            writeln!(stderr, "rsfusa sas: write {out_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
        writeln!(stdout, "SAS written to {out_path}").ok();
        writeln!(
            stdout,
            "Evidence: {present_count}/{} present",
            CHECKLIST.len()
        )
        .ok();
    }

    if has_open_errors(&findings) {
        return EXIT_GATE_FAIL;
    }
    if opts.strict && has_open_warnings(&findings) {
        return EXIT_GATE_FAIL;
    }
    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
    strict: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        format: None,
        output: None,
        strict: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--strict" | "--require-attestation" => opts.strict = true,
            flag @ ("--dir" | "--format" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa sas: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                let val = args[i].clone();
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(val)),
                    "--format" => opts.format = Some(val),
                    "--output" => opts.output = Some(val),
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
                } else {
                    writeln!(stderr, "rsfusa sas: unknown flag: {other}").ok();
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

    //fusa:test REQ-SAS004
    #[test]
    fn checklist_covers_all_twenty_do178c_items() {
        assert_eq!(CHECKLIST.len(), 20);
        assert_eq!(CHECKLIST[0].clause, "11.1");
        assert_eq!(CHECKLIST[19].clause, "11.20");
    }

    //fusa:test REQ-SAS004
    #[test]
    fn checklist_clauses_are_unique() {
        let mut clauses: Vec<&str> = CHECKLIST.iter().map(|c| c.clause).collect();
        let before = clauses.len();
        clauses.sort_unstable();
        clauses.dedup();
        assert_eq!(clauses.len(), before);
    }
}
