// `rsfusa sas` — Software Accomplishment Summary per DO-178C §11.20,
// x-FuSa spec §9.3. Reports on which of DO-178C's twenty §11 life-cycle
// data items this project has real evidence for.
//fusa:req REQ-SC002
//fusa:req REQ-SAS001
//fusa:req REQ-SAS002
//fusa:req REQ-SAS003
//fusa:req REQ-SAS004
//fusa:req REQ-SAS005

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

    // rust-FuSa-08: a DO-178C §11.20 Software Accomplishment Summary is a
    // real certification-basis claim ("this project has accomplished its
    // planned DO-178C life cycle"). Generating one, unqualified, for a
    // project whose configured standard is NOT do178c (or that has no real
    // DAL classification) misrepresents the document as a genuine
    // accomplishment summary rather than what it actually is: an
    // informational §11-checklist heuristic run against an unrelated
    // project. Detect that mismatch here and label the output accordingly
    // instead of silently presenting it as if it were authoritative.
    let is_do178c_project = standard.eq_ignore_ascii_case("do178c");
    let dal_classified = dal != "unclassified";
    let applicable = is_do178c_project && dal_classified;

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
            "applicable": applicable,
            "notice": if applicable {
                None
            } else {
                Some(format!(
                    "INFORMATIONAL ONLY — not a certification-basis DO-178C §11.20 \
                     accomplishment summary. This project's configured standard is \
                     {standard:?} with DAL/ASIL {dal:?}, not an actively-classified \
                     do178c project. The checklist below is a heuristic §11 \
                     evidence-presence scan only."
                ))
            },
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

        if !applicable {
            md.push_str(
                "> **:warning: INFORMATIONAL ONLY.** This is **not** a certification-basis \
                 DO-178C §11.20 accomplishment summary. This project's configured standard \
                 is `",
            );
            md.push_str(standard);
            md.push_str("` with DAL/ASIL `");
            md.push_str(dal);
            md.push_str(
                "` — not an actively-classified `do178c` project with a real DAL. \
                 The checklist below is a heuristic §11 evidence-presence scan only and \
                 carries no certification weight until the project is genuinely \
                 classified under DO-178C.\n\n",
            );
        }

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

    // rust-FuSa-08: a project configured for a standard other than do178c
    // (e.g. this repo's own iso26262 .fusa.json) must NOT have its sas.md
    // presented as a real DO-178C §11.20 accomplishment summary.
    //fusa:test REQ-SAS005
    #[test]
    fn sas_marks_non_do178c_project_informational_only() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa.json"),
            "{\"configVersion\":\"1.0\",\"project\":{\"name\":\"t\"},\"standard\":\"iso26262\"}\n",
        )
        .unwrap();
        let out_file = dir.path().join("sas.json");
        let a: Vec<String> = vec![
            "--dir".to_string(),
            dir.path().to_string_lossy().into_owned(),
            "--format".to_string(),
            "json".to_string(),
            "--output".to_string(),
            out_file.to_string_lossy().into_owned(),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_file).unwrap()).unwrap();
        assert_eq!(
            v["applicable"].as_bool(),
            Some(false),
            "an iso26262 project must not be marked as an applicable DO-178C SAS"
        );
        assert!(
            v["notice"]
                .as_str()
                .is_some_and(|n| n.contains("INFORMATIONAL ONLY")),
            "notice must flag the report as informational-only"
        );

        // Also check the default markdown format carries the same banner.
        let md_args: Vec<String> = vec![
            "--dir".to_string(),
            dir.path().to_string_lossy().into_owned(),
        ];
        let mut md_out = Vec::new();
        let mut md_err = Vec::new();
        assert_eq!(run(&md_args, &mut md_out, &mut md_err), 0);
        let md = std::fs::read_to_string(dir.path().join(SAS_MD)).unwrap();
        assert!(
            md.contains("INFORMATIONAL ONLY"),
            "sas.md must carry the informational-only banner for a non-do178c project"
        );
    }

    // rust-FuSa-08: a project genuinely configured for do178c with a real
    // (non-"unclassified") DAL must be treated as an applicable, real SAS.
    //fusa:test REQ-SAS005
    #[test]
    fn sas_marks_do178c_project_with_dal_as_applicable() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".fusa.json"),
            "{\"configVersion\":\"1.0\",\"project\":{\"name\":\"t\"},\"standard\":\"do178c\",\"dal\":\"C\"}\n",
        )
        .unwrap();
        let out_file = dir.path().join("sas.json");
        let a: Vec<String> = vec![
            "--dir".to_string(),
            dir.path().to_string_lossy().into_owned(),
            "--format".to_string(),
            "json".to_string(),
            "--output".to_string(),
            out_file.to_string_lossy().into_owned(),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&a, &mut out, &mut err);
        assert_eq!(code, 0);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_file).unwrap()).unwrap();
        assert_eq!(
            v["applicable"].as_bool(),
            Some(true),
            "a do178c project with a classified DAL must be applicable"
        );
        assert!(v["notice"].is_null());
    }
}
