// `rsfusa sas` — Software Accomplishment Summary (DO-178C §11.20).
//fusa:req REQ-SC002
//fusa:req REQ-SAS001
//fusa:req REQ-SAS002
//fusa:req REQ-SAS003

use crate::config::load;
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;
use std::path::PathBuf;

pub const SAS_FILE: &str = "sas.md";

struct EvidenceItem {
    category: &'static str,
    description: &'static str,
    file: &'static str,
}

const EVIDENCE: &[EvidenceItem] = &[
    EvidenceItem {
        category: "Planning",
        description: "Safety configuration",
        file: ".fusa.json",
    },
    EvidenceItem {
        category: "Requirements",
        description: "Requirements specification",
        file: ".fusa-reqs.json",
    },
    EvidenceItem {
        category: "Design",
        description: "Architecture/boundary diagram",
        file: "boundary.mermaid",
    },
    EvidenceItem {
        category: "Implementation",
        description: "Safety check report",
        file: "check-report.json",
    },
    EvidenceItem {
        category: "Verification",
        description: "Test evidence",
        file: ".fusa-evidence.json",
    },
    EvidenceItem {
        category: "Coverage",
        description: "Structural coverage report",
        file: "coverage-report.json",
    },
    EvidenceItem {
        category: "Traceability",
        description: "Requirements trace matrix",
        file: "trace.json",
    },
    EvidenceItem {
        category: "QM",
        description: "Tool qualification report",
        file: "qualify-report.json",
    },
    EvidenceItem {
        category: "Configuration",
        description: "SBOM",
        file: "sbom.json",
    },
    EvidenceItem {
        category: "Configuration",
        description: "SCI",
        file: "sci.json",
    },
    EvidenceItem {
        category: "Safety",
        description: "FMEA",
        file: "fmea.json",
    },
    EvidenceItem {
        category: "Security",
        description: "TARA",
        file: "tara.json",
    },
    EvidenceItem {
        category: "Security",
        description: "Vulnerability scan",
        file: "vuln.json",
    },
    EvidenceItem {
        category: "Delivery",
        description: "Audit pack",
        file: "audit-pack.zip",
    },
];

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

    let mut present_count = 0usize;
    let mut rows = Vec::new();
    for ev in EVIDENCE {
        let present = project_root.join(ev.file).exists();
        if present {
            present_count += 1;
        }
        rows.push((ev.category, ev.description, ev.file, present));
    }

    let now = chrono::Utc::now();

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

    md.push_str("## Software Life Cycle Data\n\n");
    md.push_str("| Category | Description | Evidence File | Status |\n");
    md.push_str("|----------|-------------|---------------|--------|\n");
    for (cat, desc, file, present) in &rows {
        let status = if *present {
            ":white_check_mark: Present"
        } else {
            ":x: Missing"
        };
        md.push_str(&format!("| {cat} | {desc} | `{file}` | {status} |\n"));
    }

    md.push_str(&format!(
        "\n## Conformance Statement\n\n\
         {present_count} of {} evidence items are present.\n\n\
         This SAS was generated automatically by {TOOL_NAME} {VERSION}. \
         A qualified safety engineer must review and sign this document before submission.\n",
        EVIDENCE.len()
    ));

    let out_path = opts
        .output
        .clone()
        .unwrap_or_else(|| project_root.join(SAS_FILE).to_string_lossy().into_owned());

    if opts.format.as_deref() == Some("json") {
        let rows_json: Vec<serde_json::Value> = rows.iter().map(|(cat, desc, file, present)| {
            serde_json::json!({ "category": cat, "description": desc, "file": file, "status": if *present { "present" } else { "missing" } })
        }).collect();
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
            "evidence": rows_json,
            "summary": { "total": EVIDENCE.len(), "present": present_count },
        });
        let path_str = opts.output.as_deref().unwrap_or("sas.json");
        if let Err(e) = std::fs::write(
            path_str,
            serde_json::to_string_pretty(&report).unwrap() + "\n",
        ) {
            writeln!(stderr, "rsfusa sas: write {path_str}: {e}").ok();
            return EXIT_RUNTIME;
        }
        writeln!(stdout, "SAS written to {path_str}").ok();
    } else {
        if let Err(e) = std::fs::write(&out_path, &md) {
            writeln!(stderr, "rsfusa sas: write {out_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
        writeln!(stdout, "SAS written to {out_path}").ok();
        writeln!(
            stdout,
            "Evidence: {present_count}/{} present",
            EVIDENCE.len()
        )
        .ok();
    }

    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        format: None,
        output: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--format" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa sas: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--format" => opts.format = Some(args[i].clone()),
                    "--output" => opts.output = Some(args[i].clone()),
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
