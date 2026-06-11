// `rsfusa safety-case` — assemble GSN safety case from evidence files.
// Writes safety-case.json, safety-case.md, safety-case.mermaid.
//fusa:req REQ-SC001
//fusa:req REQ-SC002
//fusa:req REQ-SC003
//fusa:req REQ-SC004
//fusa:req REQ-SC005
//fusa:req REQ-SAFETYCASE001

use crate::config::load;
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;
use std::path::PathBuf;

pub const SC_JSON: &str = "safety-case.json";
pub const SC_MD: &str = "safety-case.md";
pub const SC_MERMAID: &str = "safety-case.mermaid";

struct Evidence {
    description: &'static str,
    file: &'static str,
    required: bool,
}

const EVIDENCE_ITEMS: &[Evidence] = &[
    Evidence {
        description: "Safety check report",
        file: "check-report.json",
        required: true,
    },
    Evidence {
        description: "Requirements trace matrix",
        file: "trace.json",
        required: true,
    },
    Evidence {
        description: "Test evidence bundle",
        file: ".fusa-evidence.json",
        required: true,
    },
    Evidence {
        description: "Qualification report",
        file: "qualify-report.json",
        required: true,
    },
    Evidence {
        description: "SBOM",
        file: "sbom.json",
        required: true,
    },
    Evidence {
        description: "FMEA",
        file: "fmea.json",
        required: false,
    },
    Evidence {
        description: "TARA / threat analysis",
        file: "tara.json",
        required: false,
    },
    Evidence {
        description: "Vulnerability scan",
        file: "vuln.json",
        required: false,
    },
    Evidence {
        description: "Coupling analysis",
        file: "coupling-report.json",
        required: false,
    },
    Evidence {
        description: "Cybersecurity analysis",
        file: "cyber-report.json",
        required: false,
    },
    Evidence {
        description: "Requirements file",
        file: ".fusa-reqs.json",
        required: true,
    },
    Evidence {
        description: "Dispositions file",
        file: ".fusa-dispositions.json",
        required: false,
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
    let standard = cfg
        .as_ref()
        .map(|c| c.standard.as_str())
        .unwrap_or("generic");
    let project = cfg
        .as_ref()
        .map(|c| c.project.name.as_str())
        .unwrap_or("unknown");

    let mut evidence_list: Vec<serde_json::Value> = Vec::new();
    let mut present_count = 0usize;
    let mut required_missing = 0usize;

    for ev in EVIDENCE_ITEMS {
        let path = project_root.join(ev.file);
        let present = path.exists();
        if present {
            present_count += 1;
        }
        if ev.required && !present {
            required_missing += 1;
        }
        evidence_list.push(serde_json::json!({
            "description": ev.description,
            "file": ev.file,
            "required": ev.required,
            "status": if present { "present" } else { "missing" },
        }));
    }

    let goal =
        format!("The {project} software is free from unacceptable risk according to {standard}");
    let complete = required_missing == 0;

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "safety-case",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "standard": standard,
        "project": project,
        "goal": goal,
        "complete": complete,
        "evidence": evidence_list,
        "summary": {
            "total": EVIDENCE_ITEMS.len(),
            "present": present_count,
            "missing": EVIDENCE_ITEMS.len() - present_count,
            "requiredMissing": required_missing,
        }
    });

    let json_path = opts
        .json_output
        .unwrap_or_else(|| project_root.join(SC_JSON).to_string_lossy().into_owned());
    let md_path = opts
        .md_output
        .unwrap_or_else(|| project_root.join(SC_MD).to_string_lossy().into_owned());
    let mermaid_path = opts
        .mermaid_output
        .unwrap_or_else(|| project_root.join(SC_MERMAID).to_string_lossy().into_owned());

    match std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&report).unwrap() + "\n",
    ) {
        Ok(_) => writeln!(stdout, "Safety case written to {json_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa safety-case: write {json_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    // Markdown
    let mut md = format!(
        "# Safety Case\n\n\
         **Goal**: {goal}  \n\
         **Standard**: {standard}  \n\
         **Project**: {project}  \n\
         **Generated**: {}  \n\
         **Status**: {}  \n\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        if complete { "COMPLETE" } else { "INCOMPLETE" }
    );
    md.push_str("## Evidence\n\n");
    md.push_str("| Description | File | Required | Status |\n");
    md.push_str("|-------------|------|----------|--------|\n");
    for ev in EVIDENCE_ITEMS {
        let path = project_root.join(ev.file);
        let status = if path.exists() {
            ":white_check_mark: present"
        } else {
            ":x: missing"
        };
        md.push_str(&format!(
            "| {} | `{}` | {} | {} |\n",
            ev.description,
            ev.file,
            if ev.required { "yes" } else { "no" },
            status
        ));
    }
    if !complete {
        md.push_str(&format!(
            "\n> :warning: **{required_missing} required evidence items are missing.**\n"
        ));
    }

    match std::fs::write(&md_path, md) {
        Ok(_) => writeln!(stdout, "Safety case markdown written to {md_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa safety-case: write {md_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    // Mermaid GSN diagram
    let mut mermaid = String::from("graph TB\n");
    mermaid.push_str(&format!(
        "  G1[\"Goal: {}\"] --> S1[Strategy: Evidence-based assurance]\n",
        goal.replace('"', "'")
    ));
    for (i, ev) in EVIDENCE_ITEMS.iter().enumerate() {
        let path = project_root.join(ev.file);
        let shape = if path.exists() {
            format!("E{}([\"{}\"])", i, ev.description)
        } else {
            format!("E{}{{\"MISSING: {}\"}}", i, ev.description)
        };
        mermaid.push_str(&format!("  S1 --> {shape}\n"));
    }

    match std::fs::write(&mermaid_path, mermaid) {
        Ok(_) => writeln!(stdout, "Safety case mermaid written to {mermaid_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa safety-case: write {mermaid_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    if !complete {
        writeln!(
            stdout,
            "WARNING: {required_missing} required evidence item(s) missing"
        )
        .ok();
    }
    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    json_output: Option<String>,
    md_output: Option<String>,
    mermaid_output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        json_output: None,
        md_output: None,
        mermaid_output: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--output" | "--md" | "--mermaid") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa safety-case: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--output" => opts.json_output = Some(args[i].clone()),
                    "--md" => opts.md_output = Some(args[i].clone()),
                    "--mermaid" => opts.mermaid_output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.json_output = Some(v.to_string());
                } else {
                    writeln!(stderr, "rsfusa safety-case: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
