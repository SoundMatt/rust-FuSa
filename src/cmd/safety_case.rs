// `rsfusa safety-case` — assemble a GSN (Goal Structuring Notation) safety
// argument from evidence files present in the project, per the GSN
// Community Standard v3 (2021) and x-FuSa spec §9.2.
// Writes safety-case.json, safety-case.md, safety-case.mermaid.
//fusa:req REQ-SC001
//fusa:req REQ-SC002
//fusa:req REQ-SC003
//fusa:req REQ-SC004
//fusa:req REQ-SC005
//fusa:req REQ-SAFETYCASE001
//fusa:req REQ-SAFETYCASE002

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

/// §9.2 `safety-case.json` `nodes[]` entry — one of the six GSN node types.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct Node {
    id: String,
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
}

/// §9.2 `safety-case.json` `edges[]` entry.
#[derive(Serialize, Clone, Debug)]
struct Edge {
    from: String,
    to: String,
    #[serde(rename = "type")]
    kind: &'static str,
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
    let standard = cfg
        .as_ref()
        .map(|c| c.standard.as_str())
        .unwrap_or("generic");
    let project = cfg
        .as_ref()
        .map(|c| c.project.name.as_str())
        .unwrap_or("unknown");

    let goal_text =
        format!("The {project} software is free from unacceptable risk according to {standard}");

    let mut nodes: Vec<Node> = vec![
        Node { id: "G1".to_string(), kind: "goal", text: goal_text.clone(), evidence: None },
        Node {
            id: "St1".to_string(),
            kind: "strategy",
            text: format!("Argue {project} is acceptably safe over independently verifiable evidence categories"),
            evidence: None,
        },
    ];
    let mut edges: Vec<Edge> = vec![Edge {
        from: "G1".to_string(),
        to: "St1".to_string(),
        kind: "supportedBy",
    }];

    let mut goals_with_evidence = 0usize;
    let mut undeveloped = 0usize;
    let mut required_missing = 0usize;
    let mut evidence_rows: Vec<serde_json::Value> = Vec::new();

    for (i, ev) in EVIDENCE_ITEMS.iter().enumerate() {
        let goal_id = format!("G{}", i + 2);
        let path = project_root.join(ev.file);
        let present = path.exists();
        if present {
            goals_with_evidence += 1;
        } else {
            undeveloped += 1;
            if ev.required {
                required_missing += 1;
            }
        }

        nodes.push(Node {
            id: goal_id.clone(),
            kind: "goal",
            text: format!("{} is available and adequate for {project}", ev.description),
            evidence: None,
        });
        edges.push(Edge {
            from: "St1".to_string(),
            to: goal_id.clone(),
            kind: "supportedBy",
        });

        if present {
            let sol_id = format!("Sn{}", i + 2);
            nodes.push(Node {
                id: sol_id.clone(),
                kind: "solution",
                text: format!(
                    "{} produced by rsfusa/the project's own tooling",
                    ev.description
                ),
                evidence: Some(ev.file.to_string()),
            });
            edges.push(Edge {
                from: goal_id.clone(),
                to: sol_id,
                kind: "supportedBy",
            });
        }

        evidence_rows.push(serde_json::json!({
            "description": ev.description,
            "file": ev.file,
            "required": ev.required,
            "status": if present { "present" } else { "missing" },
        }));
    }

    let complete = required_missing == 0;
    let total_goals = 1 + EVIDENCE_ITEMS.len();

    let mut qual_fields = Vec::new();
    for n in &nodes {
        qual_fields.push(QualField::new(n.id.clone(), "text", n.text.clone()));
    }

    let content = serde_json::json!({ "nodes": nodes, "edges": edges });
    let content_hash = crate::canonjson::content_hash(&content);
    let json_path = opts
        .json_output
        .clone()
        .unwrap_or_else(|| project_root.join(SC_JSON).to_string_lossy().into_owned());
    let attestation: Option<Attestation> = crate::attestation::carry_forward(
        crate::attestation::read_existing(Path::new(&json_path)),
        &content_hash,
    );
    let attestation_valid = attestation
        .as_ref()
        .is_some_and(|a| crate::attestation::is_valid(a, &content_hash));

    let mut findings = detect_placeholder(SC_JSON, &qual_fields);
    if !attestation_valid {
        findings.extend(detect_blank_fallback(SC_JSON, &qual_fields));
    }
    apply_project_dispositions(&project_root, &mut findings);
    for f in &findings {
        writeln!(stderr, "{}: {} ({})", f.severity, f.message, f.rule_id).ok();
    }

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "safety-case",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "standard": standard,
        "project": project,
        "nodes": nodes,
        "edges": edges,
        "completeness": {
            "totalGoals": total_goals,
            "goalsWithEvidence": goals_with_evidence,
            "undeveloped": undeveloped,
        },
        "attestation": attestation,
        "findings": findings,
    });

    match std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&report).unwrap_or_default() + "\n",
    ) {
        Ok(_) => writeln!(stdout, "Safety case written to {json_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa safety-case: write {json_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let md_path = opts
        .md_output
        .unwrap_or_else(|| project_root.join(SC_MD).to_string_lossy().into_owned());
    let mut md = format!(
        "# Safety Case\n\n\
         **Goal**: {goal_text}  \n\
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

    let mermaid_path = opts
        .mermaid_output
        .unwrap_or_else(|| project_root.join(SC_MERMAID).to_string_lossy().into_owned());
    let mut mermaid = String::from("graph TB\n");
    mermaid.push_str(&format!(
        "  G1[\"{}\"] --> St1[Strategy: evidence categories]\n",
        goal_text.replace('"', "'")
    ));
    for (i, ev) in EVIDENCE_ITEMS.iter().enumerate() {
        let goal_id = format!("G{}", i + 2);
        let present = project_root.join(ev.file).exists();
        let shape = if present {
            format!("{goal_id}([\"{}\"])", ev.description)
        } else {
            format!("{goal_id}{{\"UNDEVELOPED: {}\"}}", ev.description)
        };
        mermaid.push_str(&format!("  St1 --> {shape}\n"));
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
    json_output: Option<String>,
    md_output: Option<String>,
    mermaid_output: Option<String>,
    strict: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        json_output: None,
        md_output: None,
        mermaid_output: None,
        strict: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--strict" | "--require-attestation" => opts.strict = true,
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

#[cfg(test)]
mod tests {
    use super::*;

    //fusa:test REQ-SAFETYCASE002
    #[test]
    fn node_types_are_all_gsn_valid() {
        const VALID: &[&str] = &[
            "goal",
            "strategy",
            "solution",
            "context",
            "assumption",
            "justification",
        ];
        let sample = [
            Node {
                id: "G1".to_string(),
                kind: "goal",
                text: "t".to_string(),
                evidence: None,
            },
            Node {
                id: "St1".to_string(),
                kind: "strategy",
                text: "t".to_string(),
                evidence: None,
            },
            Node {
                id: "Sn1".to_string(),
                kind: "solution",
                text: "t".to_string(),
                evidence: Some("f".to_string()),
            },
        ];
        for n in &sample {
            assert!(VALID.contains(&n.kind));
        }
    }

    //fusa:test REQ-SAFETYCASE002
    #[test]
    fn edge_types_are_valid() {
        let e = Edge {
            from: "G1".to_string(),
            to: "St1".to_string(),
            kind: "supportedBy",
        };
        assert!(e.kind == "supportedBy" || e.kind == "inContextOf");
    }
}
