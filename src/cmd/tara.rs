// `rsfusa tara` — Threat Analysis and Risk Assessment per ISO 21434 Ch. 9.
// Maps CYBER findings to STRIDE and writes tara.json + tara.md.

use crate::config::load;
use crate::cyber;
use crate::engine::Registry;
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;
use std::path::PathBuf;

pub const TARA_JSON: &str = "tara.json";
pub const TARA_MD: &str = "tara.md";

struct TaraEntry {
    threat: String,
    category: String,
    stride: &'static str,
    cwe: &'static str,
    risk_rating: &'static str,
    mitigation: String,
    source_rule: String,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    let cfg = match load(&project_root.join(".fusa.json")) {
        Ok(c) => c,
        Err(crate::config::ConfigError::NotFound(_)) => crate::config::FusaConfig::new(
            project_root.file_name().and_then(|n| n.to_str()).unwrap_or("project"),
            "generic",
        ),
        Err(e) => {
            writeln!(stderr, "rsfusa tara: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let mut reg = Registry::new();
    cyber::register_all(&mut reg);
    let result = reg.run(&project_root, &cfg);

    let mut entries: Vec<TaraEntry> = Vec::new();

    // Map CYBER findings to STRIDE categories
    for finding in &result.findings {
        let (stride, cwe, risk) = rule_to_stride(&finding.rule_id);
        entries.push(TaraEntry {
            threat: finding.message.clone(),
            category: finding.category.to_string(),
            stride,
            cwe,
            risk_rating: risk,
            mitigation: finding.remediation.clone(),
            source_rule: finding.rule_id.clone(),
        });
    }

    // Add standard TARA baseline entries if no findings
    if entries.is_empty() {
        add_baseline_entries(&mut entries);
    }

    let json_path = opts.json_output.unwrap_or_else(|| {
        project_root.join(TARA_JSON).to_string_lossy().into_owned()
    });
    let md_path = opts.md_output.unwrap_or_else(|| {
        project_root.join(TARA_MD).to_string_lossy().into_owned()
    });

    let entries_json: Vec<serde_json::Value> = entries.iter().map(|e| serde_json::json!({
        "threat": e.threat,
        "category": e.category,
        "stride": e.stride,
        "cwe": e.cwe,
        "riskRating": e.risk_rating,
        "mitigation": e.mitigation,
        "sourceRule": e.source_rule,
    })).collect();

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "tara",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "standard": "iso21434",
        "entries": entries_json,
        "summary": {
            "total": entries.len(),
            "high": entries.iter().filter(|e| e.risk_rating == "HIGH").count(),
            "medium": entries.iter().filter(|e| e.risk_rating == "MEDIUM").count(),
            "low": entries.iter().filter(|e| e.risk_rating == "LOW").count(),
        }
    });

    match std::fs::write(&json_path, serde_json::to_string_pretty(&report).unwrap() + "\n") {
        Ok(_) => writeln!(stdout, "TARA written to {json_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa tara: write {json_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    // Write markdown
    let mut md = format!(
        "# Threat Analysis and Risk Assessment (TARA)\n\n\
         **Standard**: ISO 21434  \n\
         **Generated**: {}  \n\
         **Tool**: {} {}  \n\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        TOOL_NAME, VERSION
    );
    md.push_str("## Threat Register\n\n");
    md.push_str("| Threat | STRIDE | CWE | Risk | Mitigation | Rule |\n");
    md.push_str("|--------|--------|-----|------|------------|------|\n");
    for e in &entries {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            md_escape(&e.threat), e.stride, e.cwe, e.risk_rating,
            md_escape(&e.mitigation), e.source_rule
        ));
    }
    md.push_str(&format!("\n## Summary\n\n- Total: {}\n- HIGH: {}\n- MEDIUM: {}\n- LOW: {}\n",
        entries.len(),
        entries.iter().filter(|e| e.risk_rating == "HIGH").count(),
        entries.iter().filter(|e| e.risk_rating == "MEDIUM").count(),
        entries.iter().filter(|e| e.risk_rating == "LOW").count(),
    ));

    match std::fs::write(&md_path, md) {
        Ok(_) => writeln!(stdout, "TARA markdown written to {md_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa tara: write {md_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    EXIT_OK
}

fn rule_to_stride(rule_id: &str) -> (&'static str, &'static str, &'static str) {
    match rule_id {
        "CYBER001" => ("T", "CWE-798", "HIGH"),
        "CYBER002" => ("T", "CWE-89", "HIGH"),
        "CYBER003" => ("T", "CWE-22", "HIGH"),
        "CYBER004" => ("T", "CWE-330", "MEDIUM"),
        "CYBER005" => ("T", "CWE-190", "MEDIUM"),
        "CYBER006" => ("I", "CWE-319", "HIGH"),
        "CYBER007" => ("E", "CWE-78", "HIGH"),
        "CYBER008" => ("T", "CWE-327", "HIGH"),
        "CYBER009" => ("I", "CWE-532", "MEDIUM"),
        "CYBER010" => ("T", "CWE-502", "MEDIUM"),
        "CYBER011" => ("T", "CWE-125", "MEDIUM"),
        "CYBER012" => ("D", "CWE-400", "MEDIUM"),
        "CYBER013" => ("T", "CWE-295", "HIGH"),
        "CYBER014" => ("T", "CWE-367", "MEDIUM"),
        "CYBER015" => ("T", "CWE-732", "MEDIUM"),
        "CYBER016" => ("I", "CWE-526", "LOW"),
        "CYBER017" => ("T", "CWE-22", "MEDIUM"),
        "CYBER018" => ("T", "CWE-415", "HIGH"),
        "CYBER019" => ("T", "CWE-134", "MEDIUM"),
        "CYBER020" => ("T", "CWE-20", "HIGH"),
        _ => ("T", "CWE-0", "LOW"),
    }
}

fn add_baseline_entries(entries: &mut Vec<TaraEntry>) {
    entries.push(TaraEntry {
        threat: "Spoofing of configuration file".to_string(),
        category: "security".to_string(),
        stride: "S",
        cwe: "CWE-345",
        risk_rating: "MEDIUM",
        mitigation: "Verify .fusa.json integrity via rsfusa sign before loading".to_string(),
        source_rule: "BASELINE".to_string(),
    });
    entries.push(TaraEntry {
        threat: "Tampering with audit evidence".to_string(),
        category: "security".to_string(),
        stride: "T",
        cwe: "CWE-345",
        risk_rating: "HIGH",
        mitigation: "Use rsfusa sign on all evidence files and verify hashes in audit-pack".to_string(),
        source_rule: "BASELINE".to_string(),
    });
    entries.push(TaraEntry {
        threat: "Information disclosure via error messages".to_string(),
        category: "security".to_string(),
        stride: "I",
        cwe: "CWE-209",
        risk_rating: "LOW",
        mitigation: "Ensure error messages do not expose internal paths or credentials".to_string(),
        source_rule: "BASELINE".to_string(),
    });
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

struct Opts {
    dir: Option<PathBuf>,
    json_output: Option<String>,
    md_output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts { dir: None, json_output: None, md_output: None };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--output" | "--md") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa tara: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--output" => opts.json_output = Some(args[i].clone()),
                    "--md" => opts.md_output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--output=") { opts.json_output = Some(v.to_string()); }
                else {
                    writeln!(stderr, "rsfusa tara: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
