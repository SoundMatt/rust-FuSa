// `rsfusa sci` — Software Configuration Index (DO-178C §11.16).

use crate::config::load;
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;
use std::path::PathBuf;

pub const SCI_FILE: &str = "sci.json";

struct SciItem {
    name: &'static str,
    category: &'static str,
    file: &'static str,
    required: bool,
}

const SCI_ITEMS: &[SciItem] = &[
    SciItem { name: "Safety Plan",                    category: "Planning",       file: ".fusa.json",             required: true },
    SciItem { name: "Software Requirements",          category: "Requirements",   file: ".fusa-reqs.json",        required: true },
    SciItem { name: "Architecture Description",       category: "Design",         file: "boundary.mermaid",       required: false },
    SciItem { name: "Source Code",                    category: "Implementation", file: "src/",                   required: true },
    SciItem { name: "Build Instructions",             category: "Build",          file: "Cargo.toml",             required: true },
    SciItem { name: "Cargo Lock",                     category: "Build",          file: "Cargo.lock",             required: true },
    SciItem { name: "Check Report",                   category: "Verification",   file: "check-report.json",      required: false },
    SciItem { name: "Test Evidence",                  category: "Testing",        file: ".fusa-evidence.json",    required: true },
    SciItem { name: "Trace Matrix",                   category: "Traceability",   file: "trace.json",             required: false },
    SciItem { name: "Qualification Report",           category: "Qualification",  file: "qualify-report.json",    required: true },
    SciItem { name: "SBOM",                           category: "Configuration",  file: "sbom.json",              required: true },
    SciItem { name: "FMEA",                           category: "Safety",         file: "fmea.json",              required: false },
    SciItem { name: "Dispositions",                   category: "Review",         file: ".fusa-dispositions.json",required: false },
    SciItem { name: "Audit Pack",                     category: "Delivery",       file: "audit-pack.zip",         required: false },
];

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    let cfg = load(&project_root.join(".fusa.json")).ok();
    let project = cfg.as_ref().map(|c| c.project.name.as_str()).unwrap_or("unknown");
    let version = cfg.as_ref().map(|c| c.project.version.as_str()).unwrap_or("0.0.0");

    let mut items_json: Vec<serde_json::Value> = Vec::new();
    let mut present_count = 0usize;
    let mut required_missing = 0usize;

    for item in SCI_ITEMS {
        let path = project_root.join(item.file);
        let present = path.exists();
        if present { present_count += 1; }
        if item.required && !present { required_missing += 1; }

        let hash = if present && path.is_file() {
            compute_file_hash(&path).unwrap_or_default()
        } else {
            String::new()
        };

        items_json.push(serde_json::json!({
            "name": item.name,
            "category": item.category,
            "file": item.file,
            "required": item.required,
            "present": present,
            "hash": hash,
        }));
    }

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "sci",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "project": project,
        "projectVersion": version,
        "items": items_json,
        "summary": {
            "total": SCI_ITEMS.len(),
            "present": present_count,
            "missing": SCI_ITEMS.len() - present_count,
            "requiredMissing": required_missing,
        }
    });

    let out_path = opts.output.unwrap_or_else(|| project_root.join(SCI_FILE).to_string_lossy().into_owned());

    if opts.format.as_deref() == Some("md") || opts.format.as_deref() == Some("markdown") {
        let mut md = format!(
            "# Software Configuration Index (SCI)\n\n\
             **DO-178C §11.16**\n\n\
             - **Project**: {project}\n\
             - **Version**: {version}\n\
             - **Generated**: {}\n\n\
             ## Lifecycle Data Items\n\n\
             | Name | Category | File | Required | Status | SHA-256 |\n\
             |------|----------|------|----------|--------|---------|\n",
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
        );
        for item in &items_json {
            let status = if item["present"].as_bool().unwrap_or(false) { ":white_check_mark:" } else { ":x:" };
            let hash = item["hash"].as_str().unwrap_or("");
            let short_hash = if hash.len() > 12 { &hash[..12] } else { hash };
            md.push_str(&format!("| {} | {} | `{}` | {} | {} | `{}` |\n",
                item["name"].as_str().unwrap_or(""),
                item["category"].as_str().unwrap_or(""),
                item["file"].as_str().unwrap_or(""),
                if item["required"].as_bool().unwrap_or(false) { "yes" } else { "no" },
                status,
                short_hash,
            ));
        }
        let md_path = out_path.replace(".json", ".md");
        match std::fs::write(&md_path, md) {
            Ok(_) => writeln!(stdout, "SCI written to {md_path}").ok(),
            Err(e) => {
                writeln!(stderr, "rsfusa sci: write {md_path}: {e}").ok();
                return EXIT_RUNTIME;
            }
        };
    } else {
        match std::fs::write(&out_path, serde_json::to_string_pretty(&report).unwrap() + "\n") {
            Ok(_) => writeln!(stdout, "SCI written to {out_path}").ok(),
            Err(e) => {
                writeln!(stderr, "rsfusa sci: write {out_path}: {e}").ok();
                return EXIT_RUNTIME;
            }
        };
    }

    writeln!(stdout, "Items: {}/{} present, {} required missing",
        present_count, SCI_ITEMS.len(), required_missing).ok();
    EXIT_OK
}

fn compute_file_hash(path: &PathBuf) -> Option<String> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts { dir: None, format: None, output: None };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--format" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa sci: {flag} requires an argument").ok();
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
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--format=") { opts.format = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--output=") { opts.output = Some(v.to_string()); }
                else {
                    writeln!(stderr, "rsfusa sci: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
