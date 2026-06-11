// `rsfusa coupling` — data and control coupling analysis between Rust modules.
// Writes coupling-report.json.

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use walkdir::WalkDir;

pub const COUPLING_FILE: &str = "coupling-report.json";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleInfo {
    name: String,
    file: String,
    imports: Vec<String>,
    import_count: usize,
    exported_items: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CouplingFinding {
    from: String,
    to: String,
    coupling_type: String,
    severity: String,
    note: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CouplingReport {
    schema_version: String,
    kind: String,
    tool: String,
    tool_version: String,
    language: String,
    generated_at: String,
    modules: Vec<ModuleInfo>,
    data_findings: Vec<CouplingFinding>,
    ctrl_findings: Vec<CouplingFinding>,
    summary: serde_json::Value,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    let src_dir = project_root.join("src");
    let scan_root = if src_dir.exists() { src_dir } else { project_root.clone() };

    let mut modules: Vec<ModuleInfo> = Vec::new();
    let mut module_imports: HashMap<String, Vec<String>> = HashMap::new();

    for entry in WalkDir::new(&scan_root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
    {
        let path = entry.path();
        let rel = path.strip_prefix(&project_root).unwrap_or(path)
            .to_string_lossy().replace('\\', "/");
        let module_name = rel.trim_end_matches(".rs")
            .replace('/', "::")
            .replace("src::", "");

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut imports = Vec::new();
        let mut exported_items = 0usize;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("use crate::") {
                let import = trimmed.trim_start_matches("use crate::")
                    .split(|c| c == ';' || c == ':' || c == '{')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !import.is_empty() && !imports.contains(&import) {
                    imports.push(import);
                }
            }
            if trimmed.starts_with("pub fn ") || trimmed.starts_with("pub struct ")
                || trimmed.starts_with("pub enum ") || trimmed.starts_with("pub type ")
                || trimmed.starts_with("pub const ")
            {
                exported_items += 1;
            }
        }

        module_imports.insert(module_name.clone(), imports.clone());
        modules.push(ModuleInfo {
            name: module_name,
            file: rel,
            import_count: imports.len(),
            imports,
            exported_items,
        });
    }

    const HIGH_COUPLING_THRESHOLD: usize = 5;
    let mut data_findings = Vec::new();
    let mut ctrl_findings = Vec::new();

    for m in &modules {
        if m.import_count > HIGH_COUPLING_THRESHOLD {
            data_findings.push(CouplingFinding {
                from: m.name.clone(),
                to: "(multiple)".to_string(),
                coupling_type: "data".to_string(),
                severity: "WARNING".to_string(),
                note: format!("module imports {} other modules (threshold {})", m.import_count, HIGH_COUPLING_THRESHOLD),
            });
        }
        // Circular coupling check: A imports B and B imports A
        for imported in &m.imports {
            if let Some(imported_imports) = module_imports.get(imported) {
                if imported_imports.iter().any(|i| i == &m.name || m.name.ends_with(i)) {
                    ctrl_findings.push(CouplingFinding {
                        from: m.name.clone(),
                        to: imported.clone(),
                        coupling_type: "control".to_string(),
                        severity: "WARNING".to_string(),
                        note: "possible circular dependency between modules".to_string(),
                    });
                }
            }
        }
    }

    let high_coupling_count = data_findings.len() + ctrl_findings.len();

    let report = CouplingReport {
        schema_version: SPEC_VERSION.to_string(),
        kind: "coupling-report".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        summary: serde_json::json!({
            "modules": modules.len(),
            "highCouplingCount": high_coupling_count,
            "dataFindings": data_findings.len(),
            "ctrlFindings": ctrl_findings.len(),
        }),
        modules,
        data_findings,
        ctrl_findings,
    };

    let out_path = opts.output.unwrap_or_else(|| {
        project_root.join(COUPLING_FILE).to_string_lossy().into_owned()
    });

    let json = serde_json::to_string_pretty(&report).expect("serialize coupling");
    match std::fs::write(&out_path, json + "\n") {
        Ok(_) => writeln!(stdout, "Coupling report written to {out_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa coupling: write {out_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    writeln!(stdout, "Modules: {}  High-coupling: {}", report.summary["modules"], report.summary["highCouplingCount"]).ok();
    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts { dir: None, output: None };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa coupling: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--output" => opts.output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--output=") { opts.output = Some(v.to_string()); }
                else {
                    writeln!(stderr, "rsfusa coupling: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
