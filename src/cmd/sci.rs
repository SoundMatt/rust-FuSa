// `rsfusa sci` — Software Configuration Index per DO-178C §11.16,
// x-FuSa spec §9.3. Indexes the project's actual controlled files with a
// real SHA-256 hash each — a placeholder or stale hash defeats the point of
// a configuration index.
//fusa:req REQ-CFG001
//fusa:req REQ-SCI001
//fusa:req REQ-SCI002
//fusa:req REQ-SCI003
//fusa:req REQ-SCI004

use crate::config::load;
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;

pub const SCI_FILE: &str = "sci.json";

/// Generated evidence artefacts (x-FuSa spec §1.3) plus the project's own
/// configuration/requirements files — indexed only when they actually
/// exist in the project.
const CANDIDATE_FILES: &[&str] = &[
    ".fusa.json",
    ".fusa-reqs.json",
    ".fusa-hara.json",
    ".fusa-dispositions.json",
    ".fusa-evidence.json",
    ".fusa-problems.json",
    "Cargo.toml",
    "Cargo.lock",
    "check-report.json",
    "trace.json",
    "qualify-report.json",
    "sbom.json",
    "provenance.json",
    "artifact-manifest.json",
    "fmea.json",
    "tara.json",
    "safety-case.json",
    "sas.json",
    "sas.md",
    "sci.json",
    "comp-report.json",
    "cyber-report.json",
    "boundary.dot",
    "boundary.mermaid",
    "results.sarif",
    "audit-pack.zip",
];

/// §9.3 `sci.json` `artifacts[]` entry.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct Artifact {
    file: String,
    hash: String,
    version: String,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let cfg = load(&project_root.join(".fusa.json")).unwrap_or_else(|_| {
        crate::config::FusaConfig::new(
            project_root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("project"),
            "generic",
        )
    });
    let project = cfg.project.name.clone();
    let version = cfg.project.version.clone();

    let mut files: Vec<PathBuf> = Vec::new();
    for name in CANDIDATE_FILES {
        let p = project_root.join(name);
        if p.is_file() {
            files.push(p);
        }
    }
    files.extend(crate::cyber::rust_sources(&project_root, &cfg));
    files.sort();
    files.dedup();

    let mut artifacts: Vec<Artifact> = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&project_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let Some(hash) = compute_file_hash(path) else {
            continue;
        };
        artifacts.push(Artifact {
            file: rel,
            hash,
            version: version.clone(),
        });
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
        "artifacts": artifacts,
    });

    let out_path = opts
        .output
        .unwrap_or_else(|| project_root.join(SCI_FILE).to_string_lossy().into_owned());

    if opts.format.as_deref() == Some("md") || opts.format.as_deref() == Some("markdown") {
        let mut md = format!(
            "# Software Configuration Index (SCI)\n\n\
             **DO-178C §11.16**\n\n\
             - **Project**: {project}\n\
             - **Version**: {version}\n\
             - **Generated**: {}\n\n\
             ## Configuration Items\n\n\
             | File | Version | SHA-256 |\n\
             |------|---------|---------|\n",
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
        );
        for a in &artifacts {
            let short_hash = a.hash.strip_prefix("sha256:").unwrap_or(&a.hash);
            let short_hash = &short_hash[..short_hash.len().min(12)];
            md.push_str(&format!(
                "| `{}` | {} | `{short_hash}` |\n",
                a.file, a.version
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
        match std::fs::write(
            &out_path,
            serde_json::to_string_pretty(&report).unwrap_or_default() + "\n",
        ) {
            Ok(_) => writeln!(stdout, "SCI written to {out_path}").ok(),
            Err(e) => {
                writeln!(stderr, "rsfusa sci: write {out_path}: {e}").ok();
                return EXIT_RUNTIME;
            }
        };
    }

    writeln!(stdout, "Configuration items indexed: {}", artifacts.len()).ok();
    EXIT_OK
}

fn compute_file_hash(path: &std::path::Path) -> Option<String> {
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
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--format=") {
                    opts.format = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.output = Some(v.to_string());
                } else {
                    writeln!(stderr, "rsfusa sci: unknown flag: {other}").ok();
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

    //fusa:test REQ-SCI004
    #[test]
    fn hash_is_sha256_prefixed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.txt");
        std::fs::write(&path, b"hello").unwrap();
        let hash = compute_file_hash(&path).unwrap();
        assert!(hash.starts_with("sha256:"));
    }

    //fusa:test REQ-SCI004
    #[test]
    fn hash_is_deterministic_for_same_content() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, b"same content").unwrap();
        std::fs::write(&b, b"same content").unwrap();
        assert_eq!(compute_file_hash(&a), compute_file_hash(&b));
    }
}
