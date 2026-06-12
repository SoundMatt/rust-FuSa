// Evidence bundle: single ZIP with manifest.json (§8).
//fusa:req REQ-AUDIT001
//fusa:req REQ-AUDIT002
//fusa:req REQ-AUDIT003
//fusa:req REQ-AUDIT004

use crate::types::{LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;

pub const AUDIT_PACK_FILE: &str = "audit-pack.zip";

// Input files (§1.2) that go into the pack.
pub const INPUT_FILES: &[&str] = &[
    ".fusa.json",
    ".fusa-reqs.json",
    ".fusa-hara.json",
    ".fusa-evidence.json",
    ".fusa-dispositions.json",
    ".fusa-problems.json",
];

// Generated evidence files (§1.3) included when present.
pub const EVIDENCE_FILES: &[&str] = &[
    "sbom.json",
    "provenance.json",
    "artifact-manifest.json",
    "safety-case.json",
    "safety-case.md",
    "safety-case.mermaid",
    "tara.json",
    "tara.md",
    "fmea.json",
    "fmea.csv",
    "comp-report.json",
    "coupling-report.json",
    "cyber-report.json",
    "vuln.json",
    "qualify-report.json",
    "boundary.dot",
    "boundary.mermaid",
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditManifest {
    pub schema_version: String,
    pub kind: String,
    pub tool: String,
    pub tool_version: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub module: String,
    pub files: Vec<ManifestEntry>,
}

pub fn pack(project_root: &Path, out_path: &Path) -> Result<AuditManifest, String> {
    let module = detect_module(project_root);

    let out_file = std::fs::File::create(out_path)
        .map_err(|e| format!("create {}: {e}", out_path.display()))?;
    let mut zip = zip::ZipWriter::new(out_file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut entries: Vec<ManifestEntry> = Vec::new();

    let candidates: Vec<&str> = INPUT_FILES
        .iter()
        .chain(EVIDENCE_FILES.iter())
        .copied()
        .collect();

    for name in &candidates {
        // §8: audit-pack.zip must not contain itself.
        if *name == AUDIT_PACK_FILE {
            continue;
        }
        let path = project_root.join(name);
        if !path.exists() {
            continue;
        }
        let data = std::fs::read(&path).map_err(|e| format!("read {name}: {e}"))?;
        let mut h = Sha256::new();
        h.update(&data);
        let sha = hex::encode(h.finalize());
        let size = data.len() as u64;

        zip.start_file(*name, opts)
            .map_err(|e| format!("zip start_file {name}: {e}"))?;
        zip.write_all(&data)
            .map_err(|e| format!("zip write {name}: {e}"))?;

        entries.push(ManifestEntry {
            path: name.to_string(),
            size,
            sha256: sha,
        });
    }

    // Write manifest.json (lowercase, §8).
    let manifest = AuditManifest {
        schema_version: SPEC_VERSION.to_string(),
        kind: "audit-manifest".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        generated_at: chrono::Utc::now(),
        module: module.clone(),
        files: entries,
    };
    let manifest_json = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
    zip.start_file("manifest.json", opts)
        .map_err(|e| format!("zip manifest.json: {e}"))?;
    zip.write_all(manifest_json.as_bytes())
        .map_err(|e| format!("zip write manifest.json: {e}"))?;

    zip.finish().map_err(|e| format!("zip finish: {e}"))?;
    Ok(manifest)
}

fn detect_module(root: &Path) -> String {
    let cargo_path = root.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo_path) {
        if let Ok(val) = content.parse::<toml::Value>() {
            if let Some(pkg) = val.get("package") {
                if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
                    return name.to_string();
                }
            }
        }
    }
    root.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}
