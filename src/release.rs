// SBOM, provenance, and artifact manifest generation (§7).
//fusa:req REQ-RELEASE001
//fusa:req REQ-RELEASE002
//fusa:req REQ-RELEASE003
//fusa:req REQ-RELEASE004
//fusa:req REQ-RELEASE005
//fusa:req REQ-RELEASE006
//fusa:req REQ-RELEASE007
//fusa:req REQ-RELEASE008

use crate::types::{LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const SBOM_FILE: &str = "sbom.json";
pub const PROVENANCE_FILE: &str = "provenance.json";
pub const MANIFEST_FILE: &str = "artifact-manifest.json";

// ── SBOM ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sbom {
    pub schema_version: String,
    pub kind: String,
    pub tool: String,
    pub tool_version: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub format: String,
    pub module: String,
    pub components: Vec<Component>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub hash: String,
}

pub fn build_sbom(project_root: &Path) -> Result<Sbom, String> {
    let module = detect_module(project_root);
    let components = scan_cargo_deps(project_root)?;

    Ok(Sbom {
        schema_version: SPEC_VERSION.to_string(),
        kind: "sbom".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        generated_at: chrono::Utc::now(),
        format: "x-FuSa SBOM v1".to_string(),
        module,
        components,
    })
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

fn scan_cargo_deps(root: &Path) -> Result<Vec<Component>, String> {
    let lock_path = root.join("Cargo.lock");
    if !lock_path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("read Cargo.lock: {e}"))?;
    let val: toml::Value =
        content.parse().map_err(|e| format!("parse Cargo.lock: {e}"))?;

    let mut components = Vec::new();
    if let Some(packages) = val.get("package").and_then(|v| v.as_array()) {
        for pkg in packages {
            let name = pkg
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string();
            // Use checksum from Cargo.lock when available, else hash the name+version.
            let hash = if let Some(cksum) = pkg.get("checksum").and_then(|v| v.as_str()) {
                format!("sha256:{cksum}")
            } else {
                let mut h = Sha256::new();
                h.update(format!("{name}@{version}").as_bytes());
                format!("sha256:{}", hex::encode(h.finalize()))
            };
            if !name.is_empty() {
                components.push(Component { name, version, hash });
            }
        }
    }
    Ok(components)
}

// ── Provenance ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub schema_version: String,
    pub kind: String,
    pub tool: String,
    pub tool_version: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub format: String,
    pub module: String,
    pub builder: String,
    pub vcs_revision: String,
    pub vcs_modified: bool,
    pub os: String,
    pub arch: String,
}

pub fn build_provenance(project_root: &Path) -> Provenance {
    let module = detect_module(project_root);
    let (vcs_revision, vcs_modified) = git_info(project_root);
    Provenance {
        schema_version: SPEC_VERSION.to_string(),
        kind: "provenance".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        generated_at: chrono::Utc::now(),
        format: "x-FuSa provenance v1".to_string(),
        module,
        builder: detect_builder(),
        vcs_revision,
        vcs_modified,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

fn detect_builder() -> String {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        return "github-actions".to_string();
    }
    if std::env::var("GITLAB_CI").is_ok() {
        return "gitlab-ci".to_string();
    }
    if std::env::var("CI").is_ok() {
        return "ci".to_string();
    }
    "local".to_string()
}

fn git_info(root: &Path) -> (String, bool) {
    let rev = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let modified = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    (rev, modified)
}

// ── Artifact manifest ──────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactManifest {
    pub schema_version: String,
    pub kind: String,
    pub tool: String,
    pub tool_version: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub format: String,
    pub artifacts: Vec<ArtifactEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub path: String,
    pub sha256: String,
}

pub fn build_manifest(paths: &[&Path], base_dir: &Path) -> Result<ArtifactManifest, String> {
    let mut artifacts = Vec::new();
    for &p in paths {
        if !p.exists() {
            continue;
        }
        let data = std::fs::read(p).map_err(|e| format!("read {}: {e}", p.display()))?;
        let mut h = Sha256::new();
        h.update(&data);
        let sha = hex::encode(h.finalize());
        let rel = p
            .strip_prefix(base_dir)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/");
        artifacts.push(ArtifactEntry { path: rel, sha256: sha });
    }
    Ok(ArtifactManifest {
        schema_version: SPEC_VERSION.to_string(),
        kind: "artifact-manifest".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        generated_at: chrono::Utc::now(),
        format: "x-FuSa manifest v1".to_string(),
        artifacts,
    })
}

pub fn save_json<T: serde::Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(value).expect("serialize json");
    std::fs::write(path, json + "\n")
}
