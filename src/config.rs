// Project configuration: .fusa.json (§1.2.1) and .fusa-reqs.json (§1.2.2).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub const CONFIG_FILE: &str = ".fusa.json";
pub const REQS_FILE: &str = ".fusa-reqs.json";
pub const CONFIG_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FusaConfig {
    pub config_version: String,
    pub project: ProjectConfig,
    pub standard: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asil: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sil: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dal: Option<String>,
    #[serde(default = "default_source_dirs")]
    pub source_dirs: Vec<String>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default)]
    pub strict: bool,
}

fn default_source_dirs() -> Vec<String> {
    vec![".".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

impl FusaConfig {
    pub fn new(name: impl Into<String>, standard: impl Into<String>) -> Self {
        Self {
            config_version: CONFIG_VERSION.to_string(),
            project: ProjectConfig {
                name: name.into(),
                version: "0.1.0".to_string(),
            },
            standard: standard.into(),
            asil: None,
            sil: None,
            dal: None,
            source_dirs: default_source_dirs(),
            exclude_patterns: vec!["target/**".to_string()],
            strict: false,
        }
    }

    pub fn integrity_level(&self) -> Option<(&str, &str)> {
        if let Some(v) = &self.asil {
            return Some(("asil", v.as_str()));
        }
        if let Some(v) = &self.sil {
            return Some(("sil", v.as_str()));
        }
        if let Some(v) = &self.dal {
            return Some(("dal", v.as_str()));
        }
        None
    }
}

/// Raw deserialisation shape that supports legacy flat "project" string.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConfig {
    #[serde(default = "default_config_version")]
    config_version: String,
    project: serde_json::Value,
    standard: String,
    #[serde(default)]
    asil: Option<String>,
    #[serde(default)]
    sil: Option<String>,
    #[serde(default)]
    dal: Option<String>,
    #[serde(default = "default_source_dirs")]
    source_dirs: Vec<String>,
    #[serde(default)]
    exclude_patterns: Vec<String>,
    #[serde(default)]
    strict: bool,
}

fn default_config_version() -> String {
    "1.0".to_string()
}

pub fn load(path: &Path) -> Result<FusaConfig, ConfigError> {
    let data = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ConfigError::NotFound(path.to_path_buf())
        } else {
            ConfigError::Io(e)
        }
    })?;

    let raw: RawConfig =
        serde_json::from_str(&data).map_err(|e| ConfigError::Parse(e.to_string()))?;

    let project = match &raw.project {
        serde_json::Value::String(s) => {
            eprintln!(
                "rsfusa: warning: legacy flat 'project' string in {}; use nested {{\"name\",\"version\"}}",
                path.display()
            );
            ProjectConfig {
                name: s.clone(),
                version: "0.1.0".to_string(),
            }
        }
        serde_json::Value::Object(_) => {
            serde_json::from_value::<ProjectConfig>(raw.project.clone())
                .map_err(|e| ConfigError::Parse(e.to_string()))?
        }
        _ => return Err(ConfigError::Parse("invalid 'project' field".to_string())),
    };

    validate_standard(&raw.standard)?;

    Ok(FusaConfig {
        config_version: raw.config_version,
        project,
        standard: raw.standard,
        asil: raw.asil,
        sil: raw.sil,
        dal: raw.dal,
        source_dirs: raw.source_dirs,
        exclude_patterns: raw.exclude_patterns,
        strict: raw.strict,
    })
}

pub fn save(path: &Path, cfg: &FusaConfig) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(cfg).expect("serialize config");
    std::fs::write(path, json + "\n")
}

fn validate_standard(s: &str) -> Result<(), ConfigError> {
    const KNOWN: &[&str] = &[
        "iso26262",
        "iec61508",
        "do178c",
        "iso21434",
        "iec62443-4-1",
        "iec62443-4-2",
        "misra-c",
        "misra-cpp",
        "autosar-cpp14",
        "cert-c",
        "cert-cpp",
        "unece-r155",
        "unece-r156",
        "generic",
    ];
    if KNOWN.contains(&s) {
        Ok(())
    } else {
        Err(ConfigError::InvalidStandard(s.to_string()))
    }
}

#[derive(Debug)]
pub enum ConfigError {
    NotFound(std::path::PathBuf),
    Io(std::io::Error),
    Parse(String),
    InvalidStandard(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NotFound(p) => write!(f, "no {} found in {}", CONFIG_FILE, p.display()),
            ConfigError::Io(e) => write!(f, "io error: {e}"),
            ConfigError::Parse(s) => write!(f, "parse error: {s}"),
            ConfigError::InvalidStandard(s) => write!(f, "unrecognised standard id {s:?}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ── Requirements registry (.fusa-reqs.json) ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asil: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReqsFile {
    pub requirements: Vec<Requirement>,
}

pub fn load_reqs(path: &Path) -> Result<ReqsFile, String> {
    let data =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let reqs: ReqsFile =
        serde_json::from_str(&data).map_err(|e| format!("parse {}: {e}", path.display()))?;
    Ok(reqs)
}

pub fn check_duplicate_ids(reqs: &ReqsFile) -> Vec<String> {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for r in &reqs.requirements {
        *seen.entry(r.id.as_str()).or_insert(0) += 1;
    }
    seen.into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(id, _)| id.to_string())
        .collect()
}

// ── Dispositions (.fusa-dispositions.json §1.2.3) ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispositionEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DispositionsFile {
    pub dispositions: Vec<DispositionEntry>,
}

pub fn load_dispositions(path: &Path) -> Option<DispositionsFile> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}
