// Core value types shared across all modules (§4, §2.4, §1.5).
//fusa:req REQ-LOC001
//fusa:req REQ-LOC-REL001
//fusa:req REQ-CLI001
//fusa:req REQ-CLI003
//fusa:req REQ-CLI004
//fusa:req REQ-ENG004
//fusa:req REQ-ENG005
//fusa:req REQ-NF002
//fusa:req REQ-RUNTIME004
//fusa:req REQ-RUNTIME005

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub const VERSION: &str = "0.3.15";
pub const SPEC_VERSION: &str = "1.15.2";
pub const TOOL_NAME: &str = "rust-FuSa";
pub const LANGUAGE: &str = "rust";

pub const EXIT_OK: i32 = 0;
pub const EXIT_GATE_FAIL: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_RUNTIME: i32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "ERROR")]
    Error,
    #[serde(rename = "WARNING")]
    Warning,
    #[serde(rename = "INFO")]
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Error => write!(f, "ERROR"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Lint,
    Style,
    Safety,
    Security,
    Coverage,
    Requirement,
    Concurrency,
    #[serde(rename = "supply-chain")]
    SupplyChain,
    Config,
    Other,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Category::Lint => "lint",
            Category::Style => "style",
            Category::Safety => "safety",
            Category::Security => "security",
            Category::Coverage => "coverage",
            Category::Requirement => "requirement",
            Category::Concurrency => "concurrency",
            Category::SupplyChain => "supply-chain",
            Category::Config => "config",
            Category::Other => "other",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Open,
    Accepted,
    Deferred,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub file: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub line: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub column: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl Location {
    pub fn new(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line: 0,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    pub fn at(file: impl Into<String>, line: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column: 0,
            end_line: None,
            end_column: None,
        }
    }

    /// Construct a location with full span: start column and end column (both 1-indexed, inclusive).
    /// Sets endLine = line (single-line span). col/end_col of 0 leave those fields absent.
    pub fn at_col(file: impl Into<String>, line: u32, col: u32, end_col: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column: col,
            end_line: if end_col > 0 { Some(line) } else { None },
            end_column: if end_col > 0 { Some(end_col) } else { None },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub location: Location,
    pub category: Category,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clause: Option<String>,
    pub remediation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<Disposition>,
    pub fingerprint: String,
}

impl Finding {
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        location: Location,
        category: Category,
        remediation: impl Into<String>,
    ) -> Self {
        let rule_id = rule_id.into();
        let message = message.into();
        let fingerprint = compute_fingerprint(&rule_id, &location.file, &message);
        Self {
            rule_id,
            severity,
            message,
            location,
            category,
            standard: None,
            clause: None,
            remediation: remediation.into(),
            disposition: None,
            fingerprint,
        }
    }

    pub fn with_standard(mut self, standard: impl Into<String>, clause: impl Into<String>) -> Self {
        self.standard = Some(standard.into());
        let c = clause.into();
        if !c.is_empty() {
            self.clause = Some(c);
        }
        self
    }
}

/// Compute the §4.2 canonical fingerprint.
pub fn compute_fingerprint(rule_id: &str, file: &str, message: &str) -> String {
    let norm = normalize_message(message);
    let canonical = format!("{rule_id}\x1f{file}\x1f{norm}");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

/// Normalise message per §4.2: replace digit runs with "#", collapse whitespace, trim.
/// NFC only when non-ASCII codepoints are present.
pub fn normalize_message(msg: &str) -> String {
    let processed: String = if msg.is_ascii() {
        msg.to_string()
    } else {
        msg.nfc().collect()
    };

    let mut out = String::with_capacity(processed.len());
    let mut in_digits = false;
    let mut in_space = false;

    for c in processed.chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                out.push('#');
                in_digits = true;
            }
            in_space = false;
        } else if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
            in_digits = false;
            in_space = true;
        } else {
            if in_space && !out.is_empty() {
                out.push(' ');
            }
            out.push(c);
            in_digits = false;
            in_space = false;
        }
    }
    out.trim().to_string()
}

/// Derive category from rule id prefix per §1.5.1.
pub fn derive_category(rule_id: &str) -> Category {
    let upper = rule_id.to_uppercase();
    let prefix: &str = {
        let cut = upper
            .find(|c: char| c.is_ascii_digit() || c == '-')
            .unwrap_or(upper.len());
        &upper[..cut]
    };
    match prefix {
        "LINT" => Category::Lint,
        "STYLE" => Category::Style,
        "FUSA" => Category::Safety,
        "SEC" | "CWE" | "CYBER" => Category::Security,
        "COV" => Category::Coverage,
        "REQ" | "TRACE" => Category::Requirement,
        "CONC" | "RACE" => Category::Concurrency,
        "SBOM" | "SLSA" | "VULN" | "RELEASE" => Category::SupplyChain,
        "CFG" => Category::Config,
        "ISO" | "IEC" | "DO" | "MISRA" | "AUTOSAR" | "CERT" | "UNECE" => Category::Safety,
        _ => Category::Other,
    }
}
