// Tool qualification suite (§6). Each rule has a positive and negative case.

use crate::engine::{Registry, RunResult};
use crate::types::{LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const REPORT_FILE: &str = "qualify-report.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Case {
    pub name: String,
    pub rule_id: String,
    pub description: String,
    pub files: BTreeMap<String, String>,
    pub expect_finding: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseResult {
    pub name: String,
    pub result: String, // PASS | FAIL | SKIP | ERROR
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: String,
    pub kind: String,
    pub tool: String,
    pub tool_version: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<CaseResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl Report {
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

static MINIMAL_BASE: &[(&str, &str)] = &[
    (".fusa.json", r#"{
  "configVersion": "1.0",
  "project": {"name": "qualify-test", "version": "0.1.0"},
  "standard": "generic",
  "sourceDirs": ["."],
  "excludePatterns": ["target/**"]
}"#),
    ("Cargo.toml", "[package]\nname = \"qualify-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    ("LICENSE", "Mozilla Public License 2.0\n"),
    ("README.md", "# qualify-test\n"),
    (".github/workflows/ci.yml", "name: CI\n"),
    (".fusa-reqs.json", "{\"requirements\":[]}\n"),
];

fn minimal_base() -> BTreeMap<String, String> {
    MINIMAL_BASE
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn merge_base(extra: BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut m = minimal_base();
    m.extend(extra);
    m
}

pub fn builtin_cases() -> Vec<Case> {
    let base = minimal_base();

    let mut cases = vec![
        // FUSA001
        Case {
            name: "FUSA001-pos: missing .fusa.json".to_string(),
            rule_id: "FUSA001".to_string(),
            description: "Project without .fusa.json must produce a FUSA001 finding.".to_string(),
            expect_finding: true,
            files: {
                let mut m = base.clone();
                m.remove(".fusa.json");
                m
            },
        },
        Case {
            name: "FUSA001-neg: .fusa.json present".to_string(),
            rule_id: "FUSA001".to_string(),
            description: "Project with .fusa.json must not produce a FUSA001 finding.".to_string(),
            expect_finding: false,
            files: base.clone(),
        },
        // FUSA002
        Case {
            name: "FUSA002-pos: missing Cargo.toml".to_string(),
            rule_id: "FUSA002".to_string(),
            description: "Project without Cargo.toml must produce a FUSA002 finding.".to_string(),
            expect_finding: true,
            files: {
                let mut m = base.clone();
                m.remove("Cargo.toml");
                m
            },
        },
        Case {
            name: "FUSA002-neg: Cargo.toml present".to_string(),
            rule_id: "FUSA002".to_string(),
            description: "Project with Cargo.toml must not produce a FUSA002 finding.".to_string(),
            expect_finding: false,
            files: base.clone(),
        },
        // FUSA003
        Case {
            name: "FUSA003-pos: missing LICENSE".to_string(),
            rule_id: "FUSA003".to_string(),
            description: "Project without LICENSE must produce a FUSA003 finding.".to_string(),
            expect_finding: true,
            files: {
                let mut m = base.clone();
                m.remove("LICENSE");
                m
            },
        },
        Case {
            name: "FUSA003-neg: LICENSE present".to_string(),
            rule_id: "FUSA003".to_string(),
            description: "Project with LICENSE must not produce a FUSA003 finding.".to_string(),
            expect_finding: false,
            files: base.clone(),
        },
        // FUSA004
        Case {
            name: "FUSA004-pos: missing README".to_string(),
            rule_id: "FUSA004".to_string(),
            description: "Project without README must produce a FUSA004 finding.".to_string(),
            expect_finding: true,
            files: {
                let mut m = base.clone();
                m.remove("README.md");
                m
            },
        },
        Case {
            name: "FUSA004-neg: README.md present".to_string(),
            rule_id: "FUSA004".to_string(),
            description: "Project with README must not produce a FUSA004 finding.".to_string(),
            expect_finding: false,
            files: base.clone(),
        },
        // FUSA005
        Case {
            name: "FUSA005-pos: missing CI config".to_string(),
            rule_id: "FUSA005".to_string(),
            description: "Project without CI config must produce a FUSA005 finding.".to_string(),
            expect_finding: true,
            files: {
                let mut m = base.clone();
                m.remove(".github/workflows/ci.yml");
                m
            },
        },
        Case {
            name: "FUSA005-neg: .github/workflows present".to_string(),
            rule_id: "FUSA005".to_string(),
            description: "Project with CI config must not produce a FUSA005 finding.".to_string(),
            expect_finding: false,
            files: base.clone(),
        },
        // LINT001 — unsafe block
        Case {
            name: "LINT001-pos: unsafe block without justification".to_string(),
            rule_id: "LINT001".to_string(),
            description: "unsafe block without //fusa:unsafe must produce LINT001.".to_string(),
            expect_finding: true,
            files: merge_base({
                let mut m = BTreeMap::new();
                m.insert("src/lib.rs".to_string(), "pub fn foo() {\n    unsafe { let _ = 0; }\n}\n".to_string());
                m
            }),
        },
        Case {
            name: "LINT001-neg: unsafe block with justification".to_string(),
            rule_id: "LINT001".to_string(),
            description: "unsafe block with //fusa:unsafe must not produce LINT001.".to_string(),
            expect_finding: false,
            files: merge_base({
                let mut m = BTreeMap::new();
                m.insert("src/lib.rs".to_string(), "pub fn foo() {\n    //fusa:unsafe FFI call validated by C API contract\n    unsafe { let _ = 0; }\n}\n".to_string());
                m
            }),
        },
        // LINT002 — unwrap
        Case {
            name: "LINT002-pos: .unwrap() in source".to_string(),
            rule_id: "LINT002".to_string(),
            description: ".unwrap() in library code must produce LINT002.".to_string(),
            expect_finding: true,
            files: merge_base({
                let mut m = BTreeMap::new();
                m.insert("src/lib.rs".to_string(), "pub fn get() -> i32 { \"42\".parse().unwrap() }\n".to_string());
                m
            }),
        },
        Case {
            name: "LINT002-neg: no .unwrap() in source".to_string(),
            rule_id: "LINT002".to_string(),
            description: "Code without .unwrap() must not produce LINT002.".to_string(),
            expect_finding: false,
            files: merge_base({
                let mut m = BTreeMap::new();
                m.insert("src/lib.rs".to_string(), "pub fn get() -> i32 { 42 }\n".to_string());
                m
            }),
        },
        // LINT004 — transmute
        Case {
            name: "LINT004-pos: transmute without justification".to_string(),
            rule_id: "LINT004".to_string(),
            description: "mem::transmute without //fusa:unsafe must produce LINT004.".to_string(),
            expect_finding: true,
            files: merge_base({
                let mut m = BTreeMap::new();
                m.insert("src/lib.rs".to_string(), "use std::mem;\npub fn cast(x: u32) -> i32 { unsafe { mem::transmute(x) } }\n".to_string());
                m
            }),
        },
        Case {
            name: "LINT004-neg: transmute with justification".to_string(),
            rule_id: "LINT004".to_string(),
            description: "mem::transmute with //fusa:unsafe must not produce LINT004.".to_string(),
            expect_finding: false,
            files: merge_base({
                let mut m = BTreeMap::new();
                m.insert("src/lib.rs".to_string(), "use std::mem;\npub fn cast(x: u32) -> i32 {\n    //fusa:unsafe same bit width, validated\n    unsafe { mem::transmute(x) }\n}\n".to_string());
                m
            }),
        },
    ];

    cases.sort_by(|a, b| a.name.cmp(&b.name));
    cases
}

pub fn run(registry: &Registry, cases: &[Case]) -> Report {
    let mut results = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;

    for case in cases {
        let dir = match tempfile::TempDir::new() {
            Ok(d) => d,
            Err(e) => {
                results.push(CaseResult {
                    name: case.name.clone(),
                    result: "ERROR".to_string(),
                    error: Some(format!("create temp dir: {e}")),
                });
                continue;
            }
        };
        if let Err(e) = write_case_files(dir.path(), &case.files) {
            results.push(CaseResult {
                name: case.name.clone(),
                result: "ERROR".to_string(),
                error: Some(e),
            });
            continue;
        }
        let cfg = crate::config::FusaConfig::new("qualify-test", "generic");
        let run_result: RunResult = registry.run(dir.path(), &cfg);
        let found = run_result
            .findings
            .iter()
            .any(|f| f.rule_id == case.rule_id);
        let ok = found == case.expect_finding;
        if ok {
            passed += 1;
            results.push(CaseResult {
                name: case.name.clone(),
                result: "PASS".to_string(),
                error: None,
            });
        } else {
            failed += 1;
            let msg = if case.expect_finding {
                format!("expected {} finding but none produced", case.rule_id)
            } else {
                format!("expected no {} finding but one was produced", case.rule_id)
            };
            results.push(CaseResult {
                name: case.name.clone(),
                result: "FAIL".to_string(),
                error: Some(msg),
            });
        }
    }

    let total = cases.len();
    let mut report = Report {
        schema_version: SPEC_VERSION.to_string(),
        kind: "qualification".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        generated_at: chrono::Utc::now(),
        total,
        passed,
        failed,
        results,
        hash: None,
    };
    report.hash = Some(compute_hash(&report));
    report
}

fn write_case_files(dir: &Path, files: &BTreeMap<String, String>) -> Result<(), String> {
    for (rel, content) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, content.as_bytes())
            .map_err(|e| format!("write {rel}: {e}"))?;
    }
    Ok(())
}

fn compute_hash(report: &Report) -> String {
    // Per §6: sort results by name, remove hash, set generatedAt:"", RFC 8785 serialise.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Canonical<'a> {
        schema_version: &'a str,
        kind: &'a str,
        tool: &'a str,
        tool_version: &'a str,
        language: &'a str,
        generated_at: &'static str,
        total: usize,
        passed: usize,
        failed: usize,
        results: Vec<&'a CaseResult>,
    }

    let mut sorted_results: Vec<&CaseResult> = report.results.iter().collect();
    sorted_results.sort_by_key(|r| r.name.as_str());

    let c = Canonical {
        schema_version: &report.schema_version,
        kind: &report.kind,
        tool: &report.tool,
        tool_version: &report.tool_version,
        language: &report.language,
        generated_at: "",
        total: report.total,
        passed: report.passed,
        failed: report.failed,
        results: sorted_results,
    };

    let json = serde_json::to_string(&c).expect("canonical serialise");
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn save(path: &Path, report: &Report) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(report).expect("serialize qualify report");
    std::fs::write(path, json + "\n")
}
