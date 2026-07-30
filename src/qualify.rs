// Tool qualification suite (§6). Each rule has a positive and negative case.
//fusa:req REQ-QUALIFY001
//fusa:req REQ-QUALIFY002
//fusa:req REQ-QUALIFY003
//fusa:req REQ-QUALIFY004
//fusa:req REQ-E2E001
//fusa:req REQ-QUALIFY-TQ001
//fusa:req REQ-QUALIFY-TQ002
//fusa:req REQ-QUALIFY-TQ003
//fusa:req REQ-QUALIFY-VV001
//fusa:req REQ-QUALIFY-VV002
//fusa:req REQ-QUALIFY-VV003
//fusa:req REQ-QUALIFY-VV004

use crate::engine::{Registry, RunResult};
use crate::types::{LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::{Deserialize, Serialize};
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
    /// "self", "independent", or absent (§6 tool qualification method).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualification_method: Option<String>,
    /// URI to the qualification dossier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualification_record_uri: Option<String>,
    /// Name/org of the qualifying entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier_identity: Option<String>,
    /// Qualification badge: "independently-qualified" | "self-qualified" | "unqualified".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualification_badge: Option<String>,
    // V&V Independence fields (§6.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub independent_reviewer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub independent_test_executor: Option<String>,
    /// ASIL achievable given independence configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub achievable_asil: Option<String>,
    /// "independent" when reviewer differs from author, else "non-independent".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub independence_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl Report {
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }

    /// Compute and set the qualification badge from qualification_method.
    pub fn compute_badge(&mut self) {
        let badge = match self.qualification_method.as_deref() {
            Some("independent") => "independently-qualified",
            Some("self") => "self-qualified",
            _ => "unqualified",
        };
        self.qualification_badge = Some(badge.to_string());
    }

    /// Compute and set independence_status from implementation_author and independent_reviewer.
    pub fn compute_independence(&mut self) {
        if let (Some(author), Some(reviewer)) = (
            self.implementation_author.as_deref(),
            self.independent_reviewer.as_deref(),
        ) {
            let status = if !author.is_empty() && !reviewer.is_empty() && author != reviewer {
                "independent"
            } else {
                "non-independent"
            };
            self.independence_status = Some(status.to_string());
        }
    }
}

static MINIMAL_BASE: &[(&str, &str)] = &[
    (
        ".fusa.json",
        r#"{
  "configVersion": "1.0",
  "project": {"name": "qualify-test", "version": "0.1.0"},
  "standard": "generic",
  "sourceDirs": ["."],
  "excludePatterns": ["target/**"]
}"#,
    ),
    (
        "Cargo.toml",
        "[package]\nname = \"qualify-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ),
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
                m.insert(
                    "src/lib.rs".to_string(),
                    "pub fn foo() {\n    unsafe { let _ = 0; }\n}\n".to_string(),
                );
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
                m.insert(
                    "src/lib.rs".to_string(),
                    "pub fn get() -> i32 { \"42\".parse().unwrap() }\n".to_string(),
                );
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
                m.insert(
                    "src/lib.rs".to_string(),
                    "pub fn get() -> i32 { 42 }\n".to_string(),
                );
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
                m.insert(
                    "src/lib.rs".to_string(),
                    "use std::mem;\npub fn cast(x: u32) -> i32 { unsafe { mem::transmute(x) } }\n"
                        .to_string(),
                );
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

/// Builder for extra qualification / V&V metadata.
#[derive(Debug, Default, Clone)]
pub struct QualifyOptions {
    pub qualification_method: Option<String>,
    pub qualification_record_uri: Option<String>,
    pub qualifier_identity: Option<String>,
    pub implementation_author: Option<String>,
    pub independent_reviewer: Option<String>,
    pub independent_test_executor: Option<String>,
    pub achievable_asil: Option<String>,
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
        qualification_method: None,
        qualification_record_uri: None,
        qualifier_identity: None,
        qualification_badge: None,
        implementation_author: None,
        independent_reviewer: None,
        independent_test_executor: None,
        achievable_asil: None,
        independence_status: None,
        hash: None,
    };
    report.hash = Some(compute_hash(&report));
    report
}

pub fn run_with_opts(registry: &Registry, cases: &[Case], opts: &QualifyOptions) -> Report {
    let mut report = run(registry, cases);
    report.qualification_method = opts.qualification_method.clone();
    report.qualification_record_uri = opts.qualification_record_uri.clone();
    report.qualifier_identity = opts.qualifier_identity.clone();
    report.implementation_author = opts.implementation_author.clone();
    report.independent_reviewer = opts.independent_reviewer.clone();
    report.independent_test_executor = opts.independent_test_executor.clone();
    report.achievable_asil = opts.achievable_asil.clone();
    report.compute_badge();
    report.compute_independence();
    // Recompute hash to include the new fields.
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
        std::fs::write(&path, content.as_bytes()).map_err(|e| format!("write {rel}: {e}"))?;
    }
    Ok(())
}

fn compute_hash(report: &Report) -> String {
    // Per §6: sort results by name, remove `hash`, blank `generatedAt`, then
    // hash the report's OWN serialized document via canonjson — so EVERY
    // authenticated field is covered. A hand-rolled `Canonical` subset omitted
    // operator-supplied `qualificationRecordUri` and `achievableAsil`, leaving
    // them tamperable without invalidating the emitted hash. This mirrors the
    // independent RFC 8785 reconstruction in this module's hash tests.
    let mut value = serde_json::to_value(report).expect("serialize report");
    let obj = value.as_object_mut().expect("report is an object");
    obj.remove("hash");
    obj.insert(
        "generatedAt".to_string(),
        serde_json::Value::String(String::new()),
    );
    if let Some(results) = obj.get_mut("results").and_then(|r| r.as_array_mut()) {
        results.sort_by(|a, b| {
            a["name"]
                .as_str()
                .unwrap_or("")
                .cmp(b["name"].as_str().unwrap_or(""))
        });
    }
    crate::canonjson::content_hash(&value)
}

pub fn save(path: &Path, report: &Report) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(report).expect("serialize qualify report");
    std::fs::write(path, json + "\n")
}

#[cfg(test)]
mod hash_tests {
    use super::*;
    use crate::engine::default_registry;

    /// §6 "hash": computed over a key-sorted canonical document (the JCS-subset
    /// canonicalization in `canonjson`) — keys sorted lexicographically
    /// at *every* level, not just `results[]` sorted by name. A hand-rolled
    /// struct serialised via `serde_json::to_string` emits keys in
    /// struct-declaration order, which is not lexicographic (e.g.
    /// `schemaVersion` before `kind` before `tool`, but sorted order is
    /// `kind` < `schemaVersion` < `tool`). This test independently
    /// reconstructs the key-sorted canonical document (via `canonjson`,
    /// the same helper the §1.6.2 attestation `contentHash` uses) and checks
    /// it against the tool's emitted `hash`, so a regression back to
    /// declaration-order serialisation would fail it.
    //fusa:test REQ-QUALIFY004
    #[test]
    fn hash_matches_independent_rfc8785_canonicalization() {
        let registry = default_registry();
        let cases = builtin_cases();
        let report = run(&registry, &cases);
        let emitted = report.hash.clone().expect("hash MUST be emitted");

        // Rebuild the same logical document independently, straight off the
        // report's own serde_json::Value (so this test does not simply call
        // the same private `Canonical` struct the implementation uses), sort
        // results by name, blank generatedAt, drop hash, then canonicalize.
        let mut value = serde_json::to_value(&report).expect("serialize report");
        let obj = value.as_object_mut().expect("report is an object");
        obj.remove("hash");
        obj.insert(
            "generatedAt".to_string(),
            serde_json::Value::String(String::new()),
        );
        if let Some(results) = obj.get_mut("results").and_then(|r| r.as_array_mut()) {
            results.sort_by(|a, b| {
                a["name"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["name"].as_str().unwrap_or(""))
            });
        }
        let expected = crate::canonjson::content_hash(&value);

        assert_eq!(
            emitted, expected,
            "qualify hash must equal a key-sorted (recursively lexicographic) \
             canonicalization of the document, not one serialised in \
             struct-declaration key order"
        );
    }

    /// The hash must not depend on the order `results[]` happen to be
    /// produced in — §6 step 1 requires sorting by `name` before hashing.
    //fusa:test REQ-QUALIFY004
    #[test]
    fn hash_independent_of_case_order() {
        let registry = default_registry();
        let mut cases = builtin_cases();
        let forward = run(&registry, &cases);

        cases.reverse();
        let reversed = run(&registry, &cases);

        assert_eq!(
            forward.hash, reversed.hash,
            "hash must be stable regardless of the order cases were run in"
        );
    }

    /// D003 regression: the integrity hash MUST authenticate every serialized
    /// field, including operator-supplied `achievableAsil` and
    /// `qualificationRecordUri`. Editing either must change the hash.
    //fusa:test REQ-QUALIFY004
    #[test]
    fn hash_covers_achievable_asil_and_record_uri() {
        let registry = default_registry();
        let cases = builtin_cases();

        let base_opts = QualifyOptions {
            achievable_asil: Some("ASIL-B".to_string()),
            qualification_record_uri: Some("https://example.com/dossier-a".to_string()),
            ..Default::default()
        };
        let base = run_with_opts(&registry, &cases, &base_opts);

        let tampered_asil = QualifyOptions {
            achievable_asil: Some("ASIL-D".to_string()),
            ..base_opts.clone()
        };
        let asil_report = run_with_opts(&registry, &cases, &tampered_asil);
        assert_ne!(
            base.hash, asil_report.hash,
            "changing achievableAsil must change the integrity hash"
        );

        let tampered_uri = QualifyOptions {
            qualification_record_uri: Some("https://evil.example/dossier-b".to_string()),
            ..base_opts.clone()
        };
        let uri_report = run_with_opts(&registry, &cases, &tampered_uri);
        assert_ne!(
            base.hash, uri_report.hash,
            "changing qualificationRecordUri must change the integrity hash"
        );
    }
}
