// Requirement traceability matrix (§5).
//fusa:req REQ-TRACE001
//fusa:req REQ-TRACE002
//fusa:req REQ-TRACE003
//fusa:req REQ-TRACE004
//fusa:req REQ-TRACE005
//fusa:req REQ-TRACE006
//fusa:req REQ-TRACE007

use crate::config::{FusaConfig, Requirement, load_reqs};
use crate::types::{Category, Finding, Location, Severity, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TagKind {
    Impl,
    Test,
    #[serde(rename = "sec-test")]
    SecTest,
}

impl std::fmt::Display for TagKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TagKind::Impl => write!(f, "impl"),
            TagKind::Test => write!(f, "test"),
            TagKind::SecTest => write!(f, "sec-test"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tag {
    pub requirement_id: String,
    pub file: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub line: u32,
    pub kind: TagKind,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub total_requirements: usize,
    pub traced_requirements: usize,
    pub tested_requirements: usize,
    pub sec_tested_requirements: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Matrix {
    pub schema_version: String,
    pub kind: String,
    pub tool: String,
    pub tool_version: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub project_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard: Option<String>,
    pub requirements: Vec<Requirement>,
    pub tags: Vec<Tag>,
    pub coverage: Coverage,
}

pub fn build(project_root: &Path, cfg: &FusaConfig) -> Result<(Matrix, Vec<Finding>), String> {
    let reqs_path = project_root.join(".fusa-reqs.json");
    let (requirements, mut findings) = if reqs_path.exists() {
        let reqs = load_reqs(&reqs_path)?;
        let dups = crate::config::check_duplicate_ids(&reqs);
        let dup_findings: Vec<Finding> = dups.into_iter().map(|id| Finding::new(
            "REQ001", Severity::Error,
            format!("duplicate requirement id: {id}"),
            Location::new(".fusa-reqs.json"),
            Category::Requirement,
            "each requirement id must be unique within .fusa-reqs.json",
        )).collect();
        (reqs.requirements, dup_findings)
    } else {
        (vec![], vec![])
    };

    let mut tags = Vec::new();
    let mut parse_findings = scan_annotations(project_root, cfg, &mut tags)?;
    findings.append(&mut parse_findings);

    // Validate referenced requirement ids exist
    let req_ids: HashMap<&str, ()> = requirements.iter().map(|r| (r.id.as_str(), ())).collect();
    for tag in &tags {
        if !req_ids.contains_key(tag.requirement_id.as_str()) {
            findings.push(Finding::new(
                "REQ002", Severity::Warning,
                format!("annotation references unknown requirement id: {}", tag.requirement_id),
                Location::at(tag.file.clone(), tag.line),
                Category::Requirement,
                "add the requirement to .fusa-reqs.json or fix the id",
            ));
        }
    }

    let coverage = compute_coverage(&requirements, &tags);

    let matrix = Matrix {
        schema_version: SPEC_VERSION.to_string(),
        kind: "trace-matrix".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        generated_at: chrono::Utc::now(),
        project_root: project_root.to_string_lossy().into_owned(),
        project: Some(cfg.project.name.clone()),
        standard: Some(cfg.standard.clone()),
        requirements,
        tags,
        coverage,
    };

    Ok((matrix, findings))
}

fn scan_annotations(
    root: &Path,
    cfg: &FusaConfig,
    tags: &mut Vec<Tag>,
) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext != "rs" && ext != "toml" {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_excluded(&rel, &cfg.exclude_patterns) {
            continue;
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("read {rel}: {e}"))?;
        for (i, line) in content.lines().enumerate() {
            let lineno = (i + 1) as u32;
            if let Some(kind) = annotation_kind(line) {
                match extract_req_id(line, kind) {
                    Ok(id) => tags.push(Tag {
                        requirement_id: id,
                        file: rel.clone(),
                        line: lineno,
                        kind: kind.clone(),
                    }),
                    Err(e) => findings.push(Finding::new(
                        "REQ003", Severity::Warning,
                        format!("malformed //fusa:{} annotation: {e}", kind),
                        Location::at(rel.clone(), lineno),
                        Category::Requirement,
                        "annotation must have exactly one requirement id after the tag keyword",
                    )),
                }
            }
        }
    }
    Ok(findings)
}

fn annotation_kind(line: &str) -> Option<&TagKind> {
    static IMPL: TagKind = TagKind::Impl;
    static TEST: TagKind = TagKind::Test;
    static SEC: TagKind = TagKind::SecTest;
    let t = line.trim();
    if t.contains("//fusa:req") || t.contains("# fusa:req") {
        Some(&IMPL)
    } else if t.contains("//fusa:sec-test") || t.contains("# fusa:sec-test") {
        Some(&SEC)
    } else if t.contains("//fusa:test") || t.contains("# fusa:test") {
        Some(&TEST)
    } else {
        None
    }
}

fn extract_req_id(line: &str, kind: &TagKind) -> Result<String, String> {
    let keyword = match kind {
        TagKind::Impl => "//fusa:req",
        TagKind::Test => "//fusa:test",
        TagKind::SecTest => "//fusa:sec-test",
    };
    let alts = match kind {
        TagKind::Impl => &["//fusa:req", "# fusa:req"][..],
        TagKind::Test => &["//fusa:test", "# fusa:test"][..],
        TagKind::SecTest => &["//fusa:sec-test", "# fusa:sec-test"][..],
    };
    for &kw in alts {
        if let Some(pos) = line.find(kw) {
            let after = line[pos + kw.len()..].trim();
            let tokens: Vec<&str> = after.split_whitespace().collect();
            if tokens.is_empty() {
                return Err(format!("missing requirement id after {kw}"));
            }
            if tokens.len() > 1 {
                return Err(format!(
                    "only one id per annotation (got {:?}); use separate lines",
                    tokens
                ));
            }
            let _ = keyword;
            return Ok(tokens[0].to_string());
        }
    }
    Err("annotation keyword not found".to_string())
}

fn is_excluded(rel: &str, patterns: &[String]) -> bool {
    for pat in patterns {
        if let Ok(g) = glob::Pattern::new(pat) {
            if g.matches(rel) {
                return true;
            }
        }
    }
    false
}

fn compute_coverage(requirements: &[Requirement], tags: &[Tag]) -> Coverage {
    let total = requirements.len();
    let req_ids: std::collections::HashSet<&str> =
        requirements.iter().map(|r| r.id.as_str()).collect();

    let mut traced: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut tested: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut sec_tested: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for tag in tags {
        let id = tag.requirement_id.as_str();
        if !req_ids.contains(id) {
            continue;
        }
        traced.insert(id);
        if tag.kind == TagKind::Test || tag.kind == TagKind::SecTest {
            tested.insert(id);
        }
        if tag.kind == TagKind::SecTest {
            sec_tested.insert(id);
        }
    }

    Coverage {
        total_requirements: total,
        traced_requirements: traced.len(),
        tested_requirements: tested.len(),
        sec_tested_requirements: sec_tested.len(),
    }
}

pub fn render_text<W: Write + ?Sized>(w: &mut W, matrix: &Matrix) -> std::io::Result<()> {
    writeln!(w, "Requirement Traceability Matrix")?;
    writeln!(w, "================================")?;
    writeln!(w)?;
    writeln!(
        w,
        "Total:   {}  Traced: {}  Tested: {}  Sec-tested: {}",
        matrix.coverage.total_requirements,
        matrix.coverage.traced_requirements,
        matrix.coverage.tested_requirements,
        matrix.coverage.sec_tested_requirements
    )?;
    writeln!(w)?;

    for req in &matrix.requirements {
        let title = req.title.as_deref().unwrap_or("(no title)");
        writeln!(w, "  {:<25} {}", req.id, title)?;
        for tag in matrix.tags.iter().filter(|t| t.requirement_id == req.id) {
            writeln!(w, "    [{:<8}] {}:{}", tag.kind, tag.file, tag.line)?;
        }
    }

    if matrix.requirements.is_empty() {
        writeln!(w, "  (no requirements defined)")?;
    }
    Ok(())
}

pub fn render_md<W: Write + ?Sized>(w: &mut W, matrix: &Matrix) -> std::io::Result<()> {
    writeln!(w, "# Requirement Traceability Matrix")?;
    writeln!(w)?;
    writeln!(w, "| ID | Title | Traced | Tested |")?;
    writeln!(w, "|---|---|---|---|")?;

    let tags_by_req: HashMap<&str, Vec<&Tag>> = {
        let mut m: HashMap<&str, Vec<&Tag>> = HashMap::new();
        for tag in &matrix.tags {
            m.entry(tag.requirement_id.as_str()).or_default().push(tag);
        }
        m
    };

    for req in &matrix.requirements {
        let tags = tags_by_req.get(req.id.as_str());
        let traced = tags.map(|t| !t.is_empty()).unwrap_or(false);
        let tested = tags
            .map(|t| t.iter().any(|tt| tt.kind == TagKind::Test || tt.kind == TagKind::SecTest))
            .unwrap_or(false);
        let title = req.title.as_deref().unwrap_or("");
        writeln!(
            w,
            "| {} | {} | {} | {} |",
            req.id,
            title,
            if traced { "✓" } else { "✗" },
            if tested { "✓" } else { "✗" }
        )?;
    }
    Ok(())
}
