// Requirement traceability matrix (§5).
//fusa:req REQ-TRACE001
//fusa:req REQ-TRACE002
//fusa:req REQ-TRACE003
//fusa:req REQ-TRACE004
//fusa:req REQ-TRACE005
//fusa:req REQ-TRACE006
//fusa:req REQ-TRACE007
//fusa:req REQ-TRACE-MD001
//fusa:req REQ-TRACE-HLR001
//fusa:req REQ-TRACE-HLR002
//fusa:req REQ-TRACE-HLR003
//fusa:req REQ-TRACE-HLR004

use crate::config::{load_reqs, FusaConfig, Requirement};
use crate::types::{
    Category, Finding, Location, Severity, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION,
};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlr_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llr_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlr_with_llr: Option<usize>,
}

/// HLR/LLR validation result.
#[derive(Debug)]
pub struct HlrLlrResult {
    pub findings: Vec<Finding>,
    /// true if any finding is ERROR severity (gate fail)
    pub has_errors: bool,
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

/// Validate HLR/LLR parent-child relationships in the requirements list.
///
/// Rules:
/// - Each LLR (level == "LLR") must reference a parent that exists and has level == "HLR".
/// - Each HLR must have at least one LLR child.
///
/// The `strict` flag forces ERROR severity regardless of DAL/ASIL level.
/// Otherwise: DAL-A/ASIL-D → ERROR; DAL-C/ASIL-C and below → WARNING.
pub fn validate_hlr_llr(
    requirements: &[Requirement],
    dal: Option<&str>,
    asil: Option<&str>,
    strict: bool,
) -> HlrLlrResult {
    //fusa:req REQ-TRACE-HLR001
    //fusa:req REQ-TRACE-HLR002
    //fusa:req REQ-TRACE-HLR003
    //fusa:req REQ-TRACE-HLR004

    // Determine base severity from DAL/ASIL context.
    let base_sev = if strict {
        Severity::Error
    } else {
        let is_critical = matches!(
            dal.unwrap_or(""),
            "DAL-A" | "DAL-B" | "a" | "b"
        ) || matches!(
            asil.unwrap_or(""),
            "ASIL-D" | "ASIL-C" | "D" | "C"
        );
        if is_critical {
            Severity::Error
        } else {
            Severity::Warning
        }
    };

    let hlr_ids: std::collections::HashSet<&str> = requirements
        .iter()
        .filter(|r| r.level.as_deref() == Some("HLR"))
        .map(|r| r.id.as_str())
        .collect();

    let mut findings = Vec::new();

    // Every LLR must reference an existing HLR parent.
    for req in requirements {
        if req.level.as_deref() != Some("LLR") {
            continue;
        }
        match req.parent.as_deref() {
            None | Some("") => {
                findings.push(
                    Finding::new(
                        "TRACE-HLR001",
                        base_sev.clone(),
                        format!("LLR {} has no parent_id; every LLR must reference an HLR", req.id),
                        Location::new(".fusa-reqs.json"),
                        Category::Requirement,
                        "add a 'parent' field to this LLR pointing to its parent HLR id",
                    )
                );
            }
            Some(pid) => {
                if !hlr_ids.contains(pid) {
                    findings.push(
                        Finding::new(
                            "TRACE-HLR002",
                            base_sev.clone(),
                            format!(
                                "LLR {} references parent '{}' which is not an HLR in .fusa-reqs.json",
                                req.id, pid
                            ),
                            Location::new(".fusa-reqs.json"),
                            Category::Requirement,
                            "ensure the parent id exists and has level 'HLR'",
                        )
                    );
                }
            }
        }
    }

    // Every HLR must have at least one LLR child.
    let mut hlr_child_count: HashMap<&str, usize> = HashMap::new();
    for req in requirements {
        if req.level.as_deref() == Some("HLR") {
            hlr_child_count.entry(req.id.as_str()).or_insert(0);
        }
    }
    for req in requirements {
        if req.level.as_deref() == Some("LLR") {
            if let Some(pid) = req.parent.as_deref() {
                if let Some(count) = hlr_child_count.get_mut(pid) {
                    *count += 1;
                }
            }
        }
    }
    for (hlr_id, count) in &hlr_child_count {
        if *count == 0 {
            findings.push(
                Finding::new(
                    "TRACE-HLR003",
                    base_sev.clone(),
                    format!("HLR {hlr_id} has no LLR children; every HLR must be decomposed"),
                    Location::new(".fusa-reqs.json"),
                    Category::Requirement,
                    "add at least one LLR with this HLR's id as its 'parent' field",
                )
            );
        }
    }

    let has_errors = findings
        .iter()
        .any(|f| f.severity == Severity::Error);

    HlrLlrResult { findings, has_errors }
}

pub fn build(project_root: &Path, cfg: &FusaConfig) -> Result<(Matrix, Vec<Finding>), String> {
    let reqs_path = project_root.join(".fusa-reqs.json");
    let (requirements, mut findings) = if reqs_path.exists() {
        let reqs = load_reqs(&reqs_path)?;
        let dups = crate::config::check_duplicate_ids(&reqs);
        let dup_findings: Vec<Finding> = dups
            .into_iter()
            .map(|id| {
                Finding::new(
                    "REQ001",
                    Severity::Error,
                    format!("duplicate requirement id: {id}"),
                    Location::new(".fusa-reqs.json"),
                    Category::Requirement,
                    "each requirement id must be unique within .fusa-reqs.json",
                )
            })
            .collect();
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
                "REQ002",
                Severity::Warning,
                format!(
                    "annotation references unknown requirement id: {}",
                    tag.requirement_id
                ),
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
        let content = std::fs::read_to_string(path).map_err(|e| format!("read {rel}: {e}"))?;
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
                        "REQ003",
                        Severity::Warning,
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

    // HLR/LLR hierarchy metrics.
    let hlr_count = requirements
        .iter()
        .filter(|r| r.level.as_deref() == Some("HLR"))
        .count();
    let llr_count = requirements
        .iter()
        .filter(|r| r.level.as_deref() == Some("LLR"))
        .count();

    // Count HLRs that have at least one LLR child.
    let llr_parents: std::collections::HashSet<&str> = requirements
        .iter()
        .filter(|r| r.level.as_deref() == Some("LLR"))
        .filter_map(|r| r.parent.as_deref())
        .collect();
    let hlr_with_llr = requirements
        .iter()
        .filter(|r| r.level.as_deref() == Some("HLR") && llr_parents.contains(r.id.as_str()))
        .count();

    let (opt_hlr, opt_llr, opt_hlr_with_llr) = if hlr_count > 0 || llr_count > 0 {
        (Some(hlr_count), Some(llr_count), Some(hlr_with_llr))
    } else {
        (None, None, None)
    };

    Coverage {
        total_requirements: total,
        traced_requirements: traced.len(),
        tested_requirements: tested.len(),
        sec_tested_requirements: sec_tested.len(),
        hlr_count: opt_hlr,
        llr_count: opt_llr,
        hlr_with_llr: opt_hlr_with_llr,
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
    if let (Some(hlr), Some(llr), Some(hlr_with_llr)) = (
        matrix.coverage.hlr_count,
        matrix.coverage.llr_count,
        matrix.coverage.hlr_with_llr,
    ) {
        writeln!(
            w,
            "HLR:     {}  LLR: {}  HLRs with LLR: {}",
            hlr, llr, hlr_with_llr
        )?;
    }
    writeln!(w)?;

    // Group LLRs by parent for hierarchical rendering.
    let mut llr_by_parent: HashMap<&str, Vec<&Requirement>> = HashMap::new();
    for req in &matrix.requirements {
        if req.level.as_deref() == Some("LLR") {
            if let Some(pid) = req.parent.as_deref() {
                llr_by_parent.entry(pid).or_default().push(req);
            }
        }
    }

    for req in &matrix.requirements {
        let title = req.title.as_deref().unwrap_or("(no title)");
        let level_tag = match req.level.as_deref() {
            Some("HLR") => " [HLR]",
            Some("LLR") => " [LLR]",
            _ => "",
        };
        writeln!(w, "  {:<25} {}{}", req.id, title, level_tag)?;
        for tag in matrix.tags.iter().filter(|t| t.requirement_id == req.id) {
            writeln!(w, "    [{:<8}] {}:{}", tag.kind, tag.file, tag.line)?;
        }
        // If HLR, show child LLRs.
        if req.level.as_deref() == Some("HLR") {
            if let Some(children) = llr_by_parent.get(req.id.as_str()) {
                for child in children {
                    let ctitle = child.title.as_deref().unwrap_or("(no title)");
                    writeln!(w, "    LLR {:<21} {}", child.id, ctitle)?;
                    for tag in matrix.tags.iter().filter(|t| t.requirement_id == child.id) {
                        writeln!(w, "      [{:<8}] {}:{}", tag.kind, tag.file, tag.line)?;
                    }
                }
            }
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
    if let (Some(hlr), Some(llr), Some(hlr_with_llr)) = (
        matrix.coverage.hlr_count,
        matrix.coverage.llr_count,
        matrix.coverage.hlr_with_llr,
    ) {
        writeln!(
            w,
            "**HLR:** {hlr}  **LLR:** {llr}  **HLRs with LLR:** {hlr_with_llr}"
        )?;
        writeln!(w)?;
    }
    writeln!(w, "| ID | Level | Parent | Title | Traced | Tested |")?;
    writeln!(w, "|---|---|---|---|---|---|")?;

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
            .map(|t| {
                t.iter()
                    .any(|tt| tt.kind == TagKind::Test || tt.kind == TagKind::SecTest)
            })
            .unwrap_or(false);
        let title = req.title.as_deref().unwrap_or("");
        let level = req.level.as_deref().unwrap_or("");
        let parent = req.parent.as_deref().unwrap_or("");
        writeln!(
            w,
            "| {} | {} | {} | {} | {} | {} |",
            req.id,
            level,
            parent,
            title,
            if traced { "✓" } else { "✗" },
            if tested { "✓" } else { "✗" }
        )?;
    }
    Ok(())
}
