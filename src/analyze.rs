// Static analysis rules: ANA001–ANA006
//fusa:req REQ-ANA001
//fusa:req REQ-ANA002
//fusa:req REQ-ANA003
//fusa:req REQ-ANA004
//fusa:req REQ-ANA005
//fusa:req REQ-ANA006

use crate::config::FusaConfig;
use crate::engine::{Registry, Rule};
use crate::types::{Category, Finding, Location, Severity};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn register_all(reg: &mut Registry) {
    reg.register(Box::new(RuleFunctionLength));
    reg.register(Box::new(RuleNestingDepth));
    reg.register(Box::new(RuleTooManyParams));
    reg.register(Box::new(RuleRawPointerDeref));
    reg.register(Box::new(RuleIntegerTruncatingCast));
    reg.register(Box::new(RuleMultipleReturnPoints));
}

fn rust_sources(root: &Path, cfg: &FusaConfig) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if is_excluded(&rel_str, &cfg.exclude_patterns) {
            continue;
        }
        if !is_in_source_dirs(&rel_str, &cfg.source_dirs) {
            continue;
        }
        files.push(path.to_path_buf());
    }
    files
}

fn is_excluded(rel: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pat| {
        glob::Pattern::new(pat)
            .map(|g| g.matches(rel))
            .unwrap_or(false)
    })
}

fn is_in_source_dirs(rel: &str, dirs: &[String]) -> bool {
    if dirs.is_empty() || dirs == ["."] {
        return true;
    }
    dirs.iter().any(|d| {
        let d = d.trim_start_matches("./");
        d == "." || rel.starts_with(d)
    })
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

// ANA001 — function body length exceeds 60 lines.
struct RuleFunctionLength;
impl Rule for RuleFunctionLength {
    fn id(&self) -> &str {
        "ANA001"
    }
    fn description(&self) -> &str {
        "Functions exceeding 60 lines are harder to review and certify."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        const MAX_LINES: usize = 60;
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            let mut fn_start: Option<(usize, String)> = None;
            let mut brace_depth: i32 = 0;
            let mut fn_brace_depth: i32 = 0;

            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if fn_start.is_none()
                    && (trimmed.contains("fn ")
                        && (trimmed.starts_with("fn ")
                            || trimmed.starts_with("pub fn ")
                            || trimmed.starts_with("async fn ")
                            || trimmed.starts_with("pub async fn ")
                            || trimmed.starts_with("unsafe fn ")
                            || trimmed.starts_with("pub unsafe fn ")))
                {
                    if let Some(name_start) = trimmed.find("fn ") {
                        let after = &trimmed[name_start + 3..];
                        let name: String = after
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        fn_start = Some((i + 1, name));
                        fn_brace_depth = brace_depth + 1;
                    }
                }
                for c in trimmed.chars() {
                    if c == '{' {
                        brace_depth += 1;
                    } else if c == '}' {
                        brace_depth -= 1;
                    }
                }
                if let Some((start, ref name)) = fn_start {
                    if brace_depth < fn_brace_depth {
                        let length = i + 1 - start;
                        if length > MAX_LINES {
                            findings.push(Finding::new(
                                self.id(),
                                Severity::Warning,
                                format!("function '{name}' is {length} lines (limit {MAX_LINES})"),
                                Location::at(rel.clone(), start as u32),
                                Category::Safety,
                                "break the function into smaller, focused functions to aid review and certification",
                            ));
                        }
                        fn_start = None;
                    }
                }
            }
        }
        Ok(findings)
    }
}

// ANA002 — nesting depth exceeds 5 levels (indentation heuristic).
struct RuleNestingDepth;
impl Rule for RuleNestingDepth {
    fn id(&self) -> &str {
        "ANA002"
    }
    fn description(&self) -> &str {
        "Deep nesting (>5 levels) increases complexity and review burden."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        const MAX_DEPTH: usize = 5;
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            let mut reported_lines = std::collections::HashSet::new();
            for (i, line) in content.lines().enumerate() {
                if line.trim().is_empty() || line.trim().starts_with("//") {
                    continue;
                }
                let spaces = line.len() - line.trim_start().len();
                let depth = spaces / 4;
                if depth > MAX_DEPTH && !reported_lines.contains(&(depth / 4)) {
                    reported_lines.insert(depth / 4);
                    findings.push(Finding::new(
                        self.id(),
                        Severity::Warning,
                        format!(
                            "nesting depth {depth} exceeds limit of {MAX_DEPTH} at this location"
                        ),
                        Location::at(rel.clone(), (i + 1) as u32),
                        Category::Safety,
                        "extract deeply nested blocks into helper functions",
                    ));
                    reported_lines.clear();
                }
            }
        }
        Ok(findings)
    }
}

// ANA003 — function with more than 7 parameters.
struct RuleTooManyParams;
impl Rule for RuleTooManyParams {
    fn id(&self) -> &str {
        "ANA003"
    }
    fn description(&self) -> &str {
        "Functions with more than 7 parameters are hard to call correctly and review."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        const MAX_PARAMS: usize = 7;
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if !(trimmed.starts_with("fn ")
                    || trimmed.starts_with("pub fn ")
                    || trimmed.starts_with("async fn ")
                    || trimmed.starts_with("pub async fn "))
                {
                    continue;
                }
                if let Some(start) = trimmed.find('(') {
                    if let Some(end) = trimmed[start..].find(')') {
                        let params_str = &trimmed[start + 1..start + end];
                        let count = if params_str.trim().is_empty() {
                            0
                        } else {
                            params_str
                                .split(',')
                                .filter(|p| !p.trim().is_empty())
                                .count()
                        };
                        if count > MAX_PARAMS {
                            let name_start = trimmed.find("fn ").unwrap_or(0) + 3;
                            let name: String = trimmed[name_start..]
                                .chars()
                                .take_while(|c| c.is_alphanumeric() || *c == '_')
                                .collect();
                            findings.push(Finding::new(
                                self.id(),
                                Severity::Warning,
                                format!(
                                    "function '{name}' has {count} parameters (limit {MAX_PARAMS})"
                                ),
                                Location::at(rel.clone(), (i + 1) as u32),
                                Category::Safety,
                                "group related parameters into a struct to reduce parameter count",
                            ));
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

// ANA004 — raw pointer dereference without //fusa:unsafe justification.
struct RuleRawPointerDeref;
impl Rule for RuleRawPointerDeref {
    fn id(&self) -> &str {
        "ANA004"
    }
    fn description(&self) -> &str {
        "Raw pointer dereference (*ptr) is memory-unsafe and requires explicit justification."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if (trimmed.contains("*ptr")
                    || trimmed.contains("*raw")
                    || trimmed.contains("*p ")
                    || trimmed.contains("*self.ptr")
                    || trimmed.contains("*buf"))
                    && !trimmed.starts_with("*")
                {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:unsafe") {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Warning,
                                "raw pointer dereference without //fusa:unsafe justification",
                                Location::at(rel.clone(), (i + 1) as u32),
                                Category::Safety,
                                "add '//fusa:unsafe <justification>' before the dereference",
                            )
                            .with_standard("cert-c", "EXP34-C"),
                        );
                    }
                }
            }
        }
        Ok(findings)
    }
}

// ANA005 — truncating integer cast (as u8/u16/i8/i16) without comment.
struct RuleIntegerTruncatingCast;
impl Rule for RuleIntegerTruncatingCast {
    fn id(&self) -> &str {
        "ANA005"
    }
    fn description(&self) -> &str {
        "Narrowing integer casts (as u8, as i8, as u16, as i16) silently truncate values."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let truncating: &[&str] = &[" as u8", " as i8", " as u16", " as i16"];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                for cast in truncating {
                    if trimmed.contains(cast) {
                        let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                        if !prev.starts_with("//") && !trimmed.contains("// safe:") {
                            findings.push(Finding::new(
                                self.id(),
                                Severity::Warning,
                                format!("truncating cast '{cast}' may silently discard bits"),
                                Location::at(rel.clone(), (i + 1) as u32),
                                Category::Safety,
                                "use try_from() / try_into() to detect overflow, or add '// safe: <range-proof>' comment",
                            ).with_standard("iso26262", "6.4.6"));
                            break;
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

// ANA006 — function with more than 3 explicit return points.
struct RuleMultipleReturnPoints;
impl Rule for RuleMultipleReturnPoints {
    fn id(&self) -> &str {
        "ANA006"
    }
    fn description(&self) -> &str {
        "Functions with many return points are harder to reason about for safety analysis."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        const MAX_RETURNS: usize = 3;
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            let mut fn_start: Option<(usize, String)> = None;
            let mut brace_depth: i32 = 0;
            let mut fn_brace_depth: i32 = 0;
            let mut return_count = 0usize;

            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if fn_start.is_none()
                    && (trimmed.starts_with("fn ")
                        || trimmed.starts_with("pub fn ")
                        || trimmed.starts_with("async fn ")
                        || trimmed.starts_with("pub async fn "))
                {
                    if let Some(name_start) = trimmed.find("fn ") {
                        let after = &trimmed[name_start + 3..];
                        let name: String = after
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        fn_start = Some((i + 1, name));
                        fn_brace_depth = brace_depth + 1;
                        return_count = 0;
                    }
                }
                if fn_start.is_some() && trimmed.starts_with("return ") {
                    return_count += 1;
                }
                for c in trimmed.chars() {
                    if c == '{' {
                        brace_depth += 1;
                    } else if c == '}' {
                        brace_depth -= 1;
                    }
                }
                if let Some((start, ref name)) = fn_start {
                    if brace_depth < fn_brace_depth {
                        if return_count > MAX_RETURNS {
                            findings.push(Finding::new(
                                self.id(),
                                Severity::Info,
                                format!("function '{name}' has {return_count} explicit return points (limit {MAX_RETURNS})"),
                                Location::at(rel.clone(), start as u32),
                                Category::Safety,
                                "restructure with a single exit point or use the ? operator to simplify control flow",
                            ));
                        }
                        fn_start = None;
                    }
                }
            }
        }
        Ok(findings)
    }
}
