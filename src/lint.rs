// Rust-specific LINT* rules: unsafe usage, unwrap, TODO, transmute, etc.

use crate::config::FusaConfig;
use crate::engine::{Registry, Rule};
use crate::types::{Category, Finding, Location, Severity};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn register_all(reg: &mut Registry) {
    reg.register(Box::new(RuleUnsafeBlock));
    reg.register(Box::new(RuleUnwrapUsage));
    reg.register(Box::new(RuleTodoFixme));
    reg.register(Box::new(RuleTransmuteUsage));
    reg.register(Box::new(RulePanicUsage));
    reg.register(Box::new(RuleMissingForbidUnsafe));
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
    for pat in patterns {
        if glob_match(pat, rel) {
            return true;
        }
    }
    false
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

fn glob_match(pattern: &str, path: &str) -> bool {
    if let Ok(g) = glob::Pattern::new(pattern) {
        return g.matches(path);
    }
    false
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_test_file(rel: &str) -> bool {
    rel.contains("/tests/") || rel.starts_with("tests/") || rel.ends_with("_test.rs")
}

// LINT001 — unsafe blocks without //fusa:unsafe annotation.
struct RuleUnsafeBlock;
impl Rule for RuleUnsafeBlock {
    fn id(&self) -> &str { "LINT001" }
    fn description(&self) -> &str {
        "unsafe blocks must be annotated with //fusa:unsafe on the preceding line."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            if is_test_file(&rel) {
                continue;
            }
            let content = std::fs::read_to_string(&file)
                .map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("unsafe {")
                    || trimmed.starts_with("unsafe{")
                    || trimmed.contains(" unsafe {")
                    || trimmed.contains(" unsafe{")
                {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:unsafe") {
                        findings.push(Finding::new(
                            self.id(), Severity::Error,
                            "unsafe block without //fusa:unsafe justification on the preceding line",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Safety,
                            "add '//fusa:unsafe <justification>' on the line before the unsafe block",
                        ).with_standard("iso26262", "6.4.6"));
                    }
                }
            }
        }
        Ok(findings)
    }
}

// LINT002 — .unwrap() in non-test, non-main code.
struct RuleUnwrapUsage;
impl Rule for RuleUnwrapUsage {
    fn id(&self) -> &str { "LINT002" }
    fn description(&self) -> &str {
        ".unwrap() panics on None/Err and should not appear in safety-critical code."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            if is_test_file(&rel) {
                continue;
            }
            let content = std::fs::read_to_string(&file)
                .map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                if line.contains(".unwrap()") && !line.trim_start().starts_with("//") {
                    let lineno = (i + 1) as u32;
                    findings.push(Finding::new(
                        self.id(), Severity::Warning,
                        ".unwrap() can panic; use ? or .expect(\"<reason>\") in library/safety code",
                        Location::at(rel.clone(), lineno),
                        Category::Safety,
                        "replace .unwrap() with ? or .expect(\"rationale\") to provide context on failure",
                    ));
                }
            }
        }
        Ok(findings)
    }
}

// LINT003 — TODO/FIXME comments in source.
struct RuleTodoFixme;
impl Rule for RuleTodoFixme {
    fn id(&self) -> &str { "LINT003" }
    fn description(&self) -> &str { "TODO and FIXME comments must be tracked as open issues." }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file)
                .map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let upper = line.to_uppercase();
                if (upper.contains("// TODO") || upper.contains("//TODO")
                    || upper.contains("// FIXME") || upper.contains("//FIXME"))
                    && !line.trim_start().starts_with("//fusa:")
                {
                    let label = if upper.contains("FIXME") { "FIXME" } else { "TODO" };
                    findings.push(Finding::new(
                        self.id(), Severity::Warning,
                        format!("{label} comment — unresolved work item in safety-critical code"),
                        Location::at(rel.clone(), (i + 1) as u32),
                        Category::Safety,
                        "resolve or convert to a tracked issue before final safety release",
                    ));
                }
            }
        }
        Ok(findings)
    }
}

// LINT004 — std::mem::transmute usage without justification.
struct RuleTransmuteUsage;
impl Rule for RuleTransmuteUsage {
    fn id(&self) -> &str { "LINT004" }
    fn description(&self) -> &str {
        "std::mem::transmute reinterprets memory and is highly unsafe."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file)
                .map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.contains("mem::transmute") && !line.trim_start().starts_with("//") {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:unsafe") {
                        findings.push(Finding::new(
                            self.id(), Severity::Error,
                            "std::mem::transmute used without //fusa:unsafe justification",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Safety,
                            "add '//fusa:unsafe <justification>' and document why transmute is safe here",
                        ).with_standard("cert-c", "EXP36-C"));
                    }
                }
            }
        }
        Ok(findings)
    }
}

// LINT005 — panic!() / unreachable!() in library code without justification.
struct RulePanicUsage;
impl Rule for RulePanicUsage {
    fn id(&self) -> &str { "LINT005" }
    fn description(&self) -> &str {
        "panic!() and unreachable!() abort the process and should be avoided in safety-critical library code."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            if is_test_file(&rel) {
                continue;
            }
            let content = std::fs::read_to_string(&file)
                .map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.contains("panic!(") || trimmed.contains("unreachable!(") {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:") {
                        let which = if trimmed.contains("panic!(") { "panic!()" } else { "unreachable!()" };
                        findings.push(Finding::new(
                            self.id(), Severity::Warning,
                            format!("{which} causes process abort — use Result or a recoverable error instead"),
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Safety,
                            "replace with a Result return or add '//fusa:panic <justification>' if intentional",
                        ));
                    }
                }
            }
        }
        Ok(findings)
    }
}

// LINT006 — safety-critical crates (ASIL set) should forbid unsafe_code at crate level.
struct RuleMissingForbidUnsafe;
impl Rule for RuleMissingForbidUnsafe {
    fn id(&self) -> &str { "LINT006" }
    fn description(&self) -> &str {
        "Crates with an ASIL/SIL integrity level should declare #![forbid(unsafe_code)] unless unsafe is explicitly justified."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        if cfg.asil.is_none() && cfg.sil.is_none() && cfg.dal.is_none() {
            return Ok(vec![]);
        }
        let lib = root.join("src").join("lib.rs");
        let main = root.join("src").join("main.rs");
        for path in &[&lib, &main] {
            if !path.exists() {
                continue;
            }
            let rel = rel_path(root, path);
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("read {rel}: {e}"))?;
            if content.contains("#![forbid(unsafe_code)]")
                || content.contains("#![deny(unsafe_code)]")
            {
                return Ok(vec![]);
            }
            return Ok(vec![Finding::new(
                self.id(), Severity::Warning,
                "crate has an integrity level but no #![forbid(unsafe_code)] declaration",
                Location::at(rel, 1),
                Category::Safety,
                "add #![forbid(unsafe_code)] at the top of lib.rs/main.rs, or document each unsafe usage with //fusa:unsafe",
            ).with_standard("iso26262", "6.4.6")]);
        }
        Ok(vec![])
    }
}
