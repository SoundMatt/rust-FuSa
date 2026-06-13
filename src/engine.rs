// Rule execution engine — trait-based, mirrors go-FuSa's engine package.
//fusa:req REQ-ENG001
//fusa:req REQ-ENG002
//fusa:req REQ-ENG003
//fusa:req REQ-ENG004
//fusa:req REQ-ENG005
//fusa:req REQ-ENG006
//fusa:req REQ-ENG007
//fusa:req REQ-RUNTIME001
//fusa:req REQ-RUNTIME002
//fusa:req REQ-RUNTIME003

use crate::config::FusaConfig;
use crate::types::Finding;
use std::path::Path;

pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn description(&self) -> &str;
    fn run(&self, project_root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String>;
}

pub struct Registry {
    rules: Vec<Box<dyn Rule>>,
}

impl Registry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn register(&mut self, rule: Box<dyn Rule>) {
        assert!(
            !self.rules.iter().any(|r| r.id() == rule.id()),
            "duplicate rule id: {}",
            rule.id()
        );
        self.rules.push(rule);
    }

    pub fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    pub fn run(&self, project_root: &Path, cfg: &FusaConfig) -> RunResult {
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        let mut sorted: Vec<_> = self.rules.iter().collect();
        sorted.sort_by_key(|r| r.id());

        for rule in sorted {
            match rule.run(project_root, cfg) {
                Ok(mut fs) => findings.append(&mut fs),
                Err(e) => errors.push(format!("{}: {e}", rule.id())),
            }
        }

        RunResult { findings, errors }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RunResult {
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
}

impl RunResult {
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.severity, crate::types::Severity::Error))
    }

    pub fn has_warnings(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.severity, crate::types::Severity::Warning))
    }
}

pub fn default_registry() -> Registry {
    let mut reg = Registry::new();
    crate::rules::register_all(&mut reg);
    crate::lint::register_all(&mut reg);
    crate::analyze::register_all(&mut reg);
    crate::cyber::register_all(&mut reg);
    reg
}
