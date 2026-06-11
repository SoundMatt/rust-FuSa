// Built-in FUSA* structural safety rules for Rust projects.
// Analogous to go-FuSa's engine/rules.go.
//fusa:req REQ-FUSA001
//fusa:req REQ-FUSA002
//fusa:req REQ-FUSA003
//fusa:req REQ-FUSA004
//fusa:req REQ-FUSA005

use crate::config::FusaConfig;
use crate::engine::{Registry, Rule};
use crate::types::{Category, Finding, Location, Severity};
use std::path::Path;

pub fn register_all(reg: &mut Registry) {
    reg.register(Box::new(RuleConfigPresent));
    reg.register(Box::new(RuleCargoTomlPresent));
    reg.register(Box::new(RuleLicensePresent));
    reg.register(Box::new(RuleReadmePresent));
    reg.register(Box::new(RuleCiPresent));
    reg.register(Box::new(RuleReqsPresent));
    reg.register(Box::new(RuleNoDuplicateReqs));
}

// FUSA001 — .fusa.json must be present.
struct RuleConfigPresent;
impl Rule for RuleConfigPresent {
    fn id(&self) -> &str { "FUSA001" }
    fn description(&self) -> &str { "Project must have a .fusa.json configuration file." }
    fn run(&self, root: &Path, _cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        if !root.join(".fusa.json").exists() {
            return Ok(vec![Finding::new(
                self.id(), Severity::Error,
                "no .fusa.json found in project root",
                Location::new(".fusa.json"),
                Category::Config,
                "run 'rsfusa init' to create a starter configuration",
            )]);
        }
        Ok(vec![])
    }
}

// FUSA002 — Cargo.toml must be present.
struct RuleCargoTomlPresent;
impl Rule for RuleCargoTomlPresent {
    fn id(&self) -> &str { "FUSA002" }
    fn description(&self) -> &str { "Project must be a Rust crate or workspace (Cargo.toml present)." }
    fn run(&self, root: &Path, _cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        if !root.join("Cargo.toml").exists() {
            return Ok(vec![Finding::new(
                self.id(), Severity::Error,
                "no Cargo.toml found — project must be a Rust crate or workspace",
                Location::new("Cargo.toml"),
                Category::Config,
                "run 'cargo init' or 'cargo new' to initialise the crate",
            )]);
        }
        Ok(vec![])
    }
}

// FUSA003 — LICENSE file must be present.
struct RuleLicensePresent;
impl Rule for RuleLicensePresent {
    fn id(&self) -> &str { "FUSA003" }
    fn description(&self) -> &str { "Project must have a LICENSE file for IP clarity in safety cases." }
    fn run(&self, root: &Path, _cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        for name in &["LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE"] {
            if root.join(name).exists() {
                return Ok(vec![]);
            }
        }
        Ok(vec![Finding::new(
            self.id(), Severity::Warning,
            "no LICENSE file found",
            Location::new("LICENSE"),
            Category::Config,
            "add a LICENSE file to clarify IP ownership for assessors",
        )])
    }
}

// FUSA004 — README must be present.
struct RuleReadmePresent;
impl Rule for RuleReadmePresent {
    fn id(&self) -> &str { "FUSA004" }
    fn description(&self) -> &str { "Project must have a README for assessors and integrators." }
    fn run(&self, root: &Path, _cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        for name in &["README.md", "README.txt", "README.rst", "README"] {
            if root.join(name).exists() {
                return Ok(vec![]);
            }
        }
        Ok(vec![Finding::new(
            self.id(), Severity::Warning,
            "no README file found",
            Location::new("README.md"),
            Category::Config,
            "add a README.md describing the project purpose and safety context",
        )])
    }
}

// FUSA005 — CI configuration must be present.
struct RuleCiPresent;
impl Rule for RuleCiPresent {
    fn id(&self) -> &str { "FUSA005" }
    fn description(&self) -> &str { "Project must have a CI configuration for automated verification." }
    fn run(&self, root: &Path, _cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let candidates = [
            root.join(".github").join("workflows"),
            root.join(".gitlab-ci.yml"),
            root.join(".circleci").join("config.yml"),
            root.join("Jenkinsfile"),
        ];
        for c in &candidates {
            if c.exists() {
                return Ok(vec![]);
            }
        }
        Ok(vec![Finding::new(
            self.id(), Severity::Warning,
            "no CI configuration found (checked .github/workflows, .gitlab-ci.yml, .circleci, Jenkinsfile)",
            Location::new(".github/workflows"),
            Category::Config,
            "add a CI pipeline to run rsfusa check on every commit",
        )])
    }
}

// FUSA006 — .fusa-reqs.json should be present.
struct RuleReqsPresent;
impl Rule for RuleReqsPresent {
    fn id(&self) -> &str { "FUSA006" }
    fn description(&self) -> &str { "Project should have a .fusa-reqs.json requirements registry." }
    fn run(&self, root: &Path, _cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        if !root.join(".fusa-reqs.json").exists() {
            return Ok(vec![Finding::new(
                self.id(), Severity::Warning,
                "no .fusa-reqs.json found — requirements traceability not possible",
                Location::new(".fusa-reqs.json"),
                Category::Requirement,
                "run 'rsfusa init' or create .fusa-reqs.json with {\"requirements\":[]}",
            )]);
        }
        Ok(vec![])
    }
}

// FUSA007 — .fusa-reqs.json must not have duplicate requirement ids.
struct RuleNoDuplicateReqs;
impl Rule for RuleNoDuplicateReqs {
    fn id(&self) -> &str { "FUSA007" }
    fn description(&self) -> &str { "Requirement IDs in .fusa-reqs.json must be unique (§1.2.2)." }
    fn run(&self, root: &Path, _cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let path = root.join(".fusa-reqs.json");
        if !path.exists() {
            return Ok(vec![]);
        }
        let reqs = crate::config::load_reqs(&path)
            .map_err(|e| format!("FUSA007: {e}"))?;
        let dups = crate::config::check_duplicate_ids(&reqs);
        if dups.is_empty() {
            return Ok(vec![]);
        }
        Ok(dups.into_iter().map(|id| Finding::new(
            self.id(), Severity::Error,
            format!("duplicate requirement id: {id}"),
            Location::new(".fusa-reqs.json"),
            Category::Requirement,
            "each requirement id must be unique within .fusa-reqs.json",
        )).collect())
    }
}
