// CWE-mapped cybersecurity rules: CYBER001–CYBER020
//fusa:req REQ-CYBER001
//fusa:req REQ-CYBER002
//fusa:req REQ-CYBER003
//fusa:req REQ-CYBER004
//fusa:req REQ-CYBER005
//fusa:req REQ-CYBER006
//fusa:req REQ-CYBER007
//fusa:req REQ-CYBER008
//fusa:req REQ-CYBER009
//fusa:req REQ-CYBER010
//fusa:req REQ-CYBER011
//fusa:req REQ-CYBER012
//fusa:req REQ-CYBER013
//fusa:req REQ-CYBER014
//fusa:req REQ-CYBER015
//fusa:req REQ-CYBER016
//fusa:req REQ-CYBER017
//fusa:req REQ-CYBER018
//fusa:req REQ-CYBER019
//fusa:req REQ-CYBER020

use crate::config::FusaConfig;
use crate::engine::{Registry, Rule};
use crate::types::{Category, Finding, Location, Severity};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn register_all(reg: &mut Registry) {
    reg.register(Box::new(RuleHardcodedCredentials));
    reg.register(Box::new(RuleSqlInjection));
    reg.register(Box::new(RulePathTraversal));
    reg.register(Box::new(RuleWeakRandom));
    reg.register(Box::new(RuleUncheckedArithmetic));
    reg.register(Box::new(RuleCleartextHttp));
    reg.register(Box::new(RuleCommandInjection));
    reg.register(Box::new(RuleDeprecatedCrypto));
    reg.register(Box::new(RuleSensitiveLogging));
    reg.register(Box::new(RuleUnvalidatedDeserialize));
    reg.register(Box::new(RuleUncheckedSliceIndex));
    reg.register(Box::new(RuleUnboundedAlloc));
    reg.register(Box::new(RuleTlsBypass));
    reg.register(Box::new(RuleToctouCheck));
    reg.register(Box::new(RuleInsecureFilePerms));
    reg.register(Box::new(RuleEnvSecretExposure));
    reg.register(Box::new(RulePathFromUserInput));
    reg.register(Box::new(RuleManuallyDrop));
    reg.register(Box::new(RuleFormatWithExternal));
    reg.register(Box::new(RuleUncheckedFromUtf8));
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

// CYBER001 (CWE-798) — hardcoded credentials in string literals.
struct RuleHardcodedCredentials;
impl Rule for RuleHardcodedCredentials {
    fn id(&self) -> &str {
        "CYBER001"
    }
    fn description(&self) -> &str {
        "CWE-798: Hardcoded credentials expose secrets in source code."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let patterns: &[(&str, &str)] = &[
            ("password", "password"),
            ("passwd", "password"),
            ("api_key", "API key"),
            ("apikey", "API key"),
            ("secret_key", "secret key"),
            ("secret =", "secret"),
            ("private_key", "private key"),
            ("access_token", "token"),
            ("auth_token", "token"),
        ];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let lower = line.to_lowercase();
                if lower.trim_start().starts_with("//") {
                    continue;
                }
                for (pat, label) in patterns {
                    if lower.contains(pat) && (lower.contains("= \"") || lower.contains("=\"")) {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Error,
                                format!("possible hardcoded {label} in string literal"),
                                Location::at(rel.clone(), (i + 1) as u32),
                                Category::Security,
                                "load credentials from environment variables or a secrets manager",
                            )
                            .with_standard("iso21434", "11.4.3"),
                        );
                        break;
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER002 (CWE-89) — SQL query built by string concatenation or interpolation.
struct RuleSqlInjection;
impl Rule for RuleSqlInjection {
    fn id(&self) -> &str {
        "CYBER002"
    }
    fn description(&self) -> &str {
        "CWE-89: SQL query built from string concatenation risks injection."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let sql_kw: &[&str] = &[
            "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "CREATE ",
        ];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                let upper = trimmed.to_uppercase();
                let has_sql = sql_kw.iter().any(|kw| upper.contains(kw));
                let has_interp = trimmed.contains("format!(")
                    || trimmed.contains("+ &")
                    || trimmed.contains("+ \"");
                if has_sql && has_interp {
                    findings.push(Finding::new(
                        self.id(), Severity::Error,
                        "SQL query appears to be constructed by string interpolation",
                        Location::at(rel.clone(), (i + 1) as u32),
                        Category::Security,
                        "use parameterised queries (? placeholders) instead of string concatenation",
                    ).with_standard("cert-c", "STR02-C"));
                }
            }
        }
        Ok(findings)
    }
}

// CYBER003 (CWE-22) — path traversal: path constructed without canonicalization.
struct RulePathTraversal;
impl Rule for RulePathTraversal {
    fn id(&self) -> &str {
        "CYBER003"
    }
    fn description(&self) -> &str {
        "CWE-22: Paths constructed from external input without canonicalization risk traversal."
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
                if (trimmed.contains("PathBuf::from(") || trimmed.contains("Path::new("))
                    && (trimmed.contains("args[")
                        || trimmed.contains("input")
                        || trimmed.contains("request"))
                {
                    let range = i.saturating_sub(3)..=(i + 3).min(lines.len() - 1);
                    let nearby: String = lines[range].to_vec().join("\n");
                    if !nearby.contains("canonicalize") && !nearby.contains("//fusa:safe") {
                        findings.push(Finding::new(
                            self.id(), Severity::Warning,
                            "path constructed from potentially user-controlled input without canonicalization",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "call .canonicalize() and verify the result is within the allowed root",
                        ).with_standard("cert-c", "FIO02-C"));
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER004 (CWE-330) — non-cryptographic RNG used without `//fusa:safe`.
struct RuleWeakRandom;
impl Rule for RuleWeakRandom {
    fn id(&self) -> &str {
        "CYBER004"
    }
    fn description(&self) -> &str {
        "CWE-330: Non-cryptographic RNG is predictable and unsuitable for security tokens."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let weak: &[&str] = &[
            "rand::random()",
            "thread_rng()",
            "SmallRng",
            "StdRng::seed_from_u64",
        ];
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
                if weak.iter().any(|p| trimmed.contains(p)) {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:safe") && !prev.contains("// not security") {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Warning,
                                "non-cryptographic RNG — do not use for security-sensitive values",
                                Location::at(rel.clone(), (i + 1) as u32),
                                Category::Security,
                                "use OsRng or the rand::rngs::OsRng for cryptographic randomness",
                            )
                            .with_standard("iso21434", "11.4.3"),
                        );
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER005 (CWE-190) — unchecked arithmetic without .checked_* variant.
struct RuleUncheckedArithmetic;
impl Rule for RuleUncheckedArithmetic {
    fn id(&self) -> &str {
        "CYBER005"
    }
    fn description(&self) -> &str {
        "CWE-190: Integer overflow in debug builds panics; in release builds wraps silently."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            if rel.contains("test") {
                continue;
            }
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                // look for unsafe{ counter } length arithmetic patterns
                if (trimmed.contains("len()") || trimmed.contains("count()"))
                    && (trimmed.contains(" + ") || trimmed.contains(" * "))
                    && !trimmed.contains("checked_")
                    && !trimmed.contains("saturating_")
                    && !trimmed.contains("wrapping_")
                {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:safe") {
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Info,
                                "arithmetic on length/count values without overflow check",
                                Location::at(rel.clone(), (i + 1) as u32),
                                Category::Security,
                                "use .checked_add() / .checked_mul() to prevent integer overflow",
                            )
                            .with_standard("cert-c", "INT30-C"),
                        );
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER006 (CWE-319) — cleartext HTTP URL literals.
struct RuleCleartextHttp;
impl Rule for RuleCleartextHttp {
    fn id(&self) -> &str {
        "CYBER006"
    }
    fn description(&self) -> &str {
        "CWE-319: Cleartext HTTP transmits data without encryption."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.contains("\"http://")
                    && !trimmed.contains("\"https://")
                    && !trimmed.contains("localhost")
                    && !trimmed.contains("127.0.0.1")
                    && !trimmed.contains("//fusa:safe")
                {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Warning,
                            "HTTP URL used — data transmitted in cleartext",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "use HTTPS to encrypt data in transit",
                        )
                        .with_standard("unece-r155", "7.3.3"),
                    );
                }
            }
        }
        Ok(findings)
    }
}

// CYBER007 (CWE-78) — Command::new() with string concatenation risk.
struct RuleCommandInjection;
impl Rule for RuleCommandInjection {
    fn id(&self) -> &str {
        "CYBER007"
    }
    fn description(&self) -> &str {
        "CWE-78: Constructing shell commands from variables risks OS command injection."
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
                if trimmed.contains("Command::new(") && !trimmed.contains("\"") {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:safe") {
                        findings.push(Finding::new(
                            self.id(), Severity::Warning,
                            "Command::new() called with a variable argument — verify no user-controlled input reaches here",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "validate and sanitise all arguments passed to Command::new(); never pass shell-interpreted strings",
                        ).with_standard("cert-c", "ENV33-C"));
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER008 (CWE-327) — deprecated/weak cryptographic algorithm.
struct RuleDeprecatedCrypto;
impl Rule for RuleDeprecatedCrypto {
    fn id(&self) -> &str {
        "CYBER008"
    }
    fn description(&self) -> &str {
        "CWE-327: MD5 and SHA-1 are cryptographically broken."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let weak: &[(&str, &str)] = &[
            ("md5", "MD5"),
            ("sha1", "SHA-1"),
            ("des::", "DES"),
            ("rc4::", "RC4"),
        ];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let lower = line.to_lowercase();
                if lower.trim_start().starts_with("//") {
                    continue;
                }
                for (pat, name) in weak {
                    if lower.contains(pat)
                        && (lower.contains("use ") || lower.contains("extern crate"))
                    {
                        findings.push(Finding::new(
                            self.id(), Severity::Error,
                            format!("use of deprecated/weak cryptographic algorithm: {name}"),
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "use SHA-256 or stronger (sha2 crate) for hashing; use AES-GCM for encryption",
                        ).with_standard("iso21434", "11.4.3"));
                        break;
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER009 (CWE-532) — logging of potentially sensitive field values.
struct RuleSensitiveLogging;
impl Rule for RuleSensitiveLogging {
    fn id(&self) -> &str {
        "CYBER009"
    }
    fn description(&self) -> &str {
        "CWE-532: Logging sensitive data (passwords, tokens, keys) leaks credentials."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let sensitive: &[&str] = &[
            "password",
            "passwd",
            "secret",
            "api_key",
            "token",
            "private_key",
            "credential",
        ];
        let log_macros: &[&str] = &[
            "println!",
            "eprintln!",
            "log::info!",
            "log::debug!",
            "log::warn!",
            "log::error!",
            "tracing::info!",
            "tracing::debug!",
        ];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let lower = line.to_lowercase();
                if lower.trim_start().starts_with("//") {
                    continue;
                }
                let has_log = log_macros.iter().any(|m| lower.contains(m));
                let has_sensitive = sensitive.iter().any(|s| lower.contains(s));
                if has_log && has_sensitive && !lower.contains("//fusa:safe") {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Warning,
                            "possible logging of sensitive field (password/token/key)",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "avoid logging sensitive values; redact or mask before logging",
                        )
                        .with_standard("iso21434", "11.4.3"),
                    );
                }
            }
        }
        Ok(findings)
    }
}

// CYBER010 (CWE-502) — deserializing untrusted input without explicit validation.
struct RuleUnvalidatedDeserialize;
impl Rule for RuleUnvalidatedDeserialize {
    fn id(&self) -> &str {
        "CYBER010"
    }
    fn description(&self) -> &str {
        "CWE-502: Deserialising untrusted data without schema validation risks unexpected behaviour."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let patterns: &[&str] = &[
            "serde_json::from_reader(",
            "serde_json::from_slice(",
            "serde_json::from_str(",
            "bincode::deserialize(",
            "toml::from_str(",
        ];
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
                if patterns.iter().any(|p| trimmed.contains(p)) {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:safe") && !prev.contains("// validated") {
                        findings.push(Finding::new(
                            self.id(), Severity::Info,
                            "deserialisation of external data — ensure input is size-bounded and validated",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "validate structure and field bounds after deserialisation before use",
                        ).with_standard("cert-c", "STR38-C"));
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER011 (CWE-125) — unchecked array/slice indexing.
struct RuleUncheckedSliceIndex;
impl Rule for RuleUncheckedSliceIndex {
    fn id(&self) -> &str {
        "CYBER011"
    }
    fn description(&self) -> &str {
        "CWE-125: Direct slice indexing panics on out-of-bounds in debug; UB in unsafe."
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
                // Pattern: identifier[variable] where variable is not a literal
                if let Some(bracket_pos) = trimmed.find('[') {
                    let before = &trimmed[..bracket_pos];
                    if let Some(close) = trimmed[bracket_pos..].find(']') {
                        let index = &trimmed[bracket_pos + 1..bracket_pos + close];
                        let is_literal = index.trim().parse::<usize>().is_ok();
                        let is_range = index.contains("..");
                        if !is_literal
                            && !is_range
                            && !before.trim_end().ends_with("if")
                            && !before.trim_end().ends_with("while")
                            && !trimmed.contains(".get(")
                            && !trimmed.contains("//fusa:safe")
                            && before
                                .chars()
                                .last()
                                .map(|c| c.is_alphanumeric() || c == '_')
                                .unwrap_or(false)
                        {
                            let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                            if !prev.contains("//fusa:safe") {
                                findings.push(Finding::new(
                                    self.id(), Severity::Info,
                                    "direct slice indexing with a variable — consider .get() for bounds-safe access",
                                    Location::at(rel.clone(), (i + 1) as u32),
                                    Category::Security,
                                    "use .get(index) which returns Option instead of panicking on out-of-bounds",
                                ).with_standard("cert-c", "ARR30-C"));
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER012 (CWE-400) — unbounded allocation (Vec with user-controlled capacity).
struct RuleUnboundedAlloc;
impl Rule for RuleUnboundedAlloc {
    fn id(&self) -> &str {
        "CYBER012"
    }
    fn description(&self) -> &str {
        "CWE-400: Allocating with user-controlled size without a cap risks resource exhaustion."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let patterns: &[&str] = &[
            "Vec::with_capacity(",
            "String::with_capacity(",
            "vec![0; ",
            "vec![Default::default(); ",
        ];
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
                for pat in patterns {
                    if trimmed.contains(pat) {
                        // Check if the argument is a variable (not a literal)
                        if let Some(start) = trimmed.find(pat) {
                            let arg_start = start + pat.len();
                            if let Some(end) = trimmed[arg_start..].find(')') {
                                let arg = trimmed[arg_start..arg_start + end].trim();
                                let is_literal = arg.parse::<usize>().is_ok();
                                if !is_literal
                                    && !trimmed.contains("MAX")
                                    && !trimmed.contains("max")
                                    && !trimmed.contains("//fusa:safe")
                                {
                                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                                    if !prev.contains("//fusa:safe") {
                                        findings.push(Finding::new(
                                            self.id(), Severity::Warning,
                                            "allocation with non-constant size — ensure capacity is bounded",
                                            Location::at(rel.clone(), (i + 1) as u32),
                                            Category::Security,
                                            "cap allocations with a constant maximum (e.g., .min(MAX_CAPACITY))",
                                        ).with_standard("cert-c", "MEM35-C"));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER013 (CWE-295) — TLS certificate verification bypass.
struct RuleTlsBypass;
impl Rule for RuleTlsBypass {
    fn id(&self) -> &str {
        "CYBER013"
    }
    fn description(&self) -> &str {
        "CWE-295: Disabling TLS certificate verification enables MITM attacks."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let patterns: &[&str] = &[
            "danger_accept_invalid_certs",
            "accept_invalid_certs",
            "verify_peer(false)",
            "danger_accept_invalid_hostnames",
            "disable_built_in_roots",
        ];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if patterns.iter().any(|p| trimmed.contains(p)) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Error,
                            "TLS certificate verification disabled — vulnerable to MITM",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "enable TLS certificate verification; never disable in production code",
                        )
                        .with_standard("unece-r155", "7.3.3"),
                    );
                }
            }
        }
        Ok(findings)
    }
}

// CYBER014 (CWE-367) — TOCTOU: filesystem check followed by use.
struct RuleToctouCheck;
impl Rule for RuleToctouCheck {
    fn id(&self) -> &str {
        "CYBER014"
    }
    fn description(&self) -> &str {
        "CWE-367: Checking a resource and then using it introduces a TOCTOU race."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let check_fns: &[&str] = &[".exists()", ".metadata()", "fs::metadata("];
        let use_fns: &[&str] = &["File::open(", "File::create(", "fs::read(", "fs::write("];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            let lines: Vec<&str> = content.lines().collect();
            for i in 0..lines.len().saturating_sub(5) {
                let check_line = lines[i].trim();
                if check_fns.iter().any(|p| check_line.contains(p)) {
                    for use_line in lines[i + 1..=(i + 5).min(lines.len() - 1)].iter() {
                        let use_line = use_line.trim();
                        if use_fns.iter().any(|p| use_line.contains(p))
                            && !check_line.contains("//fusa:safe")
                        {
                            findings.push(Finding::new(
                                self.id(), Severity::Warning,
                                "filesystem check followed by use within 5 lines — possible TOCTOU",
                                Location::at(rel.clone(), (i + 1) as u32),
                                Category::Security,
                                "open the file directly and handle errors; avoid separate existence check",
                            ).with_standard("cert-c", "FIO45-C"));
                            break;
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER015 (CWE-732) — world-writable file permission mask.
struct RuleInsecureFilePerms;
impl Rule for RuleInsecureFilePerms {
    fn id(&self) -> &str {
        "CYBER015"
    }
    fn description(&self) -> &str {
        "CWE-732: World-writable file permissions allow unauthorised modification."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let patterns: &[&str] = &["0o777", "0o666", "0o776", "0o667"];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if patterns.iter().any(|p| trimmed.contains(p)) {
                    findings.push(
                        Finding::new(
                            self.id(),
                            Severity::Warning,
                            "world-writable/world-readable file permission mask",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "use restrictive permissions (e.g., 0o600 for user-only read/write)",
                        )
                        .with_standard("cert-c", "FIO06-C"),
                    );
                }
            }
        }
        Ok(findings)
    }
}

// CYBER016 (CWE-526) — sensitive environment variables accessed insecurely.
struct RuleEnvSecretExposure;
impl Rule for RuleEnvSecretExposure {
    fn id(&self) -> &str {
        "CYBER016"
    }
    fn description(&self) -> &str {
        "CWE-526: Environment variables containing credentials may be logged or inspected."
    }
    fn run(&self, root: &Path, cfg: &FusaConfig) -> Result<Vec<Finding>, String> {
        let sensitive: &[&str] = &[
            "PASSWORD",
            "SECRET",
            "TOKEN",
            "API_KEY",
            "PRIVATE_KEY",
            "AUTH",
        ];
        let mut findings = Vec::new();
        for file in rust_sources(root, cfg) {
            let rel = rel_path(root, &file);
            let content = std::fs::read_to_string(&file).map_err(|e| format!("read {rel}: {e}"))?;
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if (trimmed.contains("env::var(") || trimmed.contains("env::var_os("))
                    && sensitive.iter().any(|s| trimmed.to_uppercase().contains(s))
                {
                    findings.push(Finding::new(
                        self.id(), Severity::Info,
                        "sensitive environment variable accessed — avoid logging or propagating this value",
                        Location::at(rel.clone(), (i + 1) as u32),
                        Category::Security,
                        "treat the value as a secret; clear it from memory when no longer needed",
                    ).with_standard("iso21434", "11.4.3"));
                }
            }
        }
        Ok(findings)
    }
}

// CYBER017 (CWE-22 variant) — path join with a string variable.
struct RulePathFromUserInput;
impl Rule for RulePathFromUserInput {
    fn id(&self) -> &str {
        "CYBER017"
    }
    fn description(&self) -> &str {
        "CWE-22: Path built by joining with a variable may enable directory traversal."
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
                if trimmed.contains(".join(") && !trimmed.contains(".join(\"") {
                    let range = i.saturating_sub(3)..=(i + 3).min(lines.len() - 1);
                    let nearby: String = lines[range].to_vec().join(" ");
                    if !nearby.contains("canonicalize") && !nearby.contains("//fusa:safe") {
                        let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                        if !prev.contains("//fusa:safe") {
                            findings.push(Finding::new(
                                self.id(), Severity::Info,
                                "path .join() with variable argument — verify no .. traversal is possible",
                                Location::at(rel.clone(), (i + 1) as u32),
                                Category::Security,
                                "call .canonicalize() after joining and verify path is within allowed root",
                            ).with_standard("cert-c", "FIO02-C"));
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER018 (CWE-415) — ManuallyDrop used without explicit justification.
struct RuleManuallyDrop;
impl Rule for RuleManuallyDrop {
    fn id(&self) -> &str {
        "CYBER018"
    }
    fn description(&self) -> &str {
        "CWE-415: ManuallyDrop bypasses Rust's automatic memory management, risking double-free."
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
                if trimmed.contains("ManuallyDrop") {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:unsafe") {
                        findings.push(Finding::new(
                            self.id(), Severity::Warning,
                            "ManuallyDrop used without //fusa:unsafe justification",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "document why ManuallyDrop is necessary and add //fusa:unsafe justification",
                        ).with_standard("cert-c", "MEM31-C"));
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER019 (CWE-134) — format string with potentially external input.
struct RuleFormatWithExternal;
impl Rule for RuleFormatWithExternal {
    fn id(&self) -> &str {
        "CYBER019"
    }
    fn description(&self) -> &str {
        "CWE-134: Using external input as a format string template risks injection."
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
                // format!() / println!() where first arg is a variable not a string literal
                for mac in &[
                    "format!(",
                    "println!(",
                    "eprintln!(",
                    "writeln!(",
                    "write!(",
                ] {
                    if trimmed.contains(mac) {
                        if let Some(pos) = trimmed.find(mac) {
                            let after = trimmed[pos + mac.len()..].trim_start();
                            // If first arg doesn't start with a quote, it's a variable
                            if !after.starts_with('"')
                                && !after.starts_with('\'')
                                && !after.starts_with("std::")
                                && after.len() > 1
                            {
                                let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                                if !prev.contains("//fusa:safe") {
                                    findings.push(Finding::new(
                                        self.id(), Severity::Info,
                                        format!("{mac} called with non-literal first argument — ensure it is not user-controlled"),
                                        Location::at(rel.clone(), (i + 1) as u32),
                                        Category::Security,
                                        "use a string literal as the format template; pass dynamic content as arguments",
                                    ).with_standard("cert-c", "FIO30-C"));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

// CYBER020 (CWE-20) — from_utf8 / from_utf8_unchecked without validation.
struct RuleUncheckedFromUtf8;
impl Rule for RuleUncheckedFromUtf8 {
    fn id(&self) -> &str {
        "CYBER020"
    }
    fn description(&self) -> &str {
        "CWE-20: from_utf8_unchecked skips UTF-8 validation and is UB on invalid input."
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
                if trimmed.contains("from_utf8_unchecked") {
                    let prev = if i > 0 { lines[i - 1].trim() } else { "" };
                    if !prev.contains("//fusa:unsafe") {
                        findings.push(Finding::new(
                            self.id(), Severity::Error,
                            "from_utf8_unchecked invoked without //fusa:unsafe justification",
                            Location::at(rel.clone(), (i + 1) as u32),
                            Category::Security,
                            "use std::str::from_utf8() which returns Result; only use unchecked variant with proof of valid UTF-8",
                        ).with_standard("cert-c", "STR38-C"));
                    }
                }
            }
        }
        Ok(findings)
    }
}
