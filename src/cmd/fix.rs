// `rsfusa fix` — show auto-fixable findings with remediation guidance.

use crate::config::load;
use crate::engine::default_registry;
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::PathBuf;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    let cfg = match load(&project_root.join(".fusa.json")) {
        Ok(c) => c,
        Err(crate::config::ConfigError::NotFound(_)) => crate::config::FusaConfig::new(
            project_root.file_name().and_then(|n| n.to_str()).unwrap_or("project"),
            "generic",
        ),
        Err(e) => {
            writeln!(stderr, "rsfusa fix: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let registry = default_registry();
    let result = registry.run(&project_root, &cfg);

    let fixable: Vec<_> = result.findings.iter()
        .filter(|f| !f.remediation.is_empty())
        .collect();

    if fixable.is_empty() {
        writeln!(stdout, "No fixable findings.").ok();
        return EXIT_OK;
    }

    if opts.format.as_deref() == Some("json") {
        use crate::types::{LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
        let json = serde_json::json!({
            "schemaVersion": SPEC_VERSION,
            "kind": "fix-report",
            "tool": TOOL_NAME,
            "toolVersion": VERSION,
            "language": LANGUAGE,
            "generatedAt": chrono::Utc::now().to_rfc3339(),
            "findings": fixable.iter().map(|f| serde_json::json!({
                "ruleId": f.rule_id,
                "severity": f.severity,
                "file": f.location.file,
                "line": f.location.line,
                "message": f.message,
                "remediation": f.remediation,
                "fingerprint": f.fingerprint,
            })).collect::<Vec<_>>(),
            "total": fixable.len(),
        });
        writeln!(stdout, "{}", serde_json::to_string_pretty(&json).unwrap()).ok();
    } else {
        writeln!(stdout, "Fixable findings: {}", fixable.len()).ok();
        writeln!(stdout).ok();
        for f in &fixable {
            writeln!(stdout, "[{}] {}:{}: {}", f.rule_id, f.location.file, f.location.line, f.message).ok();
            writeln!(stdout, "  Fix: {}", f.remediation).ok();
            writeln!(stdout, "  Fingerprint: {}", f.fingerprint).ok();
            writeln!(stdout).ok();
        }
    }

    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts { dir: None, format: None };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--format") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa fix: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--format" => opts.format = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--format=") { opts.format = Some(v.to_string()); }
                else {
                    writeln!(stderr, "rsfusa fix: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
