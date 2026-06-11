// `rsfusa cyber` — cybersecurity static analysis (CYBER001–CYBER020). Writes cyber-report.json.

use crate::config::load;
use crate::cyber;
use crate::engine::Registry;
use crate::report::{render_json, render_text, CheckReport};
use crate::types::{EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::PathBuf;

pub const CYBER_FILE: &str = "cyber-report.json";

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let cfg = match load(&project_root.join(".fusa.json")) {
        Ok(c) => c,
        Err(crate::config::ConfigError::NotFound(_)) => crate::config::FusaConfig::new(
            project_root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("project"),
            "generic",
        ),
        Err(e) => {
            writeln!(stderr, "rsfusa cyber: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let mut reg = Registry::new();
    cyber::register_all(&mut reg);
    let result = reg.run(&project_root, &cfg);

    for e in &result.errors {
        writeln!(stderr, "rsfusa cyber: warning: {e}").ok();
    }

    let report = CheckReport::new(&project_root, result.findings, Some(&cfg));
    let has_errors = report
        .findings
        .iter()
        .any(|f| f.severity == crate::types::Severity::Error);

    let out_path = opts
        .output
        .unwrap_or_else(|| project_root.join(CYBER_FILE).to_string_lossy().into_owned());

    let mut file = match std::fs::File::create(&out_path) {
        Ok(f) => f,
        Err(e) => {
            writeln!(stderr, "rsfusa cyber: create {out_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    if let Err(e) = render_json(&mut file, &report) {
        writeln!(stderr, "rsfusa cyber: write: {e}").ok();
        return EXIT_RUNTIME;
    }

    if opts.format.as_deref() != Some("json") {
        let no_color = std::env::var("NO_COLOR").is_ok();
        render_text(stdout, &report, !no_color).ok();
    }

    writeln!(stdout, "Cybersecurity report written to {out_path}").ok();

    if has_errors {
        EXIT_GATE_FAIL
    } else {
        EXIT_OK
    }
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        format: None,
        output: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--format" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa cyber: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--format" => opts.format = Some(args[i].clone()),
                    "--output" => opts.output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--format=") {
                    opts.format = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.output = Some(v.to_string());
                } else {
                    writeln!(stderr, "rsfusa cyber: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
