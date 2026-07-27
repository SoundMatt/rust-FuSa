// `rsfusa analyze` — run only ANA* static analysis rules.
//fusa:req REQ-ANA007

use crate::analyze;
use crate::config::load;
use crate::engine::Registry;
use crate::report::{render_html, render_json, render_sarif, render_text, CheckReport};
use crate::types::{EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::PathBuf;

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
            writeln!(stderr, "rsfusa analyze: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let mut reg = Registry::new();
    analyze::register_all(&mut reg);
    let result = reg.run(&project_root, &cfg);

    for e in &result.errors {
        writeln!(stderr, "rsfusa analyze: warning: {e}").ok();
    }

    let report = CheckReport::new(&project_root, result.findings, Some(&cfg));

    let no_color = opts.no_color
        || opts.format.as_deref() == Some("json")
        || opts.format.as_deref() == Some("sarif")
        || std::env::var("NO_COLOR").is_ok();

    let write_result = match opts.output.as_deref() {
        Some(path) => {
            let mut f = match std::fs::File::create(path) {
                Ok(f) => f,
                Err(e) => {
                    writeln!(stderr, "rsfusa analyze: create output {path}: {e}").ok();
                    return EXIT_RUNTIME;
                }
            };
            render_to(&mut f, &report, opts.format.as_deref(), false)
        }
        None => render_to(stdout, &report, opts.format.as_deref(), !no_color),
    };

    if let Err(e) = write_result {
        writeln!(stderr, "rsfusa analyze: render: {e}").ok();
        return EXIT_RUNTIME;
    }

    let has_errors = report
        .findings
        .iter()
        .any(|f| f.severity == crate::types::Severity::Error);
    if has_errors {
        return EXIT_GATE_FAIL;
    }
    EXIT_OK
}

fn render_to<W: Write + ?Sized>(
    w: &mut W,
    report: &CheckReport,
    format: Option<&str>,
    color: bool,
) -> std::io::Result<()> {
    match format {
        Some("json") => render_json(w, report),
        Some("sarif") => render_sarif(w, report),
        Some("html") => render_html(w, report),
        _ => render_text(w, report, color),
    }
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
    no_color: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        format: None,
        output: None,
        no_color: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--no-color" => opts.no_color = true,
            flag @ ("--dir" | "--format" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa analyze: {flag} requires an argument").ok();
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
                    writeln!(stderr, "rsfusa analyze: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
