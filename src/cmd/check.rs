use crate::config::{load, load_dispositions, DispositionEntry};
use crate::engine::default_registry;
use crate::report::{render_html, render_json, render_sarif, render_text, CheckReport};
use crate::types::{Disposition, Finding, Severity, EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::PathBuf;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_inner(args, stdout, stderr, false)
}

pub fn run_report(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    // `report` is `check` with forced exit 0; --strict is a usage error.
    if args.iter().any(|a| a == "--strict") {
        writeln!(stderr, "rsfusa report: --strict is not valid on report (always exits 0)").ok();
        return EXIT_USAGE;
    }
    let code = run_inner(args, stdout, stderr, false);
    if code == EXIT_GATE_FAIL { EXIT_OK } else { code }
}

fn run_inner(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write, _report_mode: bool) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    let cfg = match load(&project_root.join(".fusa.json")) {
        Ok(c) => c,
        Err(crate::config::ConfigError::NotFound(_)) => {
            crate::config::FusaConfig::new(
                project_root.file_name().and_then(|n| n.to_str()).unwrap_or("project"),
                "generic",
            )
        }
        Err(e) => {
            writeln!(stderr, "rsfusa check: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let registry = default_registry();
    let result = registry.run(&project_root, &cfg);

    for e in &result.errors {
        writeln!(stderr, "rsfusa check: warning: {e}").ok();
    }

    // Apply dispositions.
    let disp_path = project_root.join(".fusa-dispositions.json");
    let dispositions = load_dispositions(&disp_path);
    let mut findings = apply_dispositions(result.findings, dispositions.as_ref().map(|d| d.dispositions.as_slice()));

    // Orphaned accepted/deferred warnings.
    if let Some(disp) = &dispositions {
        for entry in &disp.dispositions {
            let is_waiver = entry.status == "accepted" || entry.status == "deferred";
            if !is_waiver {
                continue;
            }
            let matched = findings.iter().any(|f| matches_disposition(f, entry));
            if !matched {
                findings.push(Finding::new(
                    "CFG001",
                    Severity::Warning,
                    format!(
                        "orphaned {} disposition: no matching finding for rule {:?} file {:?}",
                        entry.status,
                        entry.rule_id,
                        entry.file
                    ),
                    crate::types::Location::new(".fusa-dispositions.json"),
                    crate::types::Category::Config,
                    "remove or update the stale disposition entry",
                ));
            }
        }
    }

    let report = CheckReport::new(&project_root, findings, Some(&cfg));

    let no_color = opts.no_color
        || opts.format.as_deref() == Some("json")
        || opts.format.as_deref() == Some("sarif")
        || std::env::var("NO_COLOR").is_ok();

    let write_result = match opts.output.as_deref() {
        Some(path) => {
            let mut f = match std::fs::File::create(path) {
                Ok(f) => f,
                Err(e) => {
                    writeln!(stderr, "rsfusa check: create output {path}: {e}").ok();
                    return EXIT_RUNTIME;
                }
            };
            render_to(&mut f, &report, opts.format.as_deref(), false)
        }
        None => render_to(stdout, &report, opts.format.as_deref(), !no_color),
    };

    if let Err(e) = write_result {
        writeln!(stderr, "rsfusa check: render: {e}").ok();
        return EXIT_RUNTIME;
    }

    let has_open_errors = report.findings.iter().any(|f| {
        f.severity == Severity::Error
            && !matches!(f.disposition, Some(Disposition::Accepted) | Some(Disposition::Deferred))
    });
    let has_open_warnings = report.findings.iter().any(|f| {
        f.severity == Severity::Warning
            && !matches!(f.disposition, Some(Disposition::Accepted) | Some(Disposition::Deferred))
    });

    if has_open_errors {
        return EXIT_GATE_FAIL;
    }
    if opts.strict && has_open_warnings {
        return EXIT_GATE_FAIL;
    }
    EXIT_OK
}

fn render_to<W: Write + ?Sized>(w: &mut W, report: &CheckReport, format: Option<&str>, color: bool) -> std::io::Result<()> {
    match format {
        Some("json") => render_json(w, report),
        Some("sarif") => render_sarif(w, report),
        Some("html") => render_html(w, report),
        _ => render_text(w, report, color),
    }
}

fn apply_dispositions(
    mut findings: Vec<Finding>,
    dispositions: Option<&[DispositionEntry]>,
) -> Vec<Finding> {
    let Some(entries) = dispositions else {
        return findings;
    };
    for f in &mut findings {
        for entry in entries {
            if matches_disposition(f, entry) {
                f.disposition = match entry.status.as_str() {
                    "accepted" => Some(Disposition::Accepted),
                    "deferred" => Some(Disposition::Deferred),
                    "rejected" => Some(Disposition::Rejected),
                    _ => None,
                };
                break;
            }
        }
    }
    findings
}

fn matches_disposition(f: &Finding, entry: &DispositionEntry) -> bool {
    // Prefer fingerprint match (§4.1).
    if let (Some(fp), Some(efp)) = (&Some(f.fingerprint.clone()), &entry.fingerprint) {
        if fp == efp {
            return true;
        }
    }
    // Fallback: ruleId + file + line.
    if let Some(rule) = &entry.rule_id {
        if rule == &f.rule_id {
            if entry.file.is_none() && entry.line.is_none() {
                return true; // rule-level match
            }
            let file_ok = entry.file.as_deref().map(|ef| ef == f.location.file).unwrap_or(true);
            let line_ok = entry.line.map(|el| el == f.location.line).unwrap_or(true);
            if file_ok && line_ok {
                return true;
            }
        }
    }
    false
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
    strict: bool,
    no_color: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        format: None,
        output: None,
        strict: false,
        no_color: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--strict" => opts.strict = true,
            "--no-color" => opts.no_color = true,
            flag @ ("--dir" | "--format" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa check: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                let val = args[i].clone();
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(val)),
                    "--format" => opts.format = Some(val),
                    "--output" => opts.output = Some(val),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--format=") { opts.format = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--output=") { opts.output = Some(v.to_string()); }
                else {
                    writeln!(stderr, "rsfusa check: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
