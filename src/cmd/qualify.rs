//fusa:req REQ-QUALIFY001
//fusa:req REQ-QUALIFY002
//fusa:req REQ-QUALIFY003
//fusa:req REQ-QUALIFY004
//fusa:req REQ-E2E001
use crate::engine::default_registry;
use crate::qualify::{builtin_cases, run as qualify_run, save, REPORT_FILE};
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
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

    let out_path = opts
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| project_root.join(REPORT_FILE));

    let is_json = opts.format.as_deref() == Some("json");

    let cases = builtin_cases();
    // Progress always to stderr so stdout is clean for --format json.
    writeln!(stderr, "rsfusa qualify: running {} case(s)...", cases.len()).ok();

    let registry = default_registry();
    let report = qualify_run(&registry, &cases);

    writeln!(
        stderr,
        "rsfusa qualify: {}/{} passed",
        report.passed, report.total
    )
    .ok();
    if report.has_failures() {
        writeln!(stderr, "rsfusa qualify: {} case(s) failed:", report.failed).ok();
        for r in &report.results {
            if r.result == "FAIL" {
                writeln!(
                    stderr,
                    "  FAIL  {}: {}",
                    r.name,
                    r.error.as_deref().unwrap_or("")
                )
                .ok();
            }
        }
    }

    if let Some(h) = &report.hash {
        writeln!(stderr, "rsfusa qualify: integrity hash: {h}").ok();
    }

    // §2.2: when --output is given, write to file only; otherwise write to stdout if --format json.
    if is_json && !opts.output_given {
        let json = serde_json::to_string_pretty(&report).expect("serialize qualify");
        writeln!(stdout, "{json}").ok();
    }

    match save(&out_path, &report) {
        Ok(()) => writeln!(
            stderr,
            "rsfusa qualify: report written to {}",
            out_path.display()
        )
        .ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa qualify: save report: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    if report.has_failures() {
        return EXIT_RUNTIME;
    }
    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    output: Option<String>,
    output_given: bool,
    format: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        output: None,
        output_given: false,
        format: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--output" | "--format" | "--dir") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa qualify: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--output" => {
                        opts.output = Some(args[i].clone());
                        opts.output_given = true;
                    }
                    "--format" => opts.format = Some(args[i].clone()),
                    "--dir" => opts.dir = Some(PathBuf::from(&args[i])),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--output=") {
                    opts.output = Some(v.to_string());
                    opts.output_given = true;
                } else if let Some(v) = other.strip_prefix("--format=") {
                    opts.format = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else {
                    writeln!(stderr, "rsfusa qualify: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
