use crate::config::load;
use crate::trace::{build, render_md, render_text, Coverage};
use crate::types::{EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::PathBuf;

pub fn run(args: &[String], _stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
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
            writeln!(stderr, "rsfusa trace: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let (mut matrix, _findings) = match build(&project_root, &cfg) {
        Ok(r) => r,
        Err(e) => {
            writeln!(stderr, "rsfusa trace: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    // --gaps: filter to untested requirements only (coverage still shows full totals per §5).
    let full_coverage = matrix.coverage;
    if opts.gaps {
        let tested_ids: std::collections::HashSet<String> = matrix
            .tags
            .iter()
            .filter(|t| {
                t.kind == crate::trace::TagKind::Test || t.kind == crate::trace::TagKind::SecTest
            })
            .map(|t| t.requirement_id.clone())
            .collect();
        matrix.requirements.retain(|r| !tested_ids.contains(&r.id));
        matrix.tags.retain(|t| !tested_ids.contains(&t.requirement_id));
        matrix.coverage = full_coverage;
    }

    let gate_code = check_gates(&matrix.coverage, opts.req_coverage, opts.sec_tested, stderr);

    let w: Box<dyn Write> = match opts.output.as_deref() {
        Some(path) => {
            match std::fs::File::create(path) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    writeln!(stderr, "rsfusa trace: create output {path}: {e}").ok();
                    return EXIT_RUNTIME;
                }
            }
        }
        None => Box::new(std::io::stdout()),
    };
    let mut w = w;

    let render_err = match opts.format.as_deref() {
        Some("json") => {
            let json = serde_json::to_string_pretty(&matrix).expect("serialize trace");
            writeln!(w, "{json}").err()
        }
        Some("md") => render_md(&mut w, &matrix).err(),
        _ => render_text(&mut w, &matrix).err(),
    };

    if let Some(e) = render_err {
        writeln!(stderr, "rsfusa trace: render: {e}").ok();
        return EXIT_RUNTIME;
    }

    gate_code
}

fn check_gates(cov: &Coverage, req_coverage: u32, sec_tested: u32, stderr: &mut dyn Write) -> i32 {
    let total = cov.total_requirements;
    if total == 0 {
        return EXIT_OK;
    }

    let mut fail = false;
    if req_coverage > 0 {
        let pct = (cov.traced_requirements * 100 / total) as u32;
        if pct < req_coverage {
            writeln!(
                stderr,
                "rsfusa trace: req-coverage gate failed: {pct}% < required {req_coverage}%"
            ).ok();
            fail = true;
        }
    }
    if sec_tested > 0 {
        let pct = (cov.tested_requirements * 100 / total) as u32;
        if pct < sec_tested {
            writeln!(
                stderr,
                "rsfusa trace: sec-tested gate failed: {pct}% < required {sec_tested}%"
            ).ok();
            fail = true;
        }
    }
    if fail { EXIT_GATE_FAIL } else { EXIT_OK }
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
    gaps: bool,
    req_coverage: u32,
    sec_tested: u32,
    strict: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        format: None,
        output: None,
        gaps: false,
        req_coverage: 0,
        sec_tested: 0,
        strict: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--gaps" => opts.gaps = true,
            "--strict" => {
                opts.strict = true;
                if opts.req_coverage == 0 { opts.req_coverage = 100; }
                if opts.sec_tested == 0 { opts.sec_tested = 100; }
            }
            "--no-color" => {}
            flag @ ("--dir" | "--format" | "--output" | "--req-coverage" | "--sec-tested") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa trace: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                let val = args[i].clone();
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(val)),
                    "--format" => opts.format = Some(val),
                    "--output" => opts.output = Some(val),
                    "--req-coverage" => {
                        opts.req_coverage = val.parse().unwrap_or(0);
                    }
                    "--sec-tested" => {
                        opts.sec_tested = val.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--format=") { opts.format = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--output=") { opts.output = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--req-coverage=") { opts.req_coverage = v.parse().unwrap_or(0); }
                else if let Some(v) = other.strip_prefix("--sec-tested=") { opts.sec_tested = v.parse().unwrap_or(0); }
                else {
                    writeln!(stderr, "rsfusa trace: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    // --strict overrides individual gates only if they weren't explicitly set.
    if opts.strict {
        if opts.req_coverage == 0 { opts.req_coverage = 100; }
        if opts.sec_tested == 0 { opts.sec_tested = 100; }
    }
    Some(opts)
}
