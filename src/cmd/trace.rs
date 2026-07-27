//fusa:req REQ-TRACE001
//fusa:req REQ-TRACE002
//fusa:req REQ-TRACE003
//fusa:req REQ-TRACE004
//fusa:req REQ-TRACE005
//fusa:req REQ-TRACE006
//fusa:req REQ-TRACE007
//fusa:req REQ-TRACE-HLR001
//fusa:req REQ-TRACE-HLR002
//fusa:req REQ-TRACE-HLR003
//fusa:req REQ-TRACE-HLR004
//fusa:req REQ-TRACE008
//fusa:req REQ-TRACE009
use crate::config::load;
use crate::trace::{build, render_md, render_text, scan_func_coverage, validate_hlr_llr, Coverage};
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
            writeln!(stderr, "rsfusa trace: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let (mut matrix, findings) = match build(&project_root, &cfg) {
        Ok(r) => r,
        Err(e) => {
            writeln!(stderr, "rsfusa trace: {e}").ok();
            return EXIT_RUNTIME;
        }
    };
    // Annotation-scan findings (malformed annotations, dangling requirement
    // ids — §1.4.1 item 3): WARNING-only, never gate the exit code, but must
    // not be silently dropped.
    for f in &findings {
        writeln!(stderr, "rsfusa trace: [{:?}] {}", f.severity, f.message).ok();
    }

    // Function annotation density (§1.4.1 item 2, --func-coverage). Computed
    // from the full tag set before --gaps trims matrix.tags below.
    let func_coverage = if opts.func_coverage > 0 {
        match scan_func_coverage(&project_root, &cfg, &matrix.tags) {
            Ok(fc) => Some(fc),
            Err(e) => {
                writeln!(stderr, "rsfusa trace: scan func coverage: {e}").ok();
                return EXIT_RUNTIME;
            }
        }
    } else {
        None
    };

    // HLR/LLR validation.
    let hlr_llr_result = validate_hlr_llr(
        &matrix.requirements,
        cfg.dal.as_deref(),
        cfg.asil.as_deref(),
        opts.strict_hlr_llr,
    );
    for f in &hlr_llr_result.findings {
        writeln!(stderr, "rsfusa trace: [{:?}] {}", f.severity, f.message).ok();
    }
    let hlr_gate_fail = hlr_llr_result.has_errors && !hlr_llr_result.findings.is_empty();

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
        matrix
            .tags
            .retain(|t| !tested_ids.contains(&t.requirement_id));
        matrix.coverage = full_coverage;
    }

    let gate_code = check_gates(
        &matrix.coverage,
        opts.req_coverage,
        opts.sec_tested,
        opts.func_coverage,
        func_coverage.as_ref(),
        hlr_gate_fail,
        stderr,
    );

    let render_err = if let Some(path) = opts.output.as_deref() {
        let mut f = match std::fs::File::create(path) {
            Ok(f) => f,
            Err(e) => {
                writeln!(stderr, "rsfusa trace: create output {path}: {e}").ok();
                return EXIT_RUNTIME;
            }
        };
        match opts.format.as_deref() {
            Some("json") => {
                let json = serde_json::to_string_pretty(&matrix).expect("serialize trace");
                writeln!(f, "{json}").err()
            }
            Some("md") => render_md(&mut f, &matrix).err(),
            _ => render_text(&mut f, &matrix).err(),
        }
    } else {
        match opts.format.as_deref() {
            Some("json") => {
                let json = serde_json::to_string_pretty(&matrix).expect("serialize trace");
                writeln!(stdout, "{json}").err()
            }
            Some("md") => render_md(stdout, &matrix).err(),
            _ => render_text(stdout, &matrix).err(),
        }
    };

    if let Some(e) = render_err {
        writeln!(stderr, "rsfusa trace: render: {e}").ok();
        return EXIT_RUNTIME;
    }

    gate_code
}

fn check_gates(
    cov: &Coverage,
    req_coverage: u32,
    sec_tested: u32,
    func_coverage: u32,
    fc: Option<&crate::trace::FuncCoverage>,
    hlr_gate_fail: bool,
    stderr: &mut dyn Write,
) -> i32 {
    let total = cov.total_requirements;
    let mut fail = hlr_gate_fail;

    // --func-coverage (§1.4.1 item 2) has its own denominator (public
    // functions, not requirements) so it gates independently of whether any
    // requirements are defined at all.
    if func_coverage > 0 {
        if let Some(fc) = fc {
            if fc.total > 0 {
                let pct = fc.pct();
                if pct < func_coverage {
                    writeln!(
                        stderr,
                        "rsfusa trace: func-coverage gate failed: {pct}% < required {func_coverage}%"
                    )
                    .ok();
                    fail = true;
                }
            }
        }
    }

    if total == 0 {
        return if fail { EXIT_GATE_FAIL } else { EXIT_OK };
    }

    if req_coverage > 0 {
        let pct = (cov.traced_requirements * 100 / total) as u32;
        if pct < req_coverage {
            writeln!(
                stderr,
                "rsfusa trace: req-coverage gate failed: {pct}% < required {req_coverage}%"
            )
            .ok();
            fail = true;
        }
    }
    if sec_tested > 0 {
        let pct = (cov.sec_tested_requirements * 100 / total) as u32;
        if pct < sec_tested {
            writeln!(
                stderr,
                "rsfusa trace: sec-tested gate failed: {pct}% < required {sec_tested}%"
            )
            .ok();
            fail = true;
        }
    }
    if fail {
        EXIT_GATE_FAIL
    } else {
        EXIT_OK
    }
}

struct Opts {
    dir: Option<PathBuf>,
    format: Option<String>,
    output: Option<String>,
    gaps: bool,
    req_coverage: u32,
    sec_tested: u32,
    func_coverage: u32,
    strict: bool,
    strict_hlr_llr: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        format: None,
        output: None,
        gaps: false,
        req_coverage: 0,
        sec_tested: 0,
        func_coverage: 0,
        strict: false,
        strict_hlr_llr: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--gaps" => opts.gaps = true,
            "--strict" => {
                opts.strict = true;
                if opts.req_coverage == 0 {
                    opts.req_coverage = 100;
                }
                if opts.sec_tested == 0 {
                    opts.sec_tested = 100;
                }
            }
            "--strict-hlr-llr" => opts.strict_hlr_llr = true,
            "--no-color" => {}
            flag @ ("--dir" | "--format" | "--output" | "--req-coverage" | "--sec-tested"
            | "--func-coverage") => {
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
                    "--func-coverage" => {
                        opts.func_coverage = val.parse().unwrap_or(0);
                    }
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
                } else if let Some(v) = other.strip_prefix("--req-coverage=") {
                    opts.req_coverage = v.parse().unwrap_or(0);
                } else if let Some(v) = other.strip_prefix("--sec-tested=") {
                    opts.sec_tested = v.parse().unwrap_or(0);
                } else if let Some(v) = other.strip_prefix("--func-coverage=") {
                    opts.func_coverage = v.parse().unwrap_or(0);
                } else {
                    writeln!(stderr, "rsfusa trace: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    // --strict overrides individual gates only if they weren't explicitly set.
    if opts.strict {
        if opts.req_coverage == 0 {
            opts.req_coverage = 100;
        }
        if opts.sec_tested == 0 {
            opts.sec_tested = 100;
        }
    }
    Some(opts)
}
