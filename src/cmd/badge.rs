// `rsfusa badge [check-report.json]` — generate SVG status badge.
//fusa:req REQ-BADGE001
//fusa:req REQ-BADGE002
//fusa:req REQ-BADGE003

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

    let report_path = opts.report.unwrap_or_else(|| {
        project_root
            .join("check-report.json")
            .to_string_lossy()
            .into_owned()
    });

    let (errors, warnings, label) = if let Ok(data) = std::fs::read_to_string(&report_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            let errors = v["summary"]["errors"].as_u64().unwrap_or(0);
            let warnings = v["summary"]["warnings"].as_u64().unwrap_or(0);
            let version = v["toolVersion"].as_str().unwrap_or("?").to_string();
            (errors, warnings, version)
        } else {
            (0, 0, "?".to_string())
        }
    } else {
        (0, 0, "?".to_string())
    };

    let (color, status) = if errors > 0 {
        (
            "#e05d44",
            format!("{errors} error{}", if errors == 1 { "" } else { "s" }),
        )
    } else if warnings > 0 {
        (
            "#dfb317",
            format!("{warnings} warning{}", if warnings == 1 { "" } else { "s" }),
        )
    } else {
        ("#4c1", "passing".to_string())
    };

    let svg = render_badge("rust-FuSa", &status, color, &label);

    match opts.output.as_deref() {
        Some(path) => {
            match std::fs::write(path, &svg) {
                Ok(_) => writeln!(stdout, "Badge written to {path}").ok(),
                Err(e) => {
                    writeln!(stderr, "rsfusa badge: write {path}: {e}").ok();
                    return EXIT_RUNTIME;
                }
            };
        }
        None => {
            writeln!(stdout, "{svg}").ok();
        }
    }

    EXIT_OK
}

fn render_badge(left: &str, right: &str, color: &str, version: &str) -> String {
    let left_w = left.len() * 7 + 10;
    let right_w = right.len() * 7 + 10;
    let total_w = left_w + right_w;
    let left_x = left_w / 2;
    let right_x = left_w + right_w / 2;
    let left_tw = left.len() * 70;
    let right_tw = right.len() * 70;

    let mut s = String::new();
    s.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{total_w}\" height=\"20\">\n"
    ));
    s.push_str(&format!(
        "  <title>rust-FuSa {right} (v{version})</title>\n"
    ));
    s.push_str("  <linearGradient id=\"s\" x2=\"0\" y2=\"100%\">\n");
    s.push_str("    <stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/>\n");
    s.push_str("    <stop offset=\"1\" stop-opacity=\".1\"/>\n");
    s.push_str("  </linearGradient>\n");
    s.push_str(&format!(
        "  <clipPath id=\"r\"><rect width=\"{total_w}\" height=\"20\" rx=\"3\" fill=\"white\"/></clipPath>\n"
    ));
    s.push_str("  <g clip-path=\"url(#r)\">\n");
    s.push_str(&format!(
        "    <rect width=\"{left_w}\" height=\"20\" fill=\"#555\"/>\n"
    ));
    s.push_str(&format!(
        "    <rect x=\"{left_w}\" width=\"{right_w}\" height=\"20\" fill=\"{color}\"/>\n"
    ));
    s.push_str(&format!(
        "    <rect width=\"{total_w}\" height=\"20\" fill=\"url(#s)\"/>\n"
    ));
    s.push_str("  </g>\n");
    s.push_str("  <g fill=\"white\" text-anchor=\"middle\" font-family=\"DejaVu Sans,Verdana,Geneva,sans-serif\" font-size=\"110\">\n");
    s.push_str(&format!("    <text x=\"{left_x}0\" y=\"150\" fill=\"#010101\" fill-opacity=\".3\" transform=\"scale(.1)\" textLength=\"{left_tw}\" lengthAdjust=\"spacing\">{left}</text>\n"));
    s.push_str(&format!("    <text x=\"{left_x}0\" y=\"140\" transform=\"scale(.1)\" textLength=\"{left_tw}\" lengthAdjust=\"spacing\">{left}</text>\n"));
    s.push_str(&format!("    <text x=\"{right_x}0\" y=\"150\" fill=\"#010101\" fill-opacity=\".3\" transform=\"scale(.1)\" textLength=\"{right_tw}\" lengthAdjust=\"spacing\">{right}</text>\n"));
    s.push_str(&format!("    <text x=\"{right_x}0\" y=\"140\" transform=\"scale(.1)\" textLength=\"{right_tw}\" lengthAdjust=\"spacing\">{right}</text>\n"));
    s.push_str("  </g>\n");
    s.push_str("</svg>\n");
    s
}

struct Opts {
    dir: Option<PathBuf>,
    report: Option<String>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        report: None,
        output: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--report" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa badge: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--report" => opts.report = Some(args[i].clone()),
                    "--output" => opts.output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if other.starts_with("--") {
                    if let Some(v) = other.strip_prefix("--dir=") {
                        opts.dir = Some(PathBuf::from(v));
                    } else if let Some(v) = other.strip_prefix("--output=") {
                        opts.output = Some(v.to_string());
                    } else {
                        writeln!(stderr, "rsfusa badge: unknown flag: {other}").ok();
                        return None;
                    }
                } else {
                    opts.report = Some(other.to_string());
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
