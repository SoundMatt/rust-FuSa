// `rsfusa comp` — cyclomatic complexity (McCabe V(G)) per DO-178C §6.3.4.
// Writes comp-report.json. Exits 1 if threshold violations exist.
//fusa:req REQ-COMP001
//fusa:req REQ-COMP002
//fusa:req REQ-COMP003
//fusa:req REQ-COMP004
//fusa:req REQ-COMP005

use crate::types::{
    EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION,
};
use std::io::Write;
use std::path::PathBuf;
use walkdir::WalkDir;

pub const COMP_REPORT_FILE: &str = "comp-report.json";

// DO-178C §6.3.4 / McCabe thresholds per DAL.
const THRESHOLD_DAL_A: usize = 4;
const THRESHOLD_DAL_B: usize = 10;
const THRESHOLD_DAL_C: usize = 15;
const THRESHOLD_DAL_D: usize = 20;

#[derive(Debug, Clone)]
struct FnComplexity {
    file: String,
    line: usize,
    name: String,
    complexity: usize,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let threshold = opts.threshold;
    let mut all: Vec<FnComplexity> = Vec::new();

    for entry in WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with("target/") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        all.extend(analyze_file(&content, &rel));
    }

    all.sort_by(|a, b| b.complexity.cmp(&a.complexity).then(a.file.cmp(&b.file)));

    let violations: usize = all.iter().filter(|f| f.complexity > threshold).count();
    let max_complexity = all.iter().map(|f| f.complexity).max().unwrap_or(0);

    let items: Vec<serde_json::Value> = all
        .iter()
        .map(|f| {
            serde_json::json!({
                "file": f.file,
                "line": f.line,
                "function": f.name,
                "complexity": f.complexity,
                "exceedsThreshold": f.complexity > threshold,
            })
        })
        .collect();

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "comp-report",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "threshold": threshold,
        "functions": items,
        "summary": {
            "totalFunctions": all.len(),
            "violations": violations,
            "maxComplexity": max_complexity,
        }
    });

    let json = serde_json::to_string_pretty(&report).unwrap();

    if opts.format == "json" {
        match opts.output.as_deref() {
            Some(p) => {
                if let Err(e) = std::fs::write(p, format!("{json}\n")) {
                    writeln!(stderr, "rsfusa comp: write {p}: {e}").ok();
                    return EXIT_RUNTIME;
                }
                writeln!(stdout, "Complexity report written to {p}").ok();
            }
            None => {
                writeln!(stdout, "{json}").ok();
            }
        }
    } else {
        writeln!(
            stdout,
            "Cyclomatic Complexity Report  (threshold: {threshold})"
        )
        .ok();
        writeln!(stdout, "{}", "=".repeat(70)).ok();
        writeln!(stdout, "{:<45} {:>5}  Status", "Function", "V(G)").ok();
        writeln!(stdout, "{}", "-".repeat(70)).ok();
        for f in &all {
            let status = if f.complexity > threshold {
                "VIOLATION"
            } else {
                "ok"
            };
            writeln!(
                stdout,
                "{:<45} {:>5}  {}",
                trunc(&format!("{}:{}", f.file, f.name), 44),
                f.complexity,
                status
            )
            .ok();
        }
        writeln!(stdout, "{}", "-".repeat(70)).ok();
        writeln!(
            stdout,
            "Functions: {}  Violations: {}  Max V(G): {}",
            all.len(),
            violations,
            max_complexity
        )
        .ok();
        if let Some(p) = opts.output.as_deref() {
            if let Err(e) = std::fs::write(p, format!("{json}\n")) {
                writeln!(stderr, "rsfusa comp: write {p}: {e}").ok();
                return EXIT_RUNTIME;
            }
            writeln!(stdout, "Report written to {p}").ok();
        }
    }

    if violations > 0 {
        EXIT_GATE_FAIL
    } else {
        EXIT_OK
    }
}

// ── Analysis ────────────────────────────────────────────────────────────────

fn analyze_file(content: &str, rel: &str) -> Vec<FnComplexity> {
    let lines: Vec<&str> = content.lines().collect();
    let mut results: Vec<FnComplexity> = Vec::new();
    let mut brace_depth: i32 = 0;
    // Stack: (name, start_line_1indexed, depth_when_body_opened, complexity)
    let mut stack: Vec<(String, usize, i32, usize)> = Vec::new();
    let mut pending: Option<(String, usize)> = None; // fn declared, { not yet seen

    for (i, raw) in lines.iter().enumerate() {
        let code = code_portion(raw);
        let t = code.trim();

        // Detect fn declaration on this line
        if let Some(name) = extract_fn_name(t) {
            pending = Some((name, i + 1));
        }

        let opens = code.chars().filter(|&c| c == '{').count() as i32;
        let closes = code.chars().filter(|&c| c == '}').count() as i32;

        // Opening braces: activate pending fn (first { wins)
        if opens > 0 {
            if let Some((name, ln)) = pending.take() {
                stack.push((name, ln, brace_depth, 1));
            }
            brace_depth += opens;
        }

        // Count decisions for innermost function only
        if let Some(top) = stack.last_mut() {
            top.3 += count_decisions(t);
        }

        // Closing braces
        for _ in 0..closes {
            brace_depth -= 1;
            if let Some(top) = stack.last() {
                if brace_depth <= top.2 {
                    let (name, ln, _, complexity) = stack.pop().unwrap();
                    results.push(FnComplexity {
                        file: rel.to_string(),
                        line: ln,
                        name,
                        complexity,
                    });
                }
            }
        }
    }

    results
}

/// Strip everything after `//` (best-effort; doesn't handle block comments or string literals).
fn code_portion(line: &str) -> &str {
    match line.find("//") {
        Some(p) => &line[..p],
        None => line,
    }
}

/// Extract the bare function name from a line that contains `fn `.
fn extract_fn_name(line: &str) -> Option<String> {
    let pos = line.find("fn ")?;
    // Ensure `fn` is a word boundary (not part of an identifier).
    if pos > 0 {
        let prev = line[..pos].chars().last()?;
        if prev.is_alphanumeric() || prev == '_' {
            return None;
        }
    }
    let after = &line[pos + 3..];
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Count decision points on a single (comment-stripped) line.
/// V(G) counts: if, else if, while, for, loop, match, &&, ||
fn count_decisions(line: &str) -> usize {
    let mut n = 0;
    // Keyword decisions — require a word boundary before and a space/{ after.
    for kw in &["if ", "while ", "for ", "loop ", "loop{", "match "] {
        let mut rest = line;
        while let Some(p) = rest.find(kw) {
            let boundary = p == 0 || {
                let prev = rest[..p].chars().last().unwrap();
                !prev.is_alphanumeric() && prev != '_'
            };
            if boundary {
                n += 1;
            }
            rest = &rest[p + kw.len()..];
        }
    }
    // Logical operators
    n += line.matches("&&").count();
    n += line.matches("||").count();
    n
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("…{}", &s[s.len().saturating_sub(max - 1)..])
    }
}

// ── Opts / parser ────────────────────────────────────────────────────────────

struct Opts {
    dir: Option<PathBuf>,
    output: Option<String>,
    format: String,
    threshold: usize,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        output: None,
        format: "text".to_string(),
        threshold: THRESHOLD_DAL_B,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--output" | "--format" | "--threshold") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa comp: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(&args[i])),
                    "--output" => opts.output = Some(args[i].clone()),
                    "--format" => opts.format = args[i].clone(),
                    "--threshold" => match args[i].parse::<usize>() {
                        Ok(v) => opts.threshold = v,
                        Err(_) => {
                            writeln!(
                                stderr,
                                "rsfusa comp: --threshold must be a positive integer"
                            )
                            .ok();
                            return None;
                        }
                    },
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.output = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--format=") {
                    opts.format = v.to_string();
                } else if let Some(v) = other.strip_prefix("--threshold=") {
                    match v.parse::<usize>() {
                        Ok(n) => opts.threshold = n,
                        Err(_) => {
                            writeln!(
                                stderr,
                                "rsfusa comp: --threshold must be a positive integer"
                            )
                            .ok();
                            return None;
                        }
                    }
                } else if other == "--dal-a" {
                    opts.threshold = THRESHOLD_DAL_A;
                } else if other == "--dal-b" {
                    opts.threshold = THRESHOLD_DAL_B;
                } else if other == "--dal-c" {
                    opts.threshold = THRESHOLD_DAL_C;
                } else if other == "--dal-d" {
                    opts.threshold = THRESHOLD_DAL_D;
                } else {
                    writeln!(stderr, "rsfusa comp: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
