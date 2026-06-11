// `rsfusa pr [init|add|list|close]` — software problem report log.

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

pub const PR_FILE: &str = ".fusa-problems.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProblemReport {
    id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    phase: String,
    severity: String,
    status: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assigned_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrFile {
    schema_version: String,
    kind: String,
    tool: String,
    tool_version: String,
    language: String,
    problems: Vec<ProblemReport>,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };

    let dir = parse_dir(rest);
    let project_root = dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    let pr_path = project_root.join(PR_FILE);

    match subcmd {
        "init" => cmd_init(&pr_path, stdout, stderr),
        "add" => cmd_add(rest, &pr_path, stdout, stderr),
        "list" | "show" => cmd_list(&pr_path, rest, stdout, stderr),
        "close" => cmd_close(rest, &pr_path, stdout, stderr),
        other => {
            writeln!(stderr, "rsfusa pr: unknown subcommand: {other}").ok();
            writeln!(stderr, "Usage: rsfusa pr [init|add|list|close] [flags]").ok();
            EXIT_USAGE
        }
    }
}

fn cmd_init(path: &PathBuf, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if path.exists() {
        writeln!(stdout, "{} already exists", path.display()).ok();
        return EXIT_OK;
    }
    let f = empty_file();
    if let Err(e) = std::fs::write(path, serde_json::to_string_pretty(&f).unwrap() + "\n") {
        writeln!(stderr, "rsfusa pr init: {e}").ok();
        return EXIT_RUNTIME;
    }
    writeln!(stdout, "Created {}", path.display()).ok();
    EXIT_OK
}

fn cmd_add(args: &[String], path: &PathBuf, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let title = match parse_flag(args, "--title") {
        Some(t) => t,
        None => {
            writeln!(stderr, "rsfusa pr add: --title <text> is required").ok();
            return EXIT_USAGE;
        }
    };

    let valid_phases = ["requirements", "design", "implementation", "testing", "integration", "operation"];
    let valid_severities = ["critical", "major", "minor", "observation"];

    let phase = parse_flag(args, "--phase").unwrap_or_else(|| "implementation".to_string());
    let severity = parse_flag(args, "--severity").unwrap_or_else(|| "minor".to_string());

    if !valid_phases.contains(&phase.as_str()) {
        writeln!(stderr, "rsfusa pr add: --phase must be one of: {}", valid_phases.join(", ")).ok();
        return EXIT_USAGE;
    }
    if !valid_severities.contains(&severity.as_str()) {
        writeln!(stderr, "rsfusa pr add: --severity must be one of: {}", valid_severities.join(", ")).ok();
        return EXIT_USAGE;
    }

    let mut file_data = load_or_empty(path);
    let id = format!("PR-{:04}", file_data.problems.len() + 1);

    file_data.problems.push(ProblemReport {
        id: id.clone(),
        title,
        description: parse_flag(args, "--description"),
        phase,
        severity,
        status: "open".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        resolved_at: None,
        assigned_to: parse_flag(args, "--assign"),
    });

    if let Err(e) = std::fs::write(path, serde_json::to_string_pretty(&file_data).unwrap() + "\n") {
        writeln!(stderr, "rsfusa pr add: {e}").ok();
        return EXIT_RUNTIME;
    }
    writeln!(stdout, "Created {id}").ok();
    EXIT_OK
}

fn cmd_list(path: &PathBuf, args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let format = parse_flag(args, "--format").unwrap_or_else(|| "text".to_string());
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => {
            writeln!(stdout, "No problem reports file. Run 'rsfusa pr init' first.").ok();
            return EXIT_OK;
        }
    };
    if format == "json" {
        writeln!(stdout, "{data}").ok();
        return EXIT_OK;
    }
    let file_data: PrFile = match serde_json::from_str(&data) {
        Ok(f) => f,
        Err(e) => {
            writeln!(stderr, "rsfusa pr list: parse: {e}").ok();
            return EXIT_RUNTIME;
        }
    };
    let open: Vec<_> = file_data.problems.iter().filter(|p| p.status == "open").collect();
    writeln!(stdout, "{} problems ({} open)", file_data.problems.len(), open.len()).ok();
    writeln!(stdout, "{:<10} {:<8} {:<14} {:<8} {}", "ID", "Severity", "Phase", "Status", "Title").ok();
    writeln!(stdout, "{}", "-".repeat(80)).ok();
    for p in &file_data.problems {
        writeln!(stdout, "{:<10} {:<8} {:<14} {:<8} {}",
            p.id, p.severity, p.phase, p.status,
            truncate(&p.title, 35)
        ).ok();
    }
    EXIT_OK
}

fn cmd_close(args: &[String], path: &PathBuf, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let id = match parse_flag(args, "--id").or_else(|| {
        args.iter().find(|a| !a.starts_with("--")).cloned()
    }) {
        Some(i) => i,
        None => {
            writeln!(stderr, "rsfusa pr close: --id <PR-XXXX> is required").ok();
            return EXIT_USAGE;
        }
    };

    let mut file_data = load_or_empty(path);
    let mut found = false;
    for p in &mut file_data.problems {
        if p.id == id {
            p.status = "closed".to_string();
            p.resolved_at = Some(chrono::Utc::now().to_rfc3339());
            found = true;
            break;
        }
    }
    if !found {
        writeln!(stderr, "rsfusa pr close: {id} not found").ok();
        return EXIT_RUNTIME;
    }
    if let Err(e) = std::fs::write(path, serde_json::to_string_pretty(&file_data).unwrap() + "\n") {
        writeln!(stderr, "rsfusa pr close: {e}").ok();
        return EXIT_RUNTIME;
    }
    writeln!(stdout, "Closed {id}").ok();
    EXIT_OK
}

fn empty_file() -> PrFile {
    PrFile {
        schema_version: SPEC_VERSION.to_string(),
        kind: "problem-reports".to_string(),
        tool: TOOL_NAME.to_string(),
        tool_version: VERSION.to_string(),
        language: LANGUAGE.to_string(),
        problems: vec![],
    }
}

fn load_or_empty(path: &PathBuf) -> PrFile {
    if let Ok(data) = std::fs::read_to_string(path) {
        if let Ok(f) = serde_json::from_str::<PrFile>(&data) {
            return f;
        }
    }
    empty_file()
}

fn parse_dir(args: &[String]) -> Option<PathBuf> {
    parse_flag(args, "--dir").map(PathBuf::from)
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    let prefix = format!("{flag}=");
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() { return Some(args[i + 1].clone()); }
        if let Some(v) = args[i].strip_prefix(&prefix) { return Some(v.to_string()); }
        i += 1;
    }
    None
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max - 1]) }
}
