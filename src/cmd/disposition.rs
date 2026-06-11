// `rsfusa disposition [add|list|show]` — manage .fusa-dispositions.json.

use crate::config::{load_dispositions, DispositionEntry, DispositionsFile};
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::{Path, PathBuf};

const DISP_FILE: &str = ".fusa-dispositions.json";

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("list");
    let rest = if args.is_empty() { &[] } else { &args[1..] };

    let dir = parse_dir(rest);
    let project_root =
        dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let disp_path = project_root.join(DISP_FILE);

    match subcmd {
        "add" => cmd_add(rest, &disp_path, stdout, stderr),
        "list" => cmd_list(&disp_path, rest, stdout, stderr),
        "show" => cmd_list(&disp_path, rest, stdout, stderr),
        other => {
            writeln!(stderr, "rsfusa disposition: unknown subcommand: {other}").ok();
            writeln!(stderr, "Usage: rsfusa disposition [add|list|show] [flags]").ok();
            EXIT_USAGE
        }
    }
}

fn cmd_add(args: &[String], path: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let rule = parse_flag(args, "--rule");
    let file = parse_flag(args, "--file");
    let status = parse_flag(args, "--status").unwrap_or_else(|| "accepted".to_string());
    let note = parse_flag(args, "--note");
    let by = parse_flag(args, "--by");

    if rule.is_none() {
        writeln!(
            stderr,
            "rsfusa disposition add: --rule <RULE_ID> is required"
        )
        .ok();
        return EXIT_USAGE;
    }

    let valid_statuses = ["accepted", "deferred", "rejected"];
    if !valid_statuses.contains(&status.as_str()) {
        writeln!(
            stderr,
            "rsfusa disposition add: --status must be accepted|deferred|rejected"
        )
        .ok();
        return EXIT_USAGE;
    }

    let mut file_data = load_or_empty(path);

    file_data.dispositions.push(DispositionEntry {
        fingerprint: None,
        rule_id: rule,
        file,
        line: None,
        status,
        note,
        by,
        at: Some(chrono::Utc::now().to_rfc3339()),
    });

    save_dispositions(path, &file_data, stdout, stderr)
}

fn cmd_list(
    path: &PathBuf,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let format = parse_flag(args, "--format").unwrap_or_else(|| "text".to_string());

    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => {
            writeln!(stdout, "No dispositions file found at {}", path.display()).ok();
            return EXIT_OK;
        }
    };

    if format == "json" {
        writeln!(stdout, "{data}").ok();
        return EXIT_OK;
    }

    let file_data: DispositionsFile = match serde_json::from_str(&data) {
        Ok(d) => d,
        Err(e) => {
            writeln!(
                stderr,
                "rsfusa disposition list: parse {}: {e}",
                path.display()
            )
            .ok();
            return EXIT_RUNTIME;
        }
    };

    if file_data.dispositions.is_empty() {
        writeln!(stdout, "No dispositions.").ok();
        return EXIT_OK;
    }

    writeln!(
        stdout,
        "{:<12} {:<30} {:<10} {:<15} Note",
        "Rule", "File", "Status", "By"
    )
    .ok();
    writeln!(stdout, "{}", "-".repeat(80)).ok();
    for d in &file_data.dispositions {
        writeln!(
            stdout,
            "{:<12} {:<30} {:<10} {:<15} {}",
            d.rule_id.as_deref().unwrap_or("*"),
            d.file.as_deref().unwrap_or("*"),
            d.status,
            d.by.as_deref().unwrap_or(""),
            d.note.as_deref().unwrap_or(""),
        )
        .ok();
    }
    writeln!(stdout, "\nTotal: {}", file_data.dispositions.len()).ok();
    EXIT_OK
}

fn load_or_empty(path: &Path) -> DispositionsFile {
    load_dispositions(path).unwrap_or(DispositionsFile {
        dispositions: vec![],
    })
}

fn save_dispositions(
    path: &Path,
    file_data: &DispositionsFile,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let json = serde_json::to_string_pretty(file_data).expect("serialize dispositions");
    match std::fs::write(path, json + "\n") {
        Ok(_) => {
            writeln!(
                stdout,
                "Saved {} dispositions to {}",
                file_data.dispositions.len(),
                path.display()
            )
            .ok();
            EXIT_OK
        }
        Err(e) => {
            writeln!(stderr, "rsfusa disposition: write {}: {e}", path.display()).ok();
            EXIT_RUNTIME
        }
    }
}

fn parse_dir(args: &[String]) -> Option<PathBuf> {
    parse_flag(args, "--dir").map(PathBuf::from)
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    let prefix = format!("{flag}=");
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(v) = args[i].strip_prefix(&prefix) {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
}
