// `rsfusa req [show|import|export]` — requirement management.
//fusa:req REQ-REQQ003

use crate::config::load;
use crate::config::{load_reqs, ReqsFile, Requirement};
use crate::trace::build;
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("show");
    let rest = if args.is_empty() { &[] } else { &args[1..] };

    let dir = parse_dir(rest);
    let project_root =
        dir.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    match subcmd {
        "show" | "list" => cmd_show(&project_root, rest, stdout, stderr),
        "import" => cmd_import(rest, &project_root, stdout, stderr),
        "export" => cmd_export(&project_root, rest, stdout, stderr),
        other => {
            writeln!(stderr, "rsfusa req: unknown subcommand: {other}").ok();
            writeln!(
                stderr,
                "Usage: rsfusa req [show|import|export] [--dir <path>]"
            )
            .ok();
            EXIT_USAGE
        }
    }
}

fn cmd_show(root: &Path, args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let format = parse_flag(args, "--format").unwrap_or_else(|| "text".to_string());
    let reqs_path = root.join(".fusa-reqs.json");

    let reqs = match load_reqs(&reqs_path) {
        Ok(r) => r,
        Err(e) => {
            writeln!(stderr, "rsfusa req show: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    // Enrich with trace info if available
    let cfg = load(&root.join(".fusa.json"))
        .ok()
        .unwrap_or_else(|| crate::config::FusaConfig::new("project", "generic"));
    let trace_data = build(root, &cfg).ok();

    if format == "json" {
        writeln!(stdout, "{}", serde_json::to_string_pretty(&reqs).unwrap()).ok();
        return EXIT_OK;
    }

    writeln!(stdout, "{} requirements", reqs.requirements.len()).ok();
    writeln!(
        stdout,
        "{:<16} {:<40} {:<12} Tested",
        "ID", "Title", "Traced"
    )
    .ok();
    writeln!(stdout, "{}", "-".repeat(80)).ok();

    for req in &reqs.requirements {
        let (traced, tested) = if let Some((ref matrix, _)) = trace_data {
            let traced = matrix.tags.iter().any(|t| t.requirement_id == req.id);
            let tested = matrix.tags.iter().any(|t| {
                t.requirement_id == req.id
                    && (t.kind == crate::trace::TagKind::Test
                        || t.kind == crate::trace::TagKind::SecTest)
            });
            (traced, tested)
        } else {
            (false, false)
        };

        writeln!(
            stdout,
            "{:<16} {:<40} {:<12} {}",
            req.id,
            truncate(req.title.as_deref().unwrap_or(&req.id), 39),
            if traced { "yes" } else { "no" },
            if tested { "yes" } else { "no" },
        )
        .ok();
    }
    EXIT_OK
}

fn cmd_import(args: &[String], root: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let file = match parse_flag(args, "--file")
        .or_else(|| args.iter().find(|a| !a.starts_with("--")).cloned())
    {
        Some(f) => f,
        None => {
            writeln!(stderr, "rsfusa req import: --file <path> required").ok();
            return EXIT_USAGE;
        }
    };

    let data = match std::fs::read_to_string(&file) {
        Ok(d) => d,
        Err(e) => {
            writeln!(stderr, "rsfusa req import: read {file}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    // Try to parse as JSON array of requirement objects or as a JSON requirements file
    let new_reqs: Vec<Requirement> = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data)
    {
        if let Some(arr) = v.get("requirements").and_then(|r| r.as_array()) {
            arr.iter()
                .filter_map(|r| serde_json::from_value(r.clone()).ok())
                .collect()
        } else if let Ok(reqs) = serde_json::from_value::<Vec<Requirement>>(v) {
            reqs
        } else {
            writeln!(stderr, "rsfusa req import: unrecognised format in {file}").ok();
            return EXIT_USAGE;
        }
    } else {
        writeln!(stderr, "rsfusa req import: parse {file}: invalid JSON").ok();
        return EXIT_RUNTIME;
    };

    let reqs_path = root.join(".fusa-reqs.json");
    let mut existing = if reqs_path.exists() {
        load_reqs(&reqs_path).unwrap_or(ReqsFile {
            requirements: vec![],
        })
    } else {
        ReqsFile {
            requirements: vec![],
        }
    };

    let existing_ids: std::collections::HashSet<String> =
        existing.requirements.iter().map(|r| r.id.clone()).collect();
    let mut added = 0usize;
    for req in new_reqs {
        if !existing_ids.contains(&req.id) {
            existing.requirements.push(req);
            added += 1;
        }
    }

    let json = serde_json::to_string_pretty(&existing).unwrap();
    match std::fs::write(&reqs_path, json + "\n") {
        Ok(_) => {
            writeln!(
                stdout,
                "Imported {added} requirements to {}",
                reqs_path.display()
            )
            .ok();
            EXIT_OK
        }
        Err(e) => {
            writeln!(stderr, "rsfusa req import: write: {e}").ok();
            EXIT_RUNTIME
        }
    }
}

fn cmd_export(root: &Path, args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let reqs_path = root.join(".fusa-reqs.json");
    let reqs = match load_reqs(&reqs_path) {
        Ok(r) => r,
        Err(e) => {
            writeln!(stderr, "rsfusa req export: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let format = parse_flag(args, "--format").unwrap_or_else(|| "csv".to_string());

    if format == "csv" {
        let mut csv = String::from("ID,Title,Text,Standard,Level\n");
        for req in &reqs.requirements {
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                csv_escape(&req.id),
                csv_escape(req.title.as_deref().unwrap_or("")),
                csv_escape(req.text.as_deref().unwrap_or("")),
                csv_escape(req.standard.as_deref().unwrap_or("")),
                csv_escape(req.level.as_deref().unwrap_or("")),
            ));
        }

        let out_path =
            parse_flag(args, "--output").unwrap_or_else(|| "requirements.csv".to_string());
        match std::fs::write(&out_path, csv) {
            Ok(_) => writeln!(stdout, "Requirements exported to {out_path}").ok(),
            Err(e) => {
                writeln!(stderr, "rsfusa req export: write {out_path}: {e}").ok();
                return EXIT_RUNTIME;
            }
        };
    } else {
        writeln!(stdout, "{}", serde_json::to_string_pretty(&reqs).unwrap()).ok();
    }
    EXIT_OK
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

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // ── csv_escape ────────────────────────────────────────────────────────

    //fusa:test REQ-REQQ003
    #[test]
    fn csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn csv_escape_with_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn csv_escape_with_quote() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn csv_escape_with_newline() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    // ── truncate ──────────────────────────────────────────────────────────

    //fusa:test REQ-REQQ003
    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn truncate_long_string() {
        let result = truncate("hello world", 8);
        assert!(result.len() <= 10); // includes ellipsis character
        assert!(result.starts_with("hello w"));
    }

    // ── run (unknown subcommand) ──────────────────────────────────────────

    //fusa:test REQ-REQQ003
    #[test]
    fn run_unknown_subcommand() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&sv(&["bad"]), &mut out, &mut err);
        assert_eq!(code, 2);
        let e = String::from_utf8(err).unwrap();
        assert!(e.contains("unknown subcommand"));
    }

    // ── cmd_show ─────────────────────────────────────────────────────────

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_show_no_reqs_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&["show", "--dir", dir.path().to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 3);
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_show_with_reqs_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let reqs_json = r#"{"requirements":[{"id":"REQ-001","title":"First requirement"}]}"#;
        std::fs::write(dir.path().join(".fusa-reqs.json"), reqs_json).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&["show", "--dir", dir.path().to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("1 requirements"));
        assert!(text.contains("REQ-001"));
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_show_json_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let reqs_json = r#"{"requirements":[{"id":"REQ-002"}]}"#;
        std::fs::write(dir.path().join(".fusa-reqs.json"), reqs_json).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "show",
                "--dir",
                dir.path().to_str().unwrap(),
                "--format",
                "json",
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v["requirements"].is_array());
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_list_alias_works() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(".fusa-reqs.json"), r#"{"requirements":[]}"#).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&["list", "--dir", dir.path().to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
    }

    // ── cmd_import ────────────────────────────────────────────────────────

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_import_no_file_flag() {
        // Pass "import" with no positional args and no --file flag so that
        // parse_flag returns None and find() returns None → EXIT_USAGE.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&sv(&["import"]), &mut out, &mut err);
        assert_eq!(code, 2);
        assert!(String::from_utf8(err).unwrap().contains("--file"));
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_import_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "import",
                "--dir",
                dir.path().to_str().unwrap(),
                "--file",
                "/nonexistent/reqs.json",
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 3);
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_import_invalid_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let bad_file = dir.path().join("bad.json");
        std::fs::write(&bad_file, "not json").unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "import",
                "--dir",
                dir.path().to_str().unwrap(),
                "--file",
                bad_file.to_str().unwrap(),
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 3);
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_import_valid_reqs_file_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let import_file = dir.path().join("import.json");
        let json = r#"{"requirements":[{"id":"REQ-NEW-001","title":"New Requirement"}]}"#;
        std::fs::write(&import_file, json).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "import",
                "--dir",
                dir.path().to_str().unwrap(),
                "--file",
                import_file.to_str().unwrap(),
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("1 requirements"));

        // Verify file was written
        let reqs_path = dir.path().join(".fusa-reqs.json");
        assert!(reqs_path.exists());
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(reqs_path).unwrap()).unwrap();
        assert_eq!(written["requirements"].as_array().unwrap().len(), 1);
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_import_array_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let import_file = dir.path().join("import.json");
        let json = r#"[{"id":"REQ-ARR-001","title":"Array Format"}]"#;
        std::fs::write(&import_file, json).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "import",
                "--dir",
                dir.path().to_str().unwrap(),
                "--file",
                import_file.to_str().unwrap(),
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_import_skips_duplicates() {
        let dir = tempfile::TempDir::new().unwrap();
        // Pre-populate
        let existing = r#"{"requirements":[{"id":"REQ-DUP-001"}]}"#;
        std::fs::write(dir.path().join(".fusa-reqs.json"), existing).unwrap();

        let import_file = dir.path().join("import.json");
        let json = r#"{"requirements":[{"id":"REQ-DUP-001"},{"id":"REQ-NEW-002"}]}"#;
        std::fs::write(&import_file, json).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "import",
                "--dir",
                dir.path().to_str().unwrap(),
                "--file",
                import_file.to_str().unwrap(),
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        // Only 1 new req should be added (duplicate skipped)
        assert!(text.contains("1 requirements"));
    }

    // ── cmd_export ────────────────────────────────────────────────────────

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_export_no_reqs_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&["export", "--dir", dir.path().to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 3);
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_export_csv_default() {
        let dir = tempfile::TempDir::new().unwrap();
        let reqs_json = r#"{"requirements":[{"id":"REQ-001","title":"First","text":"Desc","standard":"iso26262","level":"ASIL-B"}]}"#;
        std::fs::write(dir.path().join(".fusa-reqs.json"), reqs_json).unwrap();

        let out_file = dir.path().join("requirements.csv");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "export",
                "--dir",
                dir.path().to_str().unwrap(),
                "--output",
                out_file.to_str().unwrap(),
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        assert!(out_file.exists());
        let csv = std::fs::read_to_string(&out_file).unwrap();
        assert!(csv.contains("REQ-001"));
        assert!(csv.starts_with("ID,Title"));
    }

    //fusa:test REQ-REQQ003
    #[test]
    fn cmd_export_json_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let reqs_json = r#"{"requirements":[{"id":"REQ-001"}]}"#;
        std::fs::write(dir.path().join(".fusa-reqs.json"), reqs_json).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "export",
                "--dir",
                dir.path().to_str().unwrap(),
                "--format",
                "json",
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v["requirements"].is_array());
    }
}
