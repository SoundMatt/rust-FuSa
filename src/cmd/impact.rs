// `rsfusa impact` — analyse impact of source changes on requirements and artifacts.
//fusa:req REQ-IMPACT001
//fusa:req REQ-IMPACT002
//fusa:req REQ-IMPACT003

use crate::config::load_reqs;
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Get changed files via git diff
    let from = opts.from.as_deref().unwrap_or("HEAD~1");
    let to = opts.to.as_deref().unwrap_or("HEAD");

    let changed_files = get_changed_files(&project_root, from, to);

    // Load requirements
    let reqs_path = project_root.join(".fusa-reqs.json");
    let req_ids: Vec<String> = if reqs_path.exists() {
        load_reqs(&reqs_path)
            .map(|r| r.requirements.iter().map(|req| req.id.clone()).collect())
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Find requirements touched by the changed files (via annotation scan)
    let impacted_reqs = find_impacted_requirements(&project_root, &changed_files);

    // Find stale artifacts (output files older than changed source files)
    let stale_artifacts = find_stale_artifacts(&project_root, &changed_files);

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "impact-report",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "from": from,
        "to": to,
        "changedFiles": changed_files,
        "impactedRequirements": impacted_reqs,
        "staleArtifacts": stale_artifacts,
        "summary": {
            "changedFiles": changed_files.len(),
            "impactedRequirements": impacted_reqs.len(),
            "staleArtifacts": stale_artifacts.len(),
            "totalRequirements": req_ids.len(),
        }
    });

    match opts.format.as_deref() {
        Some("json") => {
            let path = opts.output.as_deref().unwrap_or("-");
            if path == "-" {
                writeln!(stdout, "{}", serde_json::to_string_pretty(&report).unwrap()).ok();
            } else {
                if let Err(e) =
                    std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n")
                {
                    writeln!(stderr, "rsfusa impact: write {path}: {e}").ok();
                    return EXIT_RUNTIME;
                }
                writeln!(stdout, "Impact report written to {path}").ok();
            }
        }
        _ => {
            writeln!(stdout, "Impact Analysis: {from}..{to}").ok();
            writeln!(stdout, "Changed files: {}", changed_files.len()).ok();
            if !changed_files.is_empty() {
                for f in &changed_files {
                    writeln!(stdout, "  {f}").ok();
                }
            }
            writeln!(stdout, "\nImpacted requirements: {}", impacted_reqs.len()).ok();
            for r in &impacted_reqs {
                writeln!(stdout, "  {r}").ok();
            }
            writeln!(
                stdout,
                "\nPossibly stale artifacts: {}",
                stale_artifacts.len()
            )
            .ok();
            for a in &stale_artifacts {
                writeln!(stdout, "  {a}").ok();
            }
        }
    }

    EXIT_OK
}

fn get_changed_files(root: &PathBuf, from: &str, to: &str) -> Vec<String> {
    let output = std::process::Command::new("git")
        .args(["diff", "--name-only", from, to])
        .current_dir(root)
        .output();

    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        _ => vec![],
    }
}

fn find_impacted_requirements(root: &Path, changed_files: &[String]) -> Vec<String> {
    let mut reqs = HashSet::new();
    for rel in changed_files {
        let path = root.join(rel);
        if !path.exists() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            if let Some(pos) = line.find("//fusa:req") {
                let rest = line[pos + 10..].trim_start_matches([':', ' ']);
                for id in rest.split_whitespace() {
                    reqs.insert(id.to_string());
                }
            }
        }
    }
    let mut v: Vec<_> = reqs.into_iter().collect();
    v.sort();
    v
}

fn find_stale_artifacts(root: &Path, changed_files: &[String]) -> Vec<String> {
    const ARTIFACTS: &[&str] = &[
        "check-report.json",
        "trace.json",
        ".fusa-evidence.json",
        "sbom.json",
        "fmea.json",
        "tara.json",
        "coupling-report.json",
        "cyber-report.json",
    ];

    let newest_src_time = changed_files
        .iter()
        .filter_map(|f| root.join(f).metadata().ok().and_then(|m| m.modified().ok()))
        .max();

    let Some(src_time) = newest_src_time else {
        return vec![];
    };

    let mut stale = Vec::new();
    for artifact in ARTIFACTS {
        let path = root.join(artifact);
        if !path.exists() {
            continue;
        }
        if let Ok(meta) = path.metadata() {
            if let Ok(artifact_time) = meta.modified() {
                if artifact_time < src_time {
                    stale.push(artifact.to_string());
                }
            }
        }
    }
    stale
}

struct Opts {
    dir: Option<PathBuf>,
    from: Option<String>,
    to: Option<String>,
    format: Option<String>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        from: None,
        to: None,
        format: None,
        output: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--from" | "--to" | "--format" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa impact: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--from" => opts.from = Some(args[i].clone()),
                    "--to" => opts.to = Some(args[i].clone()),
                    "--format" => opts.format = Some(args[i].clone()),
                    "--output" => opts.output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--from=") {
                    opts.from = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--to=") {
                    opts.to = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--format=") {
                    opts.format = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.output = Some(v.to_string());
                } else {
                    writeln!(stderr, "rsfusa impact: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
