use crate::auditpack::{pack, AUDIT_PACK_FILE};
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
        .unwrap_or_else(|| project_root.join(AUDIT_PACK_FILE));

    if let Some(parent) = out_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            writeln!(stderr, "rsfusa audit-pack: mkdir: {e}").ok();
            return EXIT_RUNTIME;
        }
    }

    match pack(&project_root, &out_path) {
        Ok(manifest) => {
            writeln!(stdout, "Audit pack written to {}", out_path.display()).ok();
            writeln!(stdout, "Module: {}", manifest.module).ok();
            writeln!(stdout, "Files packed: {}", manifest.files.len()).ok();
            for entry in &manifest.files {
                writeln!(stdout, "  {:<40}  {}…", entry.path, &entry.sha256[..16]).ok();
            }
            EXIT_OK
        }
        Err(e) => {
            writeln!(stderr, "rsfusa audit-pack: {e}").ok();
            EXIT_RUNTIME
        }
    }
}

struct Opts {
    dir: Option<PathBuf>,
    output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        output: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--output") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa audit-pack: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--output" => opts.output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.output = Some(v.to_string());
                } else {
                    writeln!(stderr, "rsfusa audit-pack: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
