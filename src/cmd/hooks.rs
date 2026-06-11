// `rsfusa hooks [install|remove|show]` — manage git pre-commit hooks.

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::PathBuf;

const HOOK_PATH: &str = ".git/hooks/pre-commit";

const HOOK_SCRIPT: &str = r#"#!/bin/sh
# rsfusa pre-commit hook — installed by rsfusa hooks install
set -e
if command -v rsfusa >/dev/null 2>&1; then
    rsfusa check --strict
else
    echo "rsfusa not found in PATH; skipping safety check" >&2
fi
"#;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let subcmd = args.first().map(|s| s.as_str()).unwrap_or("show");
    let rest = if args.is_empty() { &[] } else { &args[1..] };

    let dir = parse_dir(rest);
    let project_root = dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    let hook_path = project_root.join(HOOK_PATH);

    match subcmd {
        "install" => cmd_install(&hook_path, stdout, stderr),
        "remove" | "uninstall" => cmd_remove(&hook_path, stdout, stderr),
        "show" | "status" => cmd_show(&hook_path, stdout),
        other => {
            writeln!(stderr, "rsfusa hooks: unknown subcommand: {other}").ok();
            writeln!(stderr, "Usage: rsfusa hooks [install|remove|show]").ok();
            EXIT_USAGE
        }
    }
}

fn cmd_install(path: &PathBuf, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            writeln!(stderr, "rsfusa hooks install: {} not found — is this a git repository?",
                parent.display()).ok();
            return EXIT_RUNTIME;
        }
    }

    if path.exists() {
        // Check if it's already our hook
        let existing = std::fs::read_to_string(path).unwrap_or_default();
        if existing.contains("rsfusa") {
            writeln!(stdout, "rust-FuSa hook already installed at {}", path.display()).ok();
            return EXIT_OK;
        }
        writeln!(stderr, "rsfusa hooks install: {} already exists (not installed by rsfusa)", path.display()).ok();
        writeln!(stderr, "Use --force to overwrite, or manually add 'rsfusa check --strict' to your hook.").ok();
        return EXIT_RUNTIME;
    }

    match std::fs::write(path, HOOK_SCRIPT) {
        Ok(_) => {}
        Err(e) => {
            writeln!(stderr, "rsfusa hooks install: write {}: {e}", path.display()).ok();
            return EXIT_RUNTIME;
        }
    }

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).ok();
        }
    }

    writeln!(stdout, "Hook installed at {}", path.display()).ok();
    writeln!(stdout, "The hook will run 'rsfusa check --strict' before each commit.").ok();
    EXIT_OK
}

fn cmd_remove(path: &PathBuf, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if !path.exists() {
        writeln!(stdout, "No hook found at {}", path.display()).ok();
        return EXIT_OK;
    }

    let content = std::fs::read_to_string(path).unwrap_or_default();
    if !content.contains("rsfusa") {
        writeln!(stderr, "rsfusa hooks remove: hook at {} was not installed by rsfusa",
            path.display()).ok();
        return EXIT_RUNTIME;
    }

    match std::fs::remove_file(path) {
        Ok(_) => {
            writeln!(stdout, "Hook removed from {}", path.display()).ok();
            EXIT_OK
        }
        Err(e) => {
            writeln!(stderr, "rsfusa hooks remove: {e}").ok();
            EXIT_RUNTIME
        }
    }
}

fn cmd_show(path: &PathBuf, stdout: &mut dyn Write) -> i32 {
    if !path.exists() {
        writeln!(stdout, "No pre-commit hook installed at {}", path.display()).ok();
        writeln!(stdout, "Run 'rsfusa hooks install' to install one.").ok();
        return EXIT_OK;
    }
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let managed = content.contains("rsfusa");
    writeln!(stdout, "Pre-commit hook: {} ({})",
        path.display(),
        if managed { "managed by rsfusa" } else { "not managed by rsfusa" }
    ).ok();
    writeln!(stdout, "\n--- content ---\n{content}--- end ---").ok();
    EXIT_OK
}

fn parse_dir(args: &[String]) -> Option<PathBuf> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--dir" && i + 1 < args.len() { return Some(PathBuf::from(&args[i + 1])); }
        if let Some(v) = args[i].strip_prefix("--dir=") { return Some(PathBuf::from(v)); }
        i += 1;
    }
    None
}
