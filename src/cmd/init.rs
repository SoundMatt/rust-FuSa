use crate::config::{save, FusaConfig, CONFIG_FILE, REQS_FILE};
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::PathBuf;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });

    use std::io::IsTerminal;
    let is_tty = std::io::stdin().is_terminal();

    let name = opts.name.unwrap_or_else(|| {
        project_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my-project")
            .to_string()
    });

    let standard = opts.standard.unwrap_or_else(|| "iso26262".to_string());

    if name.is_empty() && !is_tty {
        writeln!(stderr, "rsfusa init: --name is required when stdin is not a TTY").ok();
        return EXIT_USAGE;
    }

    // --- .fusa.json ---
    let config_path = project_root.join(CONFIG_FILE);
    if config_path.exists() && !opts.force {
        writeln!(
            stderr,
            "rsfusa init: {} already exists (use --force to overwrite)",
            config_path.display()
        ).ok();
    } else {
        let mut cfg = FusaConfig::new(&name, &standard);
        cfg.project.version = opts.project_version.unwrap_or_else(|| "0.1.0".to_string());
        if let Some(asil) = &opts.asil {
            cfg.asil = Some(asil.clone());
        } else if let Some(sil) = &opts.sil {
            cfg.sil = Some(sil.clone());
        } else if let Some(dal) = &opts.dal {
            cfg.dal = Some(dal.clone());
        }
        match save(&config_path, &cfg) {
            Ok(()) => {
                writeln!(stdout, "Created {}", config_path.display()).ok();
            }
            Err(e) => {
                writeln!(stderr, "rsfusa init: write {}: {e}", config_path.display()).ok();
                return EXIT_RUNTIME;
            }
        }
    }

    // --- .fusa-reqs.json ---
    let reqs_path = project_root.join(REQS_FILE);
    if reqs_path.exists() && !opts.force {
        writeln!(
            stderr,
            "rsfusa init: {} already exists (use --force to overwrite)",
            reqs_path.display()
        ).ok();
    } else {
        let reqs = r#"{"requirements":[]}
"#;
        match std::fs::write(&reqs_path, reqs) {
            Ok(()) => {
                writeln!(stdout, "Created {}", reqs_path.display()).ok();
            }
            Err(e) => {
                writeln!(stderr, "rsfusa init: write {}: {e}", reqs_path.display()).ok();
                return EXIT_RUNTIME;
            }
        }
    }

    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    name: Option<String>,
    standard: Option<String>,
    asil: Option<String>,
    sil: Option<String>,
    dal: Option<String>,
    project_version: Option<String>,
    force: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        name: None,
        standard: None,
        asil: None,
        sil: None,
        dal: None,
        project_version: None,
        force: false,
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--force" => opts.force = true,
            flag @ ("--dir" | "--name" | "--standard" | "--asil" | "--sil" | "--dal"
            | "--project-version") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa init: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                let val = args[i].clone();
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(val)),
                    "--name" => opts.name = Some(val),
                    "--standard" => opts.standard = Some(val),
                    "--asil" => opts.asil = Some(val),
                    "--sil" => opts.sil = Some(val),
                    "--dal" => opts.dal = Some(val),
                    "--project-version" => opts.project_version = Some(val),
                    _ => {}
                }
            }
            other => {
                if let Some(val) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(val)); }
                else if let Some(val) = other.strip_prefix("--name=") { opts.name = Some(val.to_string()); }
                else if let Some(val) = other.strip_prefix("--standard=") { opts.standard = Some(val.to_string()); }
                else if let Some(val) = other.strip_prefix("--asil=") { opts.asil = Some(val.to_string()); }
                else if let Some(val) = other.strip_prefix("--sil=") { opts.sil = Some(val.to_string()); }
                else if let Some(val) = other.strip_prefix("--dal=") { opts.dal = Some(val.to_string()); }
                else if let Some(val) = other.strip_prefix("--project-version=") { opts.project_version = Some(val.to_string()); }
                else {
                    writeln!(stderr, "rsfusa init: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
