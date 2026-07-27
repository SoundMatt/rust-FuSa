use crate::config::{save, FusaConfig, CONFIG_FILE, REQS_FILE};
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
        writeln!(
            stderr,
            "rsfusa init: --name is required when stdin is not a TTY"
        )
        .ok();
        return EXIT_USAGE;
    }

    // --- .fusa.json ---
    let config_path = project_root.join(CONFIG_FILE);
    if config_path.exists() && !opts.force {
        writeln!(
            stderr,
            "rsfusa init: {} already exists (use --force to overwrite)",
            config_path.display()
        )
        .ok();
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
        )
        .ok();
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
                if let Some(val) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(val));
                } else if let Some(val) = other.strip_prefix("--name=") {
                    opts.name = Some(val.to_string());
                } else if let Some(val) = other.strip_prefix("--standard=") {
                    opts.standard = Some(val.to_string());
                } else if let Some(val) = other.strip_prefix("--asil=") {
                    opts.asil = Some(val.to_string());
                } else if let Some(val) = other.strip_prefix("--sil=") {
                    opts.sil = Some(val.to_string());
                } else if let Some(val) = other.strip_prefix("--dal=") {
                    opts.dal = Some(val.to_string());
                } else if let Some(val) = other.strip_prefix("--project-version=") {
                    opts.project_version = Some(val.to_string());
                } else {
                    writeln!(stderr, "rsfusa init: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // ── parse ─────────────────────────────────────────────────────────────

    //fusa:test REQ-CFG001
    #[test]
    fn parse_basic_args() {
        let mut err = Vec::new();
        let opts = parse(
            &sv(&["--name", "myproj", "--standard", "iso26262"]),
            &mut err,
        )
        .unwrap();
        assert_eq!(opts.name.as_deref(), Some("myproj"));
        assert_eq!(opts.standard.as_deref(), Some("iso26262"));
        assert!(!opts.force);
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_force_flag() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--force"]), &mut err).unwrap();
        assert!(opts.force);
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_dir_flag() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--dir", "/tmp/proj"]), &mut err).unwrap();
        assert_eq!(opts.dir.as_ref().unwrap().to_str().unwrap(), "/tmp/proj");
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_dir_eq_form() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--dir=/tmp/proj"]), &mut err).unwrap();
        assert_eq!(opts.dir.as_ref().unwrap().to_str().unwrap(), "/tmp/proj");
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_asil_flag() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--asil", "B"]), &mut err).unwrap();
        assert_eq!(opts.asil.as_deref(), Some("B"));
        assert!(opts.sil.is_none());
        assert!(opts.dal.is_none());
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_sil_flag() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--sil", "3"]), &mut err).unwrap();
        assert_eq!(opts.sil.as_deref(), Some("3"));
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_dal_flag() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--dal", "A"]), &mut err).unwrap();
        assert_eq!(opts.dal.as_deref(), Some("A"));
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_project_version_flag() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--project-version", "1.2.3"]), &mut err).unwrap();
        assert_eq!(opts.project_version.as_deref(), Some("1.2.3"));
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_name_eq_form() {
        let mut err = Vec::new();
        let opts = parse(&sv(&["--name=myproj"]), &mut err).unwrap();
        assert_eq!(opts.name.as_deref(), Some("myproj"));
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_missing_value_returns_none() {
        let mut err = Vec::new();
        assert!(parse(&sv(&["--name"]), &mut err).is_none());
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("requires an argument"));
    }

    //fusa:test REQ-CFG001
    #[test]
    fn parse_unknown_flag_returns_none() {
        let mut err = Vec::new();
        assert!(parse(&sv(&["--unknown"]), &mut err).is_none());
        assert!(String::from_utf8(err).unwrap().contains("unknown flag"));
    }

    // ── run ───────────────────────────────────────────────────────────────

    //fusa:test REQ-CFG001
    //fusa:test REQ-CFG002
    #[test]
    fn run_creates_config_and_reqs() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "--dir",
                dir.path().to_str().unwrap(),
                "--name",
                "testproj",
                "--standard",
                "iso26262",
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        assert!(dir.path().join(crate::config::CONFIG_FILE).exists());
        assert!(dir.path().join(crate::config::REQS_FILE).exists());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Created"));
    }

    //fusa:test REQ-CFG003
    #[test]
    fn run_force_overwrites() {
        let dir = tempfile::TempDir::new().unwrap();
        let args = sv(&[
            "--dir",
            dir.path().to_str().unwrap(),
            "--name",
            "proj",
            "--standard",
            "iso26262",
        ]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(&args, &mut out, &mut err);

        // Second run without force — files already exist
        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let code2 = run(&args, &mut out2, &mut err2);
        assert_eq!(code2, 0);
        let e2 = String::from_utf8(err2).unwrap();
        assert!(e2.contains("already exists"));

        // Third run with force — should succeed silently
        let force_args = sv(&[
            "--dir",
            dir.path().to_str().unwrap(),
            "--name",
            "proj",
            "--standard",
            "iso26262",
            "--force",
        ]);
        let mut out3 = Vec::new();
        let mut err3 = Vec::new();
        let code3 = run(&force_args, &mut out3, &mut err3);
        assert_eq!(code3, 0);
    }

    //fusa:test REQ-CFG001
    #[test]
    fn run_with_asil() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &sv(&[
                "--dir",
                dir.path().to_str().unwrap(),
                "--name",
                "proj",
                "--standard",
                "iso26262",
                "--asil",
                "D",
            ]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let config_path = dir.path().join(crate::config::CONFIG_FILE);
        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(config_path).unwrap()).unwrap();
        assert_eq!(cfg["asil"], "D");
    }

    //fusa:test REQ-CFG001
    #[test]
    fn run_parse_fails_returns_usage() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&sv(&["--bad-flag"]), &mut out, &mut err);
        assert_eq!(code, 2);
    }
}
