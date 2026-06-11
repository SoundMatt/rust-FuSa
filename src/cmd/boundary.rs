// `rsfusa boundary` — component boundary diagram from Cargo.toml + module graph.
// Writes boundary.dot and boundary.mermaid.
//fusa:req REQ-BOUNDARY001
//fusa:req REQ-BOUNDARY002
//fusa:req REQ-BOUNDARY003
//fusa:req REQ-BOUNDARY004
//fusa:req REQ-BOUNDARY005

use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use walkdir::WalkDir;

pub const BOUNDARY_DOT: &str = "boundary.dot";
pub const BOUNDARY_MERMAID: &str = "boundary.mermaid";

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Parse Cargo.toml for package name and dependencies
    let (pkg_name, ext_deps) = parse_cargo_toml(&project_root);

    // Scan internal modules and their imports
    let module_imports = scan_module_imports(&project_root);

    let dot_path = opts.dot_output.unwrap_or_else(|| {
        project_root
            .join(BOUNDARY_DOT)
            .to_string_lossy()
            .into_owned()
    });
    let mermaid_path = opts.mermaid_output.unwrap_or_else(|| {
        project_root
            .join(BOUNDARY_MERMAID)
            .to_string_lossy()
            .into_owned()
    });

    // Generate DOT
    let mut dot = String::from("digraph boundary {\n");
    dot.push_str("  rankdir=LR;\n");
    dot.push_str("  node [shape=box];\n");
    dot.push_str(&format!(
        "  \"{pkg_name}\" [shape=ellipse style=filled fillcolor=lightblue];\n"
    ));

    for dep in &ext_deps {
        dot.push_str(&format!("  \"{}\" [style=dashed];\n", sanitise(dep)));
        dot.push_str(&format!(
            "  \"{}\" -> \"{}\";\n",
            sanitise(&pkg_name),
            sanitise(dep)
        ));
    }

    let mut seen_edges: HashSet<String> = HashSet::new();
    for (module, imports) in &module_imports {
        let m = sanitise(module);
        dot.push_str(&format!("  \"{m}\";\n"));
        for imp in imports {
            let edge = format!("{m}->{}", sanitise(imp));
            if seen_edges.insert(edge) {
                dot.push_str(&format!("  \"{m}\" -> \"{}\";\n", sanitise(imp)));
            }
        }
    }
    dot.push_str("}\n");

    match std::fs::write(&dot_path, &dot) {
        Ok(_) => writeln!(stdout, "Boundary DOT written to {dot_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa boundary: write {dot_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    // Generate Mermaid
    let mut mermaid = String::from("graph LR\n");
    mermaid.push_str(&format!("  {}[\"{}\"]\n", mermaid_id(&pkg_name), pkg_name));

    for dep in &ext_deps {
        mermaid.push_str(&format!("  {}[\"{dep}\"]\n", mermaid_id(dep)));
        mermaid.push_str(&format!(
            "  {} --> {}\n",
            mermaid_id(&pkg_name),
            mermaid_id(dep)
        ));
    }

    let mut seen_edges: HashSet<String> = HashSet::new();
    for (module, imports) in &module_imports {
        mermaid.push_str(&format!("  {}[\"{}\"]\n", mermaid_id(module), module));
        for imp in imports {
            let edge = format!("{}->{imp}", mermaid_id(module));
            if seen_edges.insert(edge) {
                mermaid.push_str(&format!(
                    "  {} --> {}\n",
                    mermaid_id(module),
                    mermaid_id(imp)
                ));
            }
        }
    }

    match std::fs::write(&mermaid_path, mermaid) {
        Ok(_) => writeln!(stdout, "Boundary mermaid written to {mermaid_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa boundary: write {mermaid_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    writeln!(
        stdout,
        "Package: {pkg_name}  External deps: {}  Modules: {}",
        ext_deps.len(),
        module_imports.len()
    )
    .ok();
    EXIT_OK
}

fn parse_cargo_toml(root: &PathBuf) -> (String, Vec<String>) {
    let cargo_path = root.join("Cargo.toml");
    let data = match std::fs::read_to_string(&cargo_path) {
        Ok(d) => d,
        Err(_) => return ("unknown".to_string(), vec![]),
    };

    let parsed: toml::Value = match toml::from_str(&data) {
        Ok(v) => v,
        Err(_) => return ("unknown".to_string(), vec![]),
    };

    let pkg_name = parsed
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut deps = Vec::new();
    if let Some(dependencies) = parsed.get("dependencies").and_then(|d| d.as_table()) {
        for (name, _) in dependencies {
            deps.push(name.clone());
        }
    }
    deps.sort();

    (pkg_name, deps)
}

fn scan_module_imports(root: &PathBuf) -> HashMap<String, Vec<String>> {
    let mut result: HashMap<String, Vec<String>> = HashMap::new();
    let src_dir = root.join("src");
    let scan_root = if src_dir.exists() {
        src_dir
    } else {
        root.clone()
    };

    for entry in WalkDir::new(&scan_root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let module_name = rel
            .trim_end_matches(".rs")
            .replace("src/", "")
            .replace('/', "::");

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut imports: Vec<String> = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("use crate::") {
                let name = trimmed
                    .trim_start_matches("use crate::")
                    .split(|c: char| c == ';' || c == ':' || c == '{' || c == ' ')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() && !imports.contains(&name) {
                    imports.push(name);
                }
            }
        }

        if !imports.is_empty() {
            result.insert(module_name, imports);
        }
    }
    result
}

fn sanitise(s: &str) -> String {
    s.replace('-', "_").replace('/', "_").replace(':', "_")
}

fn mermaid_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

struct Opts {
    dir: Option<PathBuf>,
    dot_output: Option<String>,
    mermaid_output: Option<String>,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        dot_output: None,
        mermaid_output: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            flag @ ("--dir" | "--dot" | "--mermaid") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa boundary: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--dot" => opts.dot_output = Some(args[i].clone()),
                    "--mermaid" => opts.mermaid_output = Some(args[i].clone()),
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else {
                    writeln!(stderr, "rsfusa boundary: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
