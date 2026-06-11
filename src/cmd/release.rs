//fusa:req REQ-RELEASE001
//fusa:req REQ-RELEASE002
//fusa:req REQ-RELEASE003
//fusa:req REQ-RELEASE004
//fusa:req REQ-RELEASE005
//fusa:req REQ-RELEASE006
//fusa:req REQ-RELEASE007
//fusa:req REQ-RELEASE008
use crate::auditpack::{pack, AUDIT_PACK_FILE};
use crate::release::{build_manifest, build_provenance, build_sbom, save_json, MANIFEST_FILE, PROVENANCE_FILE, SBOM_FILE};
use crate::types::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};
use std::io::Write;
use std::path::PathBuf;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts.dir.clone().unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    let out_dir = opts.output_dir.clone().unwrap_or_else(|| project_root.clone());

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        writeln!(stderr, "rsfusa release: create output dir: {e}").ok();
        return EXIT_RUNTIME;
    }

    // SBOM
    let sbom = match build_sbom(&project_root) {
        Ok(s) => s,
        Err(e) => {
            writeln!(stderr, "rsfusa release: build SBOM: {e}").ok();
            return EXIT_RUNTIME;
        }
    };
    let comp_count = sbom.components.len();
    let sbom_path = out_dir.join(SBOM_FILE);
    if let Err(e) = save_json(&sbom_path, &sbom) {
        writeln!(stderr, "rsfusa release: save SBOM: {e}").ok();
        return EXIT_RUNTIME;
    }
    writeln!(stdout, "SBOM written to {} ({comp_count} components)", sbom_path.display()).ok();

    // Provenance
    let prov = build_provenance(&project_root);
    let prov_path = out_dir.join(PROVENANCE_FILE);
    if let Err(e) = save_json(&prov_path, &prov) {
        writeln!(stderr, "rsfusa release: save provenance: {e}").ok();
        return EXIT_RUNTIME;
    }
    writeln!(stdout, "Provenance written to {}", prov_path.display()).ok();

    // Artifact manifest
    let manifest = match build_manifest(&[&sbom_path, &prov_path], &out_dir) {
        Ok(m) => m,
        Err(e) => {
            writeln!(stderr, "rsfusa release: build manifest: {e}").ok();
            return EXIT_RUNTIME;
        }
    };
    let art_count = manifest.artifacts.len();
    let manifest_path = out_dir.join(MANIFEST_FILE);
    if let Err(e) = save_json(&manifest_path, &manifest) {
        writeln!(stderr, "rsfusa release: save manifest: {e}").ok();
        return EXIT_RUNTIME;
    }
    writeln!(stdout, "Artifact manifest written to {} ({art_count} artifacts)", manifest_path.display()).ok();

    if opts.full {
        let pack_path = out_dir.join(AUDIT_PACK_FILE);
        match pack(&project_root, &pack_path) {
            Ok(m) => {
                writeln!(stdout, "Audit pack written to {} ({} files)", pack_path.display(), m.files.len()).ok();
            }
            Err(e) => {
                writeln!(stderr, "rsfusa release --full: audit-pack: {e}").ok();
                return EXIT_RUNTIME;
            }
        }
    }

    EXIT_OK
}

struct Opts {
    dir: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    full: bool,
    _spdx_version: String,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        output_dir: None,
        full: false,
        _spdx_version: "2.3".to_string(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--full" => opts.full = true,
            flag @ ("--dir" | "--output-dir" | "--spdx-version") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa release: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                let val = args[i].clone();
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(val)),
                    "--output-dir" => opts.output_dir = Some(PathBuf::from(val)),
                    "--spdx-version" => opts._spdx_version = val,
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") { opts.dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--output-dir=") { opts.output_dir = Some(PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--spdx-version=") { opts._spdx_version = v.to_string(); }
                else {
                    writeln!(stderr, "rsfusa release: unknown flag: {other}").ok();
                    return None;
                }
            }
        }
        i += 1;
    }
    Some(opts)
}
