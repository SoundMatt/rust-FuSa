// `rsfusa tara` — Threat Analysis and Risk Assessment per ISO/SAE
// 21434:2021 Clause 15, x-FuSa spec §9.2. Maps `cyber` findings to a threat
// register with an SFOP (Safety/Financial/Operational/Privacy) impact
// rating per Clause 15.7, rather than one generic severity.
//
// `impact.{safety,financial,operational,privacy}` uses the x-FuSa family's
// canonical closed enum `critical|major|moderate|negligible` — a distinct
// scale from `attackFeasibility`'s `high|medium|low|very-low` — and `risk`
// is `critical|high|medium|low`, derived from the family's canonical risk
// combination table (highest SFOP impact x attackFeasibility). See
// SoundMatt/FuSaOps `docs/x-fusa-spec.md` §9.2 "Closed enums" / "Risk
// combination table" (clarified following SoundMatt/rust-FuSa#38 review).
//fusa:req REQ-TARA001
//fusa:req REQ-TARA002
//fusa:req REQ-TARA003
//fusa:req REQ-TARA004
//fusa:req REQ-TARA005
//fusa:req REQ-TARA006
//fusa:req REQ-TARA007

use crate::attestation::Attestation;
use crate::config::load;
use crate::cyber;
use crate::engine::Registry;
use crate::stub::{
    apply_project_dispositions, detect_blank_fallback, detect_placeholder, has_open_errors,
    has_open_warnings, QualField,
};
use crate::types::{
    EXIT_GATE_FAIL, EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION,
};
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const TARA_JSON: &str = "tara.json";
pub const TARA_MD: &str = "tara.md";

/// §21434 Clause 15.7 SFOP impact rating. Each axis is one of the x-FuSa
/// family's canonical closed enum: `critical` | `major` | `moderate` |
/// `negligible` (x-FuSa spec §9.2).
#[derive(Serialize, Clone, Copy, Debug)]
#[serde(rename_all = "camelCase")]
struct Impact {
    safety: &'static str,
    financial: &'static str,
    operational: &'static str,
    privacy: &'static str,
}

/// §9.2 `tara.json` `threats[]` shape.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct Threat {
    id: String,
    asset: String,
    threat: String,
    cwe: &'static str,
    attack_vector: &'static str,
    attack_feasibility: &'static str,
    impact: Impact,
    risk: &'static str,
    treatment: &'static str,
    mitigations: Vec<String>,
    location: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    cyber_rule_id: Option<String>,
}

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let opts = match parse(args, stderr) {
        Some(o) => o,
        None => return EXIT_USAGE,
    };

    let project_root = opts
        .dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let cfg = match load(&project_root.join(".fusa.json")) {
        Ok(c) => c,
        Err(crate::config::ConfigError::NotFound(_)) => crate::config::FusaConfig::new(
            project_root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("project"),
            "generic",
        ),
        Err(e) => {
            writeln!(stderr, "rsfusa tara: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let mut reg = Registry::new();
    cyber::register_all(&mut reg);
    let result = reg.run(&project_root, &cfg);

    // §1.6 rule 1: no cyber findings means an honestly-empty threat
    // register, never a filler/boilerplate row.
    let mut threats: Vec<Threat> = Vec::new();
    for finding in &result.findings {
        let profile = cyber_rule_profile(&finding.rule_id);
        let id = format!("TARA-{:03}", threats.len() + 1);
        let feasibility = profile.feasibility;
        let impact = profile.impact;
        let risk = derive_risk(feasibility, &impact);
        threats.push(Threat {
            id,
            asset: finding.location.file.clone(),
            threat: format!(
                "{} ({}:{})",
                finding.message, finding.location.file, finding.location.line
            ),
            cwe: profile.cwe,
            attack_vector: profile.attack_vector,
            attack_feasibility: feasibility,
            impact,
            risk,
            treatment: "mitigate",
            mitigations: vec![finding.remediation.clone()],
            location: serde_json::json!({ "file": finding.location.file, "line": finding.location.line }),
            cyber_rule_id: Some(finding.rule_id.clone()),
        });
    }

    let assets_in_project = cyber::rust_sources(&project_root, &cfg).len();
    let assets_analyzed: usize = threats
        .iter()
        .map(|t| t.asset.as_str())
        .collect::<HashSet<_>>()
        .len();
    let coverage_pct = if assets_in_project == 0 {
        100.0
    } else {
        (assets_analyzed as f64 * 1000.0 / assets_in_project as f64).round() / 10.0
    };

    let mut qual_fields = Vec::new();
    for t in &threats {
        qual_fields.push(QualField::new(t.id.clone(), "threat", t.threat.clone()));
    }

    let content = serde_json::json!({ "threats": threats });
    let content_hash = crate::canonjson::content_hash(&content);
    let json_path = opts
        .json_output
        .clone()
        .unwrap_or_else(|| project_root.join(TARA_JSON).to_string_lossy().into_owned());
    let attestation: Option<Attestation> = crate::attestation::carry_forward(
        crate::attestation::read_existing(Path::new(&json_path)),
        &content_hash,
    );
    let attestation_valid = attestation
        .as_ref()
        .is_some_and(|a| crate::attestation::is_valid(a, &content_hash));

    let mut findings = detect_placeholder(TARA_JSON, &qual_fields);
    if !attestation_valid {
        findings.extend(detect_blank_fallback(TARA_JSON, &qual_fields));
    }
    apply_project_dispositions(&project_root, &mut findings);
    for f in &findings {
        writeln!(stderr, "{}: {} ({})", f.severity, f.message, f.rule_id).ok();
    }

    let report = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "tara-report",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "standard": "iso21434",
        "threats": threats,
        "summary": {
            "assetsAnalyzed": assets_analyzed,
            "assetsInProject": assets_in_project,
            "coveragePct": coverage_pct,
            "assetInventoryMethod": "each distinct Rust source file scanned by the `cyber` ruleset is treated as one candidate asset; assetsAnalyzed counts distinct files with >=1 identified threat, assetsInProject counts every scanned file",
        },
        "attestation": attestation,
        "findings": findings,
    });

    match std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&report).unwrap_or_default() + "\n",
    ) {
        Ok(_) => writeln!(stdout, "TARA written to {json_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa tara: write {json_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    let md_path = opts
        .md_output
        .unwrap_or_else(|| project_root.join(TARA_MD).to_string_lossy().into_owned());
    let mut md = format!(
        "# Threat Analysis and Risk Assessment (TARA)\n\n\
         **Standard**: ISO/SAE 21434 Clause 15  \n\
         **Generated**: {}  \n\
         **Tool**: {} {}  \n\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        TOOL_NAME,
        VERSION
    );
    md.push_str("## Threat Register\n\n");
    md.push_str("| Asset | Threat | CWE | Feasibility | Safety | Financial | Operational | Privacy | Risk | Treatment |\n");
    md.push_str("|-------|--------|-----|-------------|--------|-----------|-------------|---------|------|-----------|\n");
    for t in &threats {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_escape(&t.asset),
            md_escape(&t.threat),
            t.cwe,
            t.attack_feasibility,
            t.impact.safety,
            t.impact.financial,
            t.impact.operational,
            t.impact.privacy,
            t.risk,
            t.treatment,
        ));
    }
    md.push_str(&format!(
        "\n## Summary\n\n- Assets analyzed: {assets_analyzed}\n- Assets in project: {assets_in_project}\n- Coverage: {coverage_pct:.1}%\n"
    ));

    match std::fs::write(&md_path, md) {
        Ok(_) => writeln!(stdout, "TARA markdown written to {md_path}").ok(),
        Err(e) => {
            writeln!(stderr, "rsfusa tara: write {md_path}: {e}").ok();
            return EXIT_RUNTIME;
        }
    };

    if let Some(min) = opts.min_coverage {
        if min > 0.0 && coverage_pct < min {
            writeln!(
                stderr,
                "rsfusa tara: coveragePct {coverage_pct:.1} < --min-coverage {min:.1}"
            )
            .ok();
            return EXIT_GATE_FAIL;
        }
    }
    if has_open_errors(&findings) {
        return EXIT_GATE_FAIL;
    }
    if opts.strict && has_open_warnings(&findings) {
        return EXIT_GATE_FAIL;
    }

    EXIT_OK
}

struct RuleProfile {
    cwe: &'static str,
    attack_vector: &'static str,
    feasibility: &'static str,
    impact: Impact,
}

/// Per-rule ISO 21434 profile: CWE, attack vector, attack-potential rating
/// (`feasibility`, `high|medium|low|very-low`), and SFOP `impact`
/// (`critical|major|moderate|negligible` — a distinct, non-interchangeable
/// scale from `feasibility`'s, per x-FuSa spec §9.2).
fn cyber_rule_profile(rule_id: &str) -> RuleProfile {
    let (cwe, attack_vector, feasibility, impact) = match rule_id {
        "CYBER001" => (
            "CWE-798",
            "local file/binary inspection",
            "high",
            ("moderate", "major", "moderate", "major"),
        ),
        "CYBER002" => (
            "CWE-89",
            "network request",
            "high",
            ("negligible", "major", "moderate", "major"),
        ),
        "CYBER003" => (
            "CWE-22",
            "network request",
            "high",
            ("negligible", "moderate", "moderate", "major"),
        ),
        "CYBER004" => (
            "CWE-330",
            "local/network prediction",
            "medium",
            ("moderate", "moderate", "negligible", "moderate"),
        ),
        "CYBER005" => (
            "CWE-190",
            "crafted input",
            "medium",
            ("moderate", "negligible", "moderate", "negligible"),
        ),
        "CYBER006" => (
            "CWE-319",
            "network eavesdropping",
            "high",
            ("negligible", "moderate", "negligible", "major"),
        ),
        "CYBER007" => (
            "CWE-78",
            "network request",
            "high",
            ("major", "major", "major", "major"),
        ),
        "CYBER008" => (
            "CWE-327",
            "cryptanalysis",
            "medium",
            ("negligible", "moderate", "negligible", "major"),
        ),
        "CYBER009" => (
            "CWE-532",
            "local log access",
            "medium",
            ("negligible", "negligible", "negligible", "major"),
        ),
        "CYBER010" => (
            "CWE-502",
            "crafted serialized input",
            "high",
            ("major", "moderate", "major", "moderate"),
        ),
        "CYBER011" => (
            "CWE-125",
            "crafted input",
            "medium",
            ("moderate", "negligible", "moderate", "negligible"),
        ),
        "CYBER012" => (
            "CWE-400",
            "resource exhaustion",
            "medium",
            ("negligible", "moderate", "major", "negligible"),
        ),
        "CYBER013" => (
            "CWE-295",
            "network man-in-the-middle",
            "medium",
            ("moderate", "moderate", "negligible", "major"),
        ),
        "CYBER014" => (
            "CWE-367",
            "local race condition",
            "low",
            ("moderate", "negligible", "moderate", "negligible"),
        ),
        "CYBER015" => (
            "CWE-732",
            "local file access",
            "medium",
            ("negligible", "negligible", "moderate", "moderate"),
        ),
        "CYBER016" => (
            "CWE-526",
            "local environment inspection",
            "low",
            ("negligible", "negligible", "negligible", "moderate"),
        ),
        "CYBER017" => (
            "CWE-22",
            "crafted path input",
            "high",
            ("negligible", "moderate", "moderate", "major"),
        ),
        "CYBER018" => (
            "CWE-415",
            "crafted input/timing",
            "low",
            ("moderate", "negligible", "moderate", "negligible"),
        ),
        "CYBER019" => (
            "CWE-134",
            "crafted format string input",
            "medium",
            ("moderate", "negligible", "moderate", "negligible"),
        ),
        "CYBER020" => (
            "CWE-20",
            "crafted input",
            "high",
            ("moderate", "moderate", "moderate", "moderate"),
        ),
        _ => (
            "CWE-0",
            "unspecified",
            "low",
            ("negligible", "negligible", "negligible", "negligible"),
        ),
    };
    RuleProfile {
        cwe,
        attack_vector,
        feasibility,
        impact: Impact {
            safety: impact.0,
            financial: impact.1,
            operational: impact.2,
            privacy: impact.3,
        },
    }
}

/// `attackFeasibility` rank: `high` | `medium` | `low` | `very-low`
/// (ISO 21434 attack-potential rating; unchanged domain).
fn level_rank(l: &str) -> u8 {
    match l {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "very-low" => 0,
        _ => 0,
    }
}

/// SFOP `impact` axis rank: the x-FuSa family's canonical `critical` |
/// `major` | `moderate` | `negligible` closed enum (x-FuSa spec §9.2) — a
/// distinct scale from `attackFeasibility`'s, per the spec's explicit
/// clarification that a tool MUST NOT substitute one vocabulary for the
/// other even though both are 4-level.
fn impact_rank(l: &str) -> u8 {
    match l {
        "critical" => 3,
        "major" => 2,
        "moderate" => 1,
        "negligible" => 0,
        _ => 0,
    }
}

/// `risk` combination table (x-FuSa spec §9.2 "Risk combination table"):
/// the x-FuSa family's own canonical feasibility x highest-SFOP-impact ->
/// risk lookup, indexed `[impact_rank][feasibility_rank]`
/// (`negligible`..`critical` / `very-low`..`high`, both ascending).
const RISK_TABLE: [[&str; 4]; 4] = [
    // negligible impact
    ["low", "low", "low", "low"],
    // moderate impact
    ["low", "low", "medium", "medium"],
    // major impact
    ["medium", "medium", "high", "high"],
    // critical impact
    ["medium", "high", "critical", "critical"],
];

/// `risk` per the x-FuSa spec §9.2 risk combination table: looked up from
/// the **highest-ranked** of the four SFOP impact axes against
/// `attackFeasibility`.
fn derive_risk(feasibility: &str, impact: &Impact) -> &'static str {
    let highest_impact = [
        impact.safety,
        impact.financial,
        impact.operational,
        impact.privacy,
    ]
    .into_iter()
    .map(impact_rank)
    .max()
    .unwrap_or(0);
    RISK_TABLE[highest_impact as usize][level_rank(feasibility) as usize]
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

struct Opts {
    dir: Option<PathBuf>,
    json_output: Option<String>,
    md_output: Option<String>,
    min_coverage: Option<f64>,
    strict: bool,
}

fn parse(args: &[String], stderr: &mut dyn Write) -> Option<Opts> {
    let mut opts = Opts {
        dir: None,
        json_output: None,
        md_output: None,
        min_coverage: None,
        strict: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--strict" | "--require-attestation" => opts.strict = true,
            flag @ ("--dir" | "--output" | "--md" | "--min-coverage") => {
                if i + 1 >= args.len() {
                    writeln!(stderr, "rsfusa tara: {flag} requires an argument").ok();
                    return None;
                }
                i += 1;
                match flag {
                    "--dir" => opts.dir = Some(PathBuf::from(args[i].clone())),
                    "--output" => opts.json_output = Some(args[i].clone()),
                    "--md" => opts.md_output = Some(args[i].clone()),
                    "--min-coverage" => {
                        opts.min_coverage = match args[i].parse::<f64>() {
                            Ok(v) => Some(v),
                            Err(_) => {
                                writeln!(stderr, "rsfusa tara: --min-coverage requires a number")
                                    .ok();
                                return None;
                            }
                        }
                    }
                    _ => {}
                }
            }
            other => {
                if let Some(v) = other.strip_prefix("--dir=") {
                    opts.dir = Some(PathBuf::from(v));
                } else if let Some(v) = other.strip_prefix("--output=") {
                    opts.json_output = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--min-coverage=") {
                    opts.min_coverage = v.parse::<f64>().ok();
                } else {
                    writeln!(stderr, "rsfusa tara: unknown flag: {other}").ok();
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

    fn impact_of(l: &'static str) -> Impact {
        Impact {
            safety: l,
            financial: l,
            operational: l,
            privacy: l,
        }
    }

    /// x-FuSa spec §9.2 risk combination table, verified at its corners and
    /// a mixed case (highest of the four SFOP axes wins, not an average).
    //fusa:test REQ-TARA006
    #[test]
    fn derive_risk_follows_the_canonical_combination_table() {
        assert_eq!(derive_risk("high", &impact_of("critical")), "critical");
        assert_eq!(derive_risk("medium", &impact_of("critical")), "critical");
        assert_eq!(derive_risk("low", &impact_of("critical")), "high");
        assert_eq!(derive_risk("very-low", &impact_of("critical")), "medium");
        assert_eq!(derive_risk("high", &impact_of("major")), "high");
        assert_eq!(derive_risk("low", &impact_of("major")), "medium");
        assert_eq!(derive_risk("high", &impact_of("moderate")), "medium");
        assert_eq!(derive_risk("low", &impact_of("moderate")), "low");
        assert_eq!(derive_risk("high", &impact_of("negligible")), "low");
        assert_eq!(derive_risk("very-low", &impact_of("negligible")), "low");
    }

    //fusa:test REQ-TARA006
    #[test]
    fn derive_risk_uses_the_highest_sfop_axis_not_an_average() {
        let impact = Impact {
            safety: "critical",
            financial: "negligible",
            operational: "negligible",
            privacy: "negligible",
        };
        // A single critical axis (safety) dominates three negligible ones.
        assert_eq!(derive_risk("high", &impact), "critical");
    }

    //fusa:test REQ-TARA007
    #[test]
    fn cyber_rule_profile_known_rule_has_real_cwe() {
        let p = cyber_rule_profile("CYBER001");
        assert_eq!(p.cwe, "CWE-798");
    }

    //fusa:test REQ-TARA007
    #[test]
    fn cyber_rule_profile_unknown_rule_falls_back_safely() {
        let p = cyber_rule_profile("CYBER999");
        assert_eq!(p.cwe, "CWE-0");
        assert_eq!(p.feasibility, "low");
        assert_eq!(p.impact.safety, "negligible");
    }

    /// x-FuSa spec §9.2 closed enums (MUST): `impact.*` MUST be one of
    /// `critical|major|moderate|negligible` — NOT `attackFeasibility`'s
    /// `high|medium|low|very-low` vocabulary — for every rule this tool
    /// knows about, not just the ones exercised elsewhere in this suite.
    //fusa:test REQ-TARA006
    #[test]
    fn every_known_rule_uses_the_canonical_impact_vocabulary() {
        let canonical = ["critical", "major", "moderate", "negligible"];
        for i in 1..=20 {
            let rule_id = format!("CYBER{i:03}");
            let p = cyber_rule_profile(&rule_id);
            for level in [
                p.impact.safety,
                p.impact.financial,
                p.impact.operational,
                p.impact.privacy,
            ] {
                assert!(
                    canonical.contains(&level),
                    "{rule_id} impact {level:?} is not in the canonical SFOP enum"
                );
            }
            assert!(
                ["high", "medium", "low", "very-low"].contains(&p.feasibility),
                "{rule_id} feasibility {:?} is not in the canonical attackFeasibility enum",
                p.feasibility
            );
        }
    }

    //fusa:test REQ-TARA006
    #[test]
    fn level_rank_orders_correctly() {
        assert!(level_rank("high") > level_rank("medium"));
        assert!(level_rank("medium") > level_rank("low"));
        assert!(level_rank("low") > level_rank("very-low"));
    }

    //fusa:test REQ-TARA006
    #[test]
    fn impact_rank_orders_correctly() {
        assert!(impact_rank("critical") > impact_rank("major"));
        assert!(impact_rank("major") > impact_rank("moderate"));
        assert!(impact_rank("moderate") > impact_rank("negligible"));
    }
}
