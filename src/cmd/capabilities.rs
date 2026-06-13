//fusa:req REQ-CLI010
//fusa:req REQ-CAP-STD001
use crate::types::{EXIT_OK, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let format = parse_format(args);
    if format.as_deref() != Some("json") && format.is_some() && format.as_deref() != Some("") {
        writeln!(
            stderr,
            "rsfusa capabilities: only --format json is supported"
        )
        .ok();
        return EXIT_USAGE;
    }

    let cap = serde_json::json!({
        "schemaVersion": SPEC_VERSION,
        "kind": "capabilities",
        "tool": TOOL_NAME,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "specVersion": SPEC_VERSION,
        "commands": {
            "must": ["version", "capabilities", "init", "check", "report", "trace", "qualify", "release", "audit-pack"],
            "should": ["lint", "analyze", "diff", "verify", "vuln", "cyber", "coverage", "coupling", "comp", "fmea", "tara", "safety-case", "boundary", "hara"],
            "may": ["iso26262", "iec61508", "do178c", "do178", "iso21434", "unece", "misra", "iec62443", "slsa", "disposition", "badge", "sas", "sci", "impact", "metrics", "fix", "sign", "req", "pr", "template", "hooks"]
        },
        "formats": {
            "check":       ["text", "json", "html", "sarif"],
            "report":      ["text", "json", "html", "sarif"],
            "lint":        ["text", "json", "html", "sarif"],
            "analyze":     ["text", "json", "html", "sarif"],
            "trace":       ["text", "json", "md"],
            "qualify":     ["text", "json"],
            "cyber":       ["text", "json"],
            "coverage":    ["text", "json"],
            "comp":        ["text", "json"],
            "diff":        ["text", "json"],
            "fix":         ["text", "json"],
            "iso26262":    ["text", "json"],
            "iec61508":    ["text", "json"],
            "do178c":      ["text", "json"],
            "iso21434":    ["text", "json"],
            "unece":       ["text", "json"],
            "misra":       ["text", "json"],
            "iec62443":    ["text", "json"],
            "slsa":        ["text", "json"],
            "sci":         ["json", "md"],
            "sas":         ["md", "json"]
        },
        "standards": [
            "iso26262", "iec61508", "do178c", "iso21434",
            "iec62443-4-1", "iec62443-4-2", "unece-r155", "unece-r156",
            "misra-c", "misra-cpp", "autosar-cpp14", "cert-c", "cert-cpp", "generic"
        ],
        "rules": {
            "fusa": ["FUSA001", "FUSA002", "FUSA003", "FUSA004", "FUSA005", "FUSA006", "FUSA007"],
            "lint": ["LINT001", "LINT002", "LINT003", "LINT004", "LINT005", "LINT006"],
            "analyze": ["ANA001", "ANA002", "ANA003", "ANA004", "ANA005", "ANA006"],
            "cyber": ["CYBER001", "CYBER002", "CYBER003", "CYBER004", "CYBER005",
                      "CYBER006", "CYBER007", "CYBER008", "CYBER009", "CYBER010",
                      "CYBER011", "CYBER012", "CYBER013", "CYBER014", "CYBER015",
                      "CYBER016", "CYBER017", "CYBER018", "CYBER019", "CYBER020"]
        }
    });

    writeln!(stdout, "{}", serde_json::to_string_pretty(&cap).unwrap()).ok();
    EXIT_OK
}

fn parse_format(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--format" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(v) = args[i].strip_prefix("--format=") {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
}
