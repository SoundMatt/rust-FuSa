use crate::types::{EXIT_OK, EXIT_USAGE, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let format = parse_format(args);
    if format.as_deref() != Some("json") && format.is_some() && format.as_deref() != Some("") {
        writeln!(stderr, "rsfusa capabilities: only --format json is supported").ok();
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
        "commands": [
            "version", "capabilities", "init", "check", "trace",
            "qualify", "release", "audit-pack", "report"
        ],
        "formats": {
            "check":  ["text", "json", "html", "sarif"],
            "report": ["text", "json", "html", "sarif"],
            "trace":  ["text", "json", "md"],
            "qualify": ["text", "json"]
        },
        "standards": ["iso26262", "iec61508", "do178c", "iso21434"]
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
