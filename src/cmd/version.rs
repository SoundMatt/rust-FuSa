use crate::types::{EXIT_OK, EXIT_USAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use std::io::Write;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let format = parse_format(args, stderr);
    match format.as_deref() {
        Some("text") | Some("") | None => {
            writeln!(stdout, "{TOOL_NAME} {VERSION}").ok();
            EXIT_OK
        }
        Some("json") => {
            let v = serde_json::json!({
                "tool": TOOL_NAME,
                "version": VERSION,
                "specVersion": SPEC_VERSION
            });
            writeln!(stdout, "{}", serde_json::to_string_pretty(&v).unwrap()).ok();
            EXIT_OK
        }
        Some(other) => {
            writeln!(
                stderr,
                "rsfusa version: unknown --format {other:?} (text or json)"
            )
            .ok();
            EXIT_USAGE
        }
    }
}

fn parse_format(args: &[String], stderr: &mut dyn Write) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--format" {
            if i + 1 < args.len() {
                return Some(args[i + 1].clone());
            }
            writeln!(stderr, "rsfusa version: --format requires an argument").ok();
            return Some("".to_string());
        }
        if let Some(val) = args[i].strip_prefix("--format=") {
            return Some(val.to_string());
        }
        i += 1;
    }
    None
}
