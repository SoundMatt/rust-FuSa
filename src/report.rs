// Report rendering: text, JSON, SARIF (§4, §2.9).
//fusa:req REQ-RPT001
//fusa:req REQ-RPT002
//fusa:req REQ-RPT003
//fusa:req REQ-HTML001
//fusa:req REQ-HTML002
//fusa:req REQ-HTML003

use crate::types::{Finding, Severity, LANGUAGE, SPEC_VERSION, TOOL_NAME, VERSION};
use serde::Serialize;
use std::io::Write;

// ── Envelope ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckReport {
    pub schema_version: String,
    pub kind: String,
    pub tool: String,
    pub tool_version: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub project_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asil: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sil: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dal: Option<String>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub total: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

impl CheckReport {
    pub fn new(
        project_root: &std::path::Path,
        findings: Vec<Finding>,
        cfg: Option<&crate::config::FusaConfig>,
    ) -> Self {
        let summary = Summary {
            total: findings.len(),
            errors: findings
                .iter()
                .filter(|f| f.severity == Severity::Error)
                .count(),
            warnings: findings
                .iter()
                .filter(|f| f.severity == Severity::Warning)
                .count(),
            infos: findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count(),
        };
        let (project, standard, asil, sil, dal) = if let Some(c) = cfg {
            let (ak, av, ad) = match c.integrity_level() {
                Some(("asil", v)) => (Some(v.to_string()), None::<String>, None::<String>),
                Some(("sil", v)) => (None, Some(v.to_string()), None),
                Some(("dal", v)) => (None, None, Some(v.to_string())),
                _ => (None, None, None),
            };
            (
                Some(c.project.name.clone()),
                Some(c.standard.clone()),
                ak,
                av,
                ad,
            )
        } else {
            (None, None, None, None, None)
        };
        Self {
            schema_version: SPEC_VERSION.to_string(),
            kind: "check-report".to_string(),
            tool: TOOL_NAME.to_string(),
            tool_version: VERSION.to_string(),
            language: LANGUAGE.to_string(),
            generated_at: chrono::Utc::now(),
            project_root: project_root.to_string_lossy().into_owned(),
            project,
            standard,
            asil,
            sil,
            dal,
            findings,
            summary,
            error: None,
        }
    }
}

// ── Render ─────────────────────────────────────────────────────────────────

pub fn render_json<W: Write + ?Sized>(w: &mut W, report: &CheckReport) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(report).expect("serialize report");
    writeln!(w, "{json}")
}

pub fn render_text<W: Write + ?Sized>(
    w: &mut W,
    report: &CheckReport,
    use_color: bool,
) -> std::io::Result<()> {
    for f in &report.findings {
        let sev = severity_label(&f.severity, use_color);
        writeln!(
            w,
            "{sev} [{rule}] {file}:{line}: {msg}",
            sev = sev,
            rule = f.rule_id,
            file = f.location.file,
            line = f.location.line,
            msg = f.message
        )?;
        writeln!(w, "  Remediation: {}", f.remediation)?;
        writeln!(w, "  Fingerprint: {}", f.fingerprint)?;
    }
    writeln!(w)?;
    writeln!(
        w,
        "Summary: {} total  {} errors  {} warnings  {} infos",
        report.summary.total, report.summary.errors, report.summary.warnings, report.summary.infos
    )
}

fn severity_label(sev: &Severity, color: bool) -> String {
    if !color {
        return sev.to_string();
    }
    match sev {
        Severity::Error => "\x1b[31mERROR\x1b[0m".to_string(),
        Severity::Warning => "\x1b[33mWARNING\x1b[0m".to_string(),
        Severity::Info => "\x1b[36mINFO\x1b[0m".to_string(),
    }
}

pub fn render_sarif<W: Write + ?Sized>(w: &mut W, report: &CheckReport) -> std::io::Result<()> {
    // SARIF 2.1.0 per §4
    use serde_json::{json, Value};

    let rules: Vec<Value> = {
        let mut seen = std::collections::HashSet::new();
        let mut v = Vec::new();
        for f in &report.findings {
            if seen.insert(&f.rule_id) {
                let mut props = serde_json::Map::new();
                props.insert("category".to_string(), json!(f.category.to_string()));
                if let Some(s) = &f.standard {
                    props.insert("standard".to_string(), json!(s));
                }
                if let Some(c) = &f.clause {
                    props.insert("clause".to_string(), json!(c));
                }
                v.push(json!({
                    "id": f.rule_id,
                    "shortDescription": { "text": f.remediation },
                    "properties": props
                }));
            }
        }
        v
    };

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "note",
            };
            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.location.file },
                        "region": { "startLine": f.location.line.max(1) }
                    }
                }],
                "fingerprints": { "sha256/v1": f.fingerprint }
            })
        })
        .collect();

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": VERSION,
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    let json = serde_json::to_string_pretty(&sarif).expect("serialize sarif");
    writeln!(w, "{json}")
}

pub fn render_html<W: Write + ?Sized>(w: &mut W, report: &CheckReport) -> std::io::Result<()> {
    writeln!(w, "<!DOCTYPE html><html lang=\"en\"><head>")?;
    writeln!(
        w,
        "<meta charset=\"UTF-8\"><title>rust-FuSa Check Report</title>"
    )?;
    writeln!(w, "<style>body{{font-family:monospace;margin:2rem}}table{{border-collapse:collapse;width:100%}}")?;
    writeln!(
        w,
        "th,td{{border:1px solid #ccc;padding:4px 8px;text-align:left}}"
    )?;
    writeln!(
        w,
        ".ERROR{{color:#c00}}.WARNING{{color:#a60}}.INFO{{color:#066}}"
    )?;
    writeln!(w, "</style></head><body>")?;
    writeln!(w, "<h1>rust-FuSa Check Report</h1>")?;
    writeln!(
        w,
        "<p>Generated: {}</p>",
        report.generated_at.format("%Y-%m-%dT%H:%M:%SZ")
    )?;
    writeln!(
        w,
        "<p>Summary: {} total &mdash; {} errors, {} warnings, {} infos</p>",
        report.summary.total, report.summary.errors, report.summary.warnings, report.summary.infos
    )?;
    writeln!(w, "<table><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th><th>Remediation</th></tr>")?;
    for f in &report.findings {
        writeln!(
            w,
            "<tr><td class=\"{sev}\">{sev}</td><td>{rule}</td><td>{file}</td><td>{line}</td><td>{msg}</td><td>{rem}</td></tr>",
            sev = f.severity,
            rule = html_escape(&f.rule_id),
            file = html_escape(&f.location.file),
            line = f.location.line,
            msg = html_escape(&f.message),
            rem = html_escape(&f.remediation),
        )?;
    }
    writeln!(w, "</table></body></html>")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn should_use_color(out: &std::fs::File) -> bool {
    use std::io::IsTerminal;
    out.is_terminal() && std::env::var("NO_COLOR").is_err()
}

pub fn stdout_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal() && std::env::var("NO_COLOR").is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Category, Finding, Location, Severity};

    fn sample_finding(severity: Severity) -> Finding {
        Finding::new(
            "TEST001",
            severity,
            "test message",
            Location::at("src/foo.rs", 10),
            Category::Lint,
            "fix it",
        )
    }

    fn sample_report(findings: Vec<Finding>) -> CheckReport {
        CheckReport::new(std::path::Path::new("/proj"), findings, None)
    }

    // ── html_escape ────────────────────────────────────────────────────────

    //fusa:test REQ-LOC-REL001
    #[test]
    fn html_escape_ampersand() {
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn html_escape_lt_gt() {
        assert_eq!(html_escape("<tag>"), "&lt;tag&gt;");
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn html_escape_quote() {
        assert_eq!(html_escape("\"val\""), "&quot;val&quot;");
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn html_escape_plain() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    // ── CheckReport::new ──────────────────────────────────────────────────

    //fusa:test REQ-LOC-REL001
    //fusa:test REQ-ENG004
    #[test]
    fn check_report_new_summary() {
        let findings = vec![
            sample_finding(Severity::Error),
            sample_finding(Severity::Warning),
            sample_finding(Severity::Info),
        ];
        let r = sample_report(findings);
        assert_eq!(r.summary.total, 3);
        assert_eq!(r.summary.errors, 1);
        assert_eq!(r.summary.warnings, 1);
        assert_eq!(r.summary.infos, 1);
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn check_report_new_fields() {
        let r = sample_report(vec![]);
        assert_eq!(r.kind, "check-report");
        assert_eq!(r.tool, crate::types::TOOL_NAME);
        assert_eq!(r.schema_version, crate::types::SPEC_VERSION);
        assert_eq!(r.language, crate::types::LANGUAGE);
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn check_report_with_config() {
        let cfg = crate::config::FusaConfig::new("myproj", "iso26262");
        let r = CheckReport::new(std::path::Path::new("/proj"), vec![], Some(&cfg));
        assert_eq!(r.project.as_deref(), Some("myproj"));
        assert_eq!(r.standard.as_deref(), Some("iso26262"));
    }

    // ── render_json ───────────────────────────────────────────────────────

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_json_valid_output() {
        let r = sample_report(vec![sample_finding(Severity::Error)]);
        let mut buf = Vec::new();
        render_json(&mut buf, &r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["kind"], "check-report");
        assert_eq!(v["summary"]["total"], 1);
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_json_empty_findings() {
        let r = sample_report(vec![]);
        let mut buf = Vec::new();
        render_json(&mut buf, &r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["summary"]["total"], 0);
        assert!(v["findings"].as_array().unwrap().is_empty());
    }

    // ── render_text ───────────────────────────────────────────────────────

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_text_no_color() {
        let r = sample_report(vec![sample_finding(Severity::Error)]);
        let mut buf = Vec::new();
        render_text(&mut buf, &r, false).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("ERROR"));
        assert!(text.contains("TEST001"));
        assert!(text.contains("src/foo.rs:10"));
        assert!(text.contains("Summary:"));
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_text_with_color() {
        let r = sample_report(vec![
            sample_finding(Severity::Error),
            sample_finding(Severity::Warning),
            sample_finding(Severity::Info),
        ]);
        let mut buf = Vec::new();
        render_text(&mut buf, &r, true).unwrap();
        let text = String::from_utf8(buf).unwrap();
        // ANSI escape codes present
        assert!(text.contains("\x1b["));
        assert!(text.contains("Summary:"));
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_text_empty_findings() {
        let r = sample_report(vec![]);
        let mut buf = Vec::new();
        render_text(&mut buf, &r, false).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("0 total"));
    }

    // ── render_sarif ─────────────────────────────────────────────────────

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_sarif_structure() {
        let r = sample_report(vec![sample_finding(Severity::Error)]);
        let mut buf = Vec::new();
        render_sarif(&mut buf, &r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"], "error");
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_sarif_warning_and_info() {
        let findings = vec![
            sample_finding(Severity::Warning),
            sample_finding(Severity::Info),
        ];
        let r = sample_report(findings);
        let mut buf = Vec::new();
        render_sarif(&mut buf, &r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let results = &v["runs"][0]["results"];
        assert_eq!(results[0]["level"], "warning");
        assert_eq!(results[1]["level"], "note");
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_sarif_deduplicates_rules() {
        let findings = vec![
            sample_finding(Severity::Error),
            sample_finding(Severity::Warning),
        ];
        let r = sample_report(findings);
        let mut buf = Vec::new();
        render_sarif(&mut buf, &r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "same ruleId should appear only once");
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_sarif_with_standard() {
        let mut f = sample_finding(Severity::Error);
        f = f.with_standard("iso26262", "6.4.2");
        let r = sample_report(vec![f]);
        let mut buf = Vec::new();
        render_sarif(&mut buf, &r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["properties"]["standard"], "iso26262");
        assert_eq!(rules[0]["properties"]["clause"], "6.4.2");
    }

    // ── render_html ───────────────────────────────────────────────────────

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_html_structure() {
        let r = sample_report(vec![sample_finding(Severity::Error)]);
        let mut buf = Vec::new();
        render_html(&mut buf, &r).unwrap();
        let html = String::from_utf8(buf).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("rust-FuSa Check Report"));
        assert!(html.contains("<table>"));
        assert!(html.contains("TEST001"));
        assert!(html.contains("src/foo.rs"));
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_html_escapes_content() {
        let mut f = Finding::new(
            "TEST<script>",
            Severity::Error,
            "msg &amp; <b>bold</b>",
            Location::at("src/\"foo\".rs", 1),
            Category::Lint,
            "fix",
        );
        f.standard = None;
        let r = sample_report(vec![f]);
        let mut buf = Vec::new();
        render_html(&mut buf, &r).unwrap();
        let html = String::from_utf8(buf).unwrap();
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&amp;amp;"));
        assert!(html.contains("&quot;foo&quot;"));
    }

    //fusa:test REQ-LOC-REL001
    #[test]
    fn render_html_empty() {
        let r = sample_report(vec![]);
        let mut buf = Vec::new();
        render_html(&mut buf, &r).unwrap();
        let html = String::from_utf8(buf).unwrap();
        assert!(html.contains("0 total"));
        assert!(html.contains("</table>"));
    }
}
