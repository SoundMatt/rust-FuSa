// x-FuSa spec §1.6.1 detection heuristics for evidence-artifact content
// quality — the cross-cutting anti-stub-content baseline (§1.6) applied to
// fmea.json, .fusa-hara.json, tara.json, safety-case.json, and sas.json:
//
//   Rule A / FUSA-STUB001 (always ERROR, disposition-suppressible only): a
//   deny-list scan for literal placeholder/template text.
//
//   Rule B / FUSA-STUB002 (WARNING by default, not gating): a distinct-value
//   ratio check (<0.1 across >=10 entries) flagging a single hardcoded
//   qualitative string applied to every entry regardless of the underlying
//   item. Suppressible only by a valid §1.6.2 attestation (see
//   `crate::attestation`), never by a disposition — the concern is about the
//   artifact as a whole, not one entry.
//
// Both reuse `types::Finding`/`compute_fingerprint`, so they compose with
// disposition/suppression exactly like any other `check` finding — this
// module defines two new `ruleId`s, not a second finding mechanism.
//fusa:req REQ-STUB001

use crate::config::{apply_dispositions, load_dispositions};
use crate::types::{Category, Disposition, Finding, Location, Severity};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

/// One qualitative text field pulled from an evidence artifact, tagged with
/// which entry and logical field it came from: Rule A scans every value;
/// Rule B groups values by `field` across entries.
///
//fusa:req REQ-STUB001
pub struct QualField {
    pub entry_id: String,
    pub field: &'static str,
    pub value: String,
}

impl QualField {
    pub fn new(entry_id: impl Into<String>, field: &'static str, value: impl Into<String>) -> Self {
        Self {
            entry_id: entry_id.into(),
            field,
            value: value.into(),
        }
    }
}

const PLACEHOLDER_SUBSTRINGS: &[&str] = &[
    "replace with",
    "example hazard",
    "tbd",
    "lorem ipsum",
    "fill in",
];

fn looks_like_placeholder(v: &str) -> bool {
    let lower = v.to_lowercase();
    if PLACEHOLDER_SUBSTRINGS.iter().any(|s| lower.contains(s)) {
        return true;
    }
    has_bracketed_instruction(v)
}

/// Matches the spec's `\[[A-Za-z][^\]]*\]` bracket-wrapped-instruction
/// pattern without a regex dependency: an opening `[` followed by an ASCII
/// letter, then a run of non-`]` characters, then a closing `]`.
fn has_bracketed_instruction(v: &str) -> bool {
    let bytes = v.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'[' {
            continue;
        }
        let Some(&next) = bytes.get(i + 1) else {
            continue;
        };
        // `i + 1` is a valid char boundary: '[' is a single ASCII byte.
        if next.is_ascii_alphabetic() && v[i + 1..].contains(']') {
            return true;
        }
    }
    false
}

/// Rule A (FUSA-STUB001): flag any qualitative field matching the deny-list
/// as an `ERROR` finding, always — never attestation-suppressible.
///
//fusa:req REQ-STUB002
pub fn detect_placeholder(artifact_file: &str, fields: &[QualField]) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in fields {
        if !looks_like_placeholder(&f.value) {
            continue;
        }
        let msg = format!(
            "{}.{} contains placeholder/template text: {:?}",
            f.entry_id, f.field, f.value
        );
        out.push(Finding::new(
            "FUSA-STUB001",
            Severity::Error,
            msg,
            Location::new(artifact_file),
            Category::Safety,
            "replace the placeholder text with real, item-specific analysis",
        ));
    }
    out
}

/// Rule B (FUSA-STUB002): for a group of >=10 entries sharing the same
/// semantic field, a distinct-value ratio below 0.1 is flagged as a
/// `WARNING` — advisory, never gating on its own.
///
//fusa:req REQ-STUB003
pub fn detect_blank_fallback(artifact_file: &str, fields: &[QualField]) -> Vec<Finding> {
    let mut by_field: BTreeMap<&'static str, Vec<&QualField>> = BTreeMap::new();
    for f in fields {
        by_field.entry(f.field).or_default().push(f);
    }

    let mut out = Vec::new();
    for (field_name, group) in by_field {
        if group.len() < 10 {
            continue;
        }
        let distinct: HashSet<&str> = group.iter().map(|f| f.value.as_str()).collect();
        let ratio = distinct.len() as f64 / group.len() as f64;
        if ratio >= 0.1 {
            continue;
        }
        let msg = format!(
            "field {field_name:?} shows only {} distinct value(s) across {} entries (ratio {ratio:.2} < 0.10) — looks templated, not per-item analysis",
            distinct.len(),
            group.len(),
        );
        out.push(Finding::new(
            "FUSA-STUB002",
            Severity::Warning,
            msg,
            Location::new(artifact_file),
            Category::Safety,
            "vary this field per entry's actual signature/behaviour, or attest (x-FuSa spec §1.6.2) that the repetition is genuine",
        ));
    }
    out
}

/// Load `root`'s `.fusa-dispositions.json` (if present) and apply it to
/// `findings` in place, per §4.1 — the same matching rule `check` uses, so a
/// FUSA-STUB001 finding waived once is waived everywhere.
///
//fusa:req REQ-STUB004
pub fn apply_project_dispositions(root: &Path, findings: &mut [Finding]) {
    if let Some(disp) = load_dispositions(&root.join(".fusa-dispositions.json")) {
        apply_dispositions(findings, &disp.dispositions);
    }
}

/// True when any of `findings` is an open (not accepted/deferred) `ERROR`.
///
//fusa:req REQ-STUB004
pub fn has_open_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|f| {
        f.severity == Severity::Error
            && !matches!(
                f.disposition,
                Some(Disposition::Accepted) | Some(Disposition::Deferred)
            )
    })
}

/// True when any of `findings` is an open (not accepted/deferred) `WARNING`.
///
//fusa:req REQ-STUB004
pub fn has_open_warnings(findings: &[Finding]) -> bool {
    findings.iter().any(|f| {
        f.severity == Severity::Warning
            && !matches!(
                f.disposition,
                Some(Disposition::Accepted) | Some(Disposition::Deferred)
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    //fusa:test REQ-STUB001
    //fusa:test REQ-STUB002
    #[test]
    fn detects_bracketed_placeholder() {
        let fields = vec![QualField::new("H-001", "description", "[describe hazard]")];
        let findings = detect_placeholder("hara.json", &fields);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FUSA-STUB001");
        assert_eq!(findings[0].severity, Severity::Error);
    }

    //fusa:test REQ-STUB002
    #[test]
    fn detects_replace_with_substring_case_insensitively() {
        let fields = vec![QualField::new(
            "FMEA-001",
            "failureMode",
            "Replace With actual failure mode",
        )];
        assert_eq!(detect_placeholder("fmea.json", &fields).len(), 1);
    }

    //fusa:test REQ-STUB002
    #[test]
    fn detects_tbd() {
        let fields = vec![QualField::new("TARA-001", "threat", "TBD")];
        assert_eq!(detect_placeholder("tara.json", &fields).len(), 1);
    }

    //fusa:test REQ-STUB002
    #[test]
    fn genuine_text_is_not_flagged() {
        let fields = vec![QualField::new(
            "FMEA-001",
            "failureMode",
            "Registry::register returns Err when the rule id is a duplicate",
        )];
        assert!(detect_placeholder("fmea.json", &fields).is_empty());
    }

    //fusa:test REQ-STUB002
    #[test]
    fn bracket_with_no_closing_is_not_flagged() {
        let fields = vec![QualField::new(
            "H-001",
            "description",
            "array bounds: no bracket",
        )];
        assert!(detect_placeholder("hara.json", &fields).is_empty());
    }

    //fusa:test REQ-STUB002
    #[test]
    fn digit_only_bracket_is_not_flagged() {
        // "[0]" — the spec's bracket pattern requires an ASCII *letter* right
        // after '[', so a bare numeric index like array[0] does not match.
        let fields = vec![QualField::new(
            "H-001",
            "description",
            "reads array[0] safely",
        )];
        assert!(detect_placeholder("hara.json", &fields).is_empty());
    }

    //fusa:test REQ-STUB002
    #[test]
    fn single_letter_bracket_is_flagged_per_spec_regex() {
        // The spec's deny-list regex is deliberately loose: `[i]` technically
        // matches `\[[A-Za-z][^\]]*\]`, even though it's plausibly a real
        // array-index mention rather than placeholder text. This is a known,
        // accepted false-positive shape of Rule A (still ERROR — waive via a
        // disposition per §1.6.1, not by loosening the regex).
        let fields = vec![QualField::new("H-001", "description", "array[i] access")];
        assert_eq!(detect_placeholder("hara.json", &fields).len(), 1);
    }

    //fusa:test REQ-STUB003
    #[test]
    fn blank_fallback_flags_ratio_strictly_below_point_one() {
        // 11 entries, 1 distinct value: ratio = 1/11 ≈ 0.091 < 0.1.
        let mut fields = Vec::new();
        for i in 0..11 {
            fields.push(QualField::new(
                format!("FMEA-{i:03}"),
                "failureMode",
                "Function does not perform intended action",
            ));
        }
        let findings = detect_blank_fallback("fmea.json", &fields);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FUSA-STUB002");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    //fusa:test REQ-STUB003
    #[test]
    fn blank_fallback_does_not_flag_ratio_exactly_at_threshold() {
        // 10 entries, 1 distinct value: ratio = 0.1, which is not *below*
        // 0.1 (spec: "a ratio below 0.1"), so this must not fire.
        let mut fields = Vec::new();
        for i in 0..10 {
            fields.push(QualField::new(
                format!("FMEA-{i:03}"),
                "failureMode",
                "same text",
            ));
        }
        assert!(detect_blank_fallback("fmea.json", &fields).is_empty());
    }

    //fusa:test REQ-STUB003
    #[test]
    fn blank_fallback_ignores_groups_under_ten() {
        let mut fields = Vec::new();
        for i in 0..9 {
            fields.push(QualField::new(
                format!("FMEA-{i:03}"),
                "failureMode",
                "same text",
            ));
        }
        assert!(detect_blank_fallback("fmea.json", &fields).is_empty());
    }

    //fusa:test REQ-STUB003
    #[test]
    fn blank_fallback_allows_varied_text() {
        let mut fields = Vec::new();
        for i in 0..12 {
            fields.push(QualField::new(
                format!("FMEA-{i:03}"),
                "failureMode",
                format!("distinct failure mode #{i}"),
            ));
        }
        assert!(detect_blank_fallback("fmea.json", &fields).is_empty());
    }

    //fusa:test REQ-STUB004
    #[test]
    fn has_open_errors_ignores_dispositioned_findings() {
        let mut f = Finding::new(
            "FUSA-STUB001",
            Severity::Error,
            "placeholder",
            Location::new("fmea.json"),
            Category::Safety,
            "fix",
        );
        assert!(has_open_errors(std::slice::from_ref(&f)));
        f.disposition = Some(Disposition::Accepted);
        assert!(!has_open_errors(std::slice::from_ref(&f)));
    }

    //fusa:test REQ-STUB004
    #[test]
    fn has_open_warnings_ignores_dispositioned_findings() {
        let mut f = Finding::new(
            "FUSA-STUB002",
            Severity::Warning,
            "templated",
            Location::new("fmea.json"),
            Category::Safety,
            "vary it",
        );
        assert!(has_open_warnings(std::slice::from_ref(&f)));
        f.disposition = Some(Disposition::Deferred);
        assert!(!has_open_warnings(std::slice::from_ref(&f)));
    }
}
