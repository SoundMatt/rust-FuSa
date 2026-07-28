// x-FuSa spec §1.6.2 attestation: a DCO-style, per-artifact provenance
// record that lets a genuinely independent human review suppress the
// FUSA-STUB002 (§1.6.1 Rule B) advisory warning. Mirrors the independence
// model (implementationAuthor vs. independentReviewer) already established
// for V&V independence declarations elsewhere in the x-FuSa family
// (ISO 26262-2:2018 §6.4).
//fusa:req REQ-ATT001

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationStatus {
    /// Fail-safe default: no human has vouched for this content. An artifact
    /// with no `attestation` object at all MUST be treated as this value.
    Heuristic,
    /// An independent reviewer examined the content at `contentHash` and
    /// found it genuine, not templated/placeholder.
    Reviewed,
}

/// §1.6.2 `attestation` object, optionally carried on an evidence artifact
/// (`fmea.json`, `.fusa-hara.json`, `tara.json`, `safety-case.json`,
/// `sas.json`).
///
//fusa:req REQ-ATT001
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub status: AttestationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub independent_reviewer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// True when `att` is a non-stale, genuinely independent `"reviewed"`
/// attestation matching `current_hash`. Every failure mode — `"heuristic"`
/// status, a self-attestation (`independentReviewer == implementationAuthor`),
/// a missing hash, or a stale hash — returns `false` (fail-safe): the caller
/// MUST then treat the content as unreviewed and MUST NOT suppress Rule B.
///
//fusa:req REQ-ATT002
pub fn is_valid(att: &Attestation, current_hash: &str) -> bool {
    if att.status != AttestationStatus::Reviewed {
        return false;
    }
    let reviewer = att.independent_reviewer.as_deref().unwrap_or("");
    let author = att.implementation_author.as_deref().unwrap_or("");
    if reviewer.is_empty() || reviewer == author {
        return false;
    }
    match &att.content_hash {
        Some(h) if !h.is_empty() && !current_hash.is_empty() => h == current_hash,
        _ => false,
    }
}

/// Read `path`'s existing JSON document (if any) and return its top-level
/// `attestation` object, so a regenerating command can attempt to carry it
/// forward via [`carry_forward`].
///
//fusa:req REQ-ATT003
pub fn read_existing(path: &Path) -> Option<Attestation> {
    let data = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    let att = v.get("attestation")?.clone();
    serde_json::from_value(att).ok()
}

/// Carry `existing`'s attestation forward only if it is still valid against
/// `current_hash` — otherwise the edit invalidates it: "a consumer MUST
/// recompute this hash and treat the attestation as stale ... when it
/// doesn't match the artifact's current content" (§1.6.2). Regenerating an
/// artifact command therefore never blindly preserves a prior attestation;
/// it re-derives whether it still applies.
///
//fusa:req REQ-ATT003
pub fn carry_forward(existing: Option<Attestation>, current_hash: &str) -> Option<Attestation> {
    let att = existing?;
    if is_valid(&att, current_hash) {
        Some(att)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed(reviewer: &str, author: &str, hash: &str) -> Attestation {
        Attestation {
            status: AttestationStatus::Reviewed,
            implementation_author: Some(author.to_string()),
            independent_reviewer: Some(reviewer.to_string()),
            reviewed_at: Some("2026-07-28T00:00:00Z".to_string()),
            content_hash: Some(hash.to_string()),
        }
    }

    //fusa:test REQ-ATT002
    #[test]
    fn heuristic_is_never_valid() {
        let att = Attestation {
            status: AttestationStatus::Heuristic,
            implementation_author: None,
            independent_reviewer: None,
            reviewed_at: None,
            content_hash: None,
        };
        assert!(!is_valid(&att, "sha256:abc"));
    }

    //fusa:test REQ-ATT002
    #[test]
    fn self_attestation_is_invalid() {
        let att = reviewed("Jane Doe", "Jane Doe", "sha256:abc");
        assert!(!is_valid(&att, "sha256:abc"));
    }

    //fusa:test REQ-ATT002
    #[test]
    fn stale_hash_is_invalid() {
        let att = reviewed("Jane Doe <jane@example.com>", "auto", "sha256:old");
        assert!(!is_valid(&att, "sha256:new"));
    }

    //fusa:test REQ-ATT002
    #[test]
    fn genuine_independent_review_is_valid() {
        let att = reviewed("Jane Doe <jane@example.com>", "auto", "sha256:abc");
        assert!(is_valid(&att, "sha256:abc"));
    }

    //fusa:test REQ-ATT002
    #[test]
    fn missing_content_hash_is_invalid() {
        let mut att = reviewed("Jane Doe <jane@example.com>", "auto", "sha256:abc");
        att.content_hash = None;
        assert!(!is_valid(&att, "sha256:abc"));
    }

    //fusa:test REQ-ATT003
    #[test]
    fn carry_forward_drops_stale_attestation() {
        let att = reviewed("Jane Doe <jane@example.com>", "auto", "sha256:old");
        assert!(carry_forward(Some(att), "sha256:new").is_none());
    }

    //fusa:test REQ-ATT003
    #[test]
    fn carry_forward_keeps_valid_attestation() {
        let att = reviewed("Jane Doe <jane@example.com>", "auto", "sha256:abc");
        assert!(carry_forward(Some(att), "sha256:abc").is_some());
    }

    //fusa:test REQ-ATT003
    #[test]
    fn carry_forward_none_when_no_existing() {
        assert!(carry_forward(None, "sha256:abc").is_none());
    }
}
