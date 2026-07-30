// JCS-subset (RFC 8785-inspired) JSON canonicalization, used to compute
// reproducible content hashes: the §6 `qualify.hash` field and the §1.6.2 attestation
// `contentHash`. Targets the JSON shapes this tool itself emits (structs
// serialized via serde_json — small integers, plain strings, nested
// objects/arrays) rather than adversarial arbitrary JSON.
//
// The single rule that makes two conforming tools agree: object keys sorted
// lexicographically at every level, no insignificant whitespace, numbers in
// a stable round-trip form.
//fusa:req REQ-CANON001

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Serialize `v` to canonical JSON: object keys sorted, no whitespace.
///
//fusa:req REQ-CANON001
pub fn canonicalize(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let _ = write!(out, "{n}");
        }
        Value::String(s) => write_canonical_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // serde_json's default `Map` is already key-sorted (it is
            // backed by a `BTreeMap` unless the `preserve_order` feature is
            // enabled, which this crate does not enable) — sort explicitly
            // anyway so canonicalization does not silently depend on that.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_string(k, out);
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
    }
}

fn write_canonical_string(s: &str, out: &mut String) {
    // serde_json's string encoding matches standard JSON escaping and (unlike
    // Go's encoding/json) does not HTML-escape '<'/'>'/'&' by default, so no
    // extra encoder configuration is needed here.
    match serde_json::to_string(s) {
        Ok(encoded) => out.push_str(&encoded),
        Err(_) => out.push_str("\"\""),
    }
}

/// `"sha256:" + lowercase_hex(SHA-256(canonicalize(v)))` — the reproducible
/// integrity hash shape used by §6 `qualify.hash` and §1.6.2
/// `attestation.contentHash`.
///
//fusa:req REQ-CANON002
pub fn content_hash(v: &Value) -> String {
    let canon = canonicalize(v);
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    //fusa:test REQ-CANON001
    #[test]
    fn sorts_object_keys() {
        let a = json!({"b": 1, "a": 2});
        assert_eq!(canonicalize(&a), r#"{"a":2,"b":1}"#);
    }

    //fusa:test REQ-CANON001
    #[test]
    fn nested_keys_are_sorted_too() {
        let a = json!({"z": {"y": 1, "x": 2}, "a": 1});
        assert_eq!(canonicalize(&a), r#"{"a":1,"z":{"x":2,"y":1}}"#);
    }

    //fusa:test REQ-CANON001
    #[test]
    fn arrays_preserve_order() {
        let a = json!([3, 1, 2]);
        assert_eq!(canonicalize(&a), "[3,1,2]");
    }

    //fusa:test REQ-CANON001
    #[test]
    fn key_order_in_source_does_not_affect_output() {
        let a = json!({"a": 1, "b": 2});
        let b = json!({"b": 2, "a": 1});
        assert_eq!(canonicalize(&a), canonicalize(&b));
    }

    //fusa:test REQ-CANON002
    #[test]
    fn content_hash_is_sha256_prefixed_and_deterministic() {
        let a = json!({"a": 1, "b": 2});
        let b = json!({"b": 2, "a": 1});
        let ha = content_hash(&a);
        let hb = content_hash(&b);
        assert!(ha.starts_with("sha256:"));
        assert_eq!(ha, hb);
    }

    //fusa:test REQ-CANON002
    #[test]
    fn content_hash_changes_with_content() {
        let a = json!({"a": 1});
        let b = json!({"a": 2});
        assert_ne!(content_hash(&a), content_hash(&b));
    }
}
