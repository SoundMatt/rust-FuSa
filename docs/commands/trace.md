# rsfusa trace

Generate a requirement traceability matrix by scanning source files for `//fusa:req` and `//fusa:test` annotations.

## Usage

```
rsfusa trace [--dir <path>] [--format text|json|md] [--output <file>] [--strict]
```

## Annotation syntax

Add these comments anywhere in your Rust source files:

```rust
//fusa:req REQ-FUSA001   // marks this file/function as implementing the requirement
//fusa:test REQ-FUSA001  // marks this test as covering the requirement
//fusa:sec-test REQ-CYBER001  // marks this as a security test
```

## Output

The trace command produces a matrix with three counts per requirement:

| Column | Source | Meaning |
|--------|--------|---------|
| `traced` | `//fusa:req` | Requirement has at least one implementation annotation |
| `tested` | `//fusa:test` | Requirement has at least one test annotation |
| `secTested` | `//fusa:sec-test` | Requirement has at least one security test annotation |

## JSON output schema (x-FuSa spec §5)

```json
{
  "schemaVersion": "1.9",
  "kind": "trace",
  "tool": "rust-FuSa",
  "toolVersion": "0.2.0",
  "language": "rust",
  "generatedAt": "2026-06-11T00:00:00Z",
  "tracedRequirements": 42,
  "testedRequirements": 38,
  "secTestedRequirements": 6,
  "items": [
    {
      "id": "REQ-FUSA001",
      "title": "Configuration file present",
      "traced": true,
      "tested": true,
      "secTested": false,
      "locations": ["src/rules.rs:5"]
    }
  ]
}
```

## Strict mode

`--strict` exits 1 if any requirement in `.fusa-reqs.json` has `traced=false` or `tested=false`.

## Examples

```bash
# Text summary
rsfusa trace

# JSON to file for CI evidence
rsfusa trace --format json --output trace.json

# Strict — fail if any requirement is untested
rsfusa trace --strict
```
