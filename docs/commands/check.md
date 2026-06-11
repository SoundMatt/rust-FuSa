# rsfusa check

Run all safety checks against a Rust project and exit 1 if any ERROR findings are present.

## Usage

```
rsfusa check [--dir <path>] [--format text|json|html|sarif|md] [--output <file>] [--strict] [--no-color]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dir <path>` | `.` | Project root to scan |
| `--format <fmt>` | `text` | Output format: `text`, `json`, `html`, `sarif`, `md` |
| `--output <file>` | stdout | Write output to file |
| `--strict` | off | Exit 1 on WARNING findings too |
| `--no-color` | off | Disable ANSI colour in text output |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No gate-failing findings |
| 1 | ERROR findings present (or WARNING with `--strict`) |
| 2 | Invalid arguments |
| 3 | Runtime error (I/O or parse failure) |

## Rules run

`check` runs all active rule sets:

- **FUSA001–FUSA007**: Structural requirements (config, manifest, license, README, CI, unsafe, unwrap)
- **LINT001–LINT006**: Rust coding standard rules
- **ANA001–ANA006**: Static analysis rules
- **CYBER001–CYBER020**: CWE-mapped security rules

## JSON output schema

```json
{
  "schemaVersion": "1.9",
  "kind": "check-report",
  "tool": "rust-FuSa",
  "toolVersion": "0.2.0",
  "language": "rust",
  "generatedAt": "2026-06-11T00:00:00Z",
  "findings": [
    {
      "ruleId": "LINT002",
      "severity": "WARNING",
      "category": "safety",
      "message": ".unwrap() may panic",
      "location": { "file": "src/main.rs", "line": 42 },
      "fingerprint": "sha256:abc123...",
      "remediation": "Replace with ? operator or explicit match"
    }
  ],
  "summary": { "errors": 0, "warnings": 1, "infos": 0 }
}
```

## Examples

```bash
# Basic scan with text output
rsfusa check

# JSON to file (typical CI usage)
rsfusa check --format json --output check-report.json

# Strict mode — fail on warnings too
rsfusa check --strict

# SARIF for GitHub Code Scanning
rsfusa check --format sarif --output results.sarif
```

## Difference from `report`

`rsfusa report` runs the same analysis but always exits 0, making it suitable for informational runs that should never block CI.
