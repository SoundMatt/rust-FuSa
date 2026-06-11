# rust-FuSa

A functional safety enablement toolkit for Rust projects. rust-FuSa provides static checks,
coding rules, traceability helpers, CI evidence bundles, reproducible build metadata, and
tool qualification support to help teams build safety cases for ISO 26262, IEC 61508,
ISO 21434, and DO-178C.

[![CI](https://github.com/SoundMatt/rust-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/rust-FuSa/actions/workflows/ci.yml)

> **Not a certification product.** rust-FuSa is an engineering accelerator that reduces
> the cost of producing functional safety evidence throughout the SDLC.

## Install

```bash
cargo install --git https://github.com/SoundMatt/rust-FuSa rsfusa
```

## Quick start

```bash
# Initialise a project (creates .fusa.json and .fusa-reqs.json)
rsfusa init --name my-project --standard iso26262 --asil ASIL-B

# Run all safety checks (exit 1 on ERROR; --strict exits 1 on WARNING too)
rsfusa check
rsfusa check --strict

# Generate a compliance report (always exits 0, same schema as check)
rsfusa report --format html --output safety-report.html

# Show requirement traceability matrix
rsfusa trace
rsfusa trace --gaps            # only requirements with no test tag
rsfusa trace --req-coverage 80 # exit 1 if <80% traced

# Run tool qualification suite (produces qualify-report.json)
rsfusa qualify

# Generate SBOM, provenance, and artifact manifest
rsfusa release

# Bundle all evidence into audit-pack.zip
rsfusa audit-pack

# Report supported commands and formats (for FuSaOps discovery)
rsfusa capabilities --format json

# Version info
rsfusa version
rsfusa version --format json
```

## Rust-specific rules

| Rule | Severity | Description |
|---|---|---|
| `FUSA001` | ERROR | `.fusa.json` must be present |
| `FUSA002` | ERROR | `Cargo.toml` must be present |
| `FUSA003` | WARNING | `LICENSE` file must be present |
| `FUSA004` | WARNING | `README` file must be present |
| `FUSA005` | WARNING | CI configuration must be present |
| `FUSA006` | WARNING | `.fusa-reqs.json` should be present |
| `FUSA007` | ERROR | Requirement IDs in `.fusa-reqs.json` must be unique |
| `LINT001` | ERROR | `unsafe` blocks must have `//fusa:unsafe` justification |
| `LINT002` | WARNING | `.unwrap()` should not appear in safety-critical library code |
| `LINT003` | WARNING | `TODO`/`FIXME` comments must be tracked as issues |
| `LINT004` | ERROR | `std::mem::transmute` requires `//fusa:unsafe` justification |
| `LINT005` | WARNING | `panic!()`/`unreachable!()` in library code without justification |
| `LINT006` | WARNING | Crates with ASIL/SIL should declare `#![forbid(unsafe_code)]` |

## Source annotations

Annotate source with `//fusa:` tags to build the traceability matrix:

```rust
//fusa:req REQ-CORE001
pub fn classify_severity(raw: u8) -> Severity {
    // ...
}

//fusa:test REQ-CORE001
#[test]
fn test_severity_classification() {
    // ...
}

//fusa:sec-test REQ-SEC001
#[test]
fn test_bounds_check() {
    // ...
}
```

## Configuration (`.fusa.json`)

```json
{
  "configVersion": "1.0",
  "project": { "name": "my-project", "version": "0.1.0" },
  "standard": "iso26262",
  "asil": "ASIL-B",
  "sourceDirs": ["src"],
  "excludePatterns": ["target/**", "tests/fixtures/**"],
  "strict": false
}
```

Standards: `iso26262` · `iec61508` · `do178c` · `iso21434` · `iec62443-4-1` ·
`iec62443-4-2` · `misra-c` · `cert-c` · `unece-r155` · `unece-r156` · `generic`

## Output formats

All reporting commands support `--format text|json|html|sarif`.
JSON output follows the [x-FuSa spec v1.9](https://github.com/SoundMatt/FuSaOps/blob/main/docs/x-fusa-spec.md)
envelope so FuSaOps can consume rust-FuSa output without tool-specific code.

## FuSaOps integration

rust-FuSa implements the x-FuSa spec v1.9 interface:

```yaml
# docker-compose.yml excerpt
services:
  rust-fusa:
    image: ghcr.io/soundmatt/rust-fusa:latest
    volumes: [".:/project"]
    command: check --format json --output check-report.json
```

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).
