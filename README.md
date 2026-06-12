# rust-FuSa

**Version 0.2.5** · x-FuSa spec v1.10 · language: rust · binary: `rsfusa`

A functional safety enablement toolkit for Rust projects. rust-FuSa provides static checks, coding rules, traceability helpers, CI evidence bundles, reproducible build metadata, HARA, FMEA, TARA, boundary diagrams, and tool qualification support to help teams build safety cases under ISO 26262, IEC 61508, ISO 21434, DO-178C, and MISRA.

[![CI](https://github.com/SoundMatt/rust-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/rust-FuSa/actions/workflows/ci.yml)

> **Not a certification product.** rust-FuSa is an engineering accelerator that reduces the cost of producing functional safety evidence throughout the SDLC.

---

## Install

```bash
cargo install --git https://github.com/SoundMatt/rust-FuSa rsfusa
```

Or build from source:

```bash
git clone https://github.com/SoundMatt/rust-FuSa
cd rust-FuSa
cargo build --release
./target/release/rsfusa version
```

---

## Quick start

```bash
# Initialise a project (creates .fusa.json and .fusa-reqs.json)
rsfusa init --name my-project --standard iso26262 --asil ASIL-B

# Run all safety checks (exit 1 on ERROR)
rsfusa check
rsfusa check --strict              # also exit 1 on WARNING
rsfusa check --format json --output check-report.json

# Lint-only and analysis-only runs
rsfusa lint
rsfusa analyze

# CWE-mapped security analysis
rsfusa cyber --format json --output cyber-report.json

# Requirement traceability matrix
rsfusa trace
rsfusa trace --format json --output trace.json

# Tool qualification suite (produces qualify-report.json)
rsfusa qualify

# Generate SBOM, provenance, and artifact manifest
rsfusa release

# Bundle all evidence into audit-pack.zip
rsfusa audit-pack

# Safety documents
rsfusa hara init          # create .fusa-hara.json template
rsfusa hara show          # display hazard table
rsfusa hara asil --severity S3 --exposure E4 --controllability C2
rsfusa fmea               # design FMEA → fmea.json + fmea.csv
rsfusa tara               # threat analysis → tara.json + tara.md
rsfusa boundary           # dependency graph → boundary.dot + boundary.mermaid
rsfusa safety-case        # GSN safety argument → safety-case.{json,md,mermaid}

# Standards gap reports
rsfusa iso26262
rsfusa iec61508
rsfusa do178c
rsfusa iso21434
rsfusa unece
rsfusa misra

# Tool management
rsfusa version
rsfusa version --format json
rsfusa capabilities --format json
rsfusa report --format html --output safety-report.html
rsfusa diff baseline.json current.json
rsfusa vuln
rsfusa coverage
rsfusa coupling
rsfusa comp
rsfusa verify
rsfusa badge --output status.svg
rsfusa sas                # Software Accomplishment Summary (DO-178C §11.20)
rsfusa sci                # Software Configuration Index (DO-178C §11.16)
rsfusa impact             # impact analysis via git diff
rsfusa metrics record
rsfusa metrics show
rsfusa fix
rsfusa sign --keygen
rsfusa sign <file> --key <hex>
rsfusa req show
rsfusa pr init
rsfusa disposition add --rule LINT002 --status accepted --note "test code only"
rsfusa template --kind safety-plan
rsfusa hooks install
```

---

## All 44 commands

### §9.1 MUST (required by x-FuSa spec)

| Command | Description |
|---------|-------------|
| `version` | Print tool name, version, and spec version |
| `capabilities` | Machine-readable list of all commands, formats, rules, standards |
| `init` | Create `.fusa.json` and `.fusa-reqs.json` |
| `check` | Run all safety checks (exit 1 on ERROR) |
| `report` | Run all safety checks (always exits 0) |
| `trace` | Requirement traceability matrix |
| `qualify` | Tool qualification suite |
| `release` | SBOM, provenance, artifact manifest |
| `audit-pack` | Bundle evidence into ZIP |

### §9.2 SHOULD (recommended)

| Command | Description |
|---------|-------------|
| `lint` | LINT* rules only |
| `analyze` | ANA* static analysis rules only |
| `diff` | Compare two check reports by fingerprint |
| `verify` | Run `cargo test` and save test evidence |
| `vuln` | Dependency vulnerability scan (cargo-audit) |
| `cyber` | CWE-mapped security analysis → `cyber-report.json` |
| `coverage` | Structural coverage report |
| `coupling` | Module coupling analysis |
| `comp` | Cyclomatic complexity (McCabe V(G)) per DO-178C §6.3.4 |
| `fmea` | Design FMEA from `pub fn` declarations |
| `tara` | Threat Analysis per ISO 21434 |
| `safety-case` | GSN safety argument |
| `boundary` | Dependency boundary diagram |
| `hara` | Hazard Analysis and Risk Assessment |

### §9.3 MAY (optional)

| Command | Description |
|---------|-------------|
| `iso26262` | ISO 26262 Part 6 gap report |
| `iec61508` | IEC 61508 Part 3 gap report |
| `do178c` | DO-178C Annex A gap report |
| `iso21434` | ISO 21434 gap report |
| `unece` | UN R.155 gap report |
| `misra` | MISRA C:2023 coverage mapping |
| `disposition` | Manage `.fusa-dispositions.json` |
| `badge` | Generate SVG status badge |
| `sas` | Software Accomplishment Summary |
| `sci` | Software Configuration Index |
| `impact` | Impact analysis via git diff |
| `metrics` | Safety metrics time series |
| `fix` | Show auto-fixable findings with guidance |
| `sign` | Sign/verify files with HMAC-SHA256 |
| `req` | Requirement management |
| `pr` | Software problem reports |
| `template` | Safety documentation templates |
| `hooks` | Manage git pre-commit hooks |
| `iec62443` | IEC 62443 IACS security gap report |
| `slsa` | SLSA supply-chain levels gap report |

---

## Rules

### FUSA — structural checks

| Rule | Severity | Description |
|------|----------|-------------|
| FUSA001 | ERROR | `.fusa.json` must be present |
| FUSA002 | ERROR | `Cargo.toml` must be present |
| FUSA003 | WARNING | `LICENSE` file must be present |
| FUSA004 | WARNING | `README` file must be present |
| FUSA005 | WARNING | CI configuration must be present |
| FUSA006 | ERROR | `unsafe` block without `//fusa:unsafe` justification |
| FUSA007 | WARNING | `.unwrap()` in non-test code |

### LINT — Rust coding standards

| Rule | Severity | Description |
|------|----------|-------------|
| LINT001 | ERROR | Unjustified `unsafe` block |
| LINT002 | WARNING | `.unwrap()` without handling |
| LINT003 | WARNING | `.expect()` without handling |
| LINT004 | WARNING | `todo!()` or `unimplemented!()` |
| LINT005 | ERROR | `std::mem::transmute` |
| LINT006 | WARNING | `std::mem::forget` |

### ANA — static analysis

| Rule | Severity | Description |
|------|----------|-------------|
| ANA001 | WARNING | Function body >60 lines |
| ANA002 | WARNING | Nesting depth >5 levels |
| ANA003 | WARNING | Function parameters >7 |
| ANA004 | WARNING | Raw pointer dereference |
| ANA005 | WARNING | Integer truncating cast (`as u8/i8/u16/i16`) |
| ANA006 | INFO | >3 explicit return points |

### CYBER — CWE-mapped security (20 rules)

| Rule | CWE | Severity | Description |
|------|-----|----------|-------------|
| CYBER001 | CWE-798 | ERROR | Hardcoded credentials |
| CYBER002 | CWE-89 | ERROR | SQL injection pattern |
| CYBER003 | CWE-22 | ERROR | Path traversal |
| CYBER004 | CWE-330 | WARNING | Weak random number generator |
| CYBER005 | CWE-190 | WARNING | Unchecked arithmetic |
| CYBER006 | CWE-319 | ERROR | Cleartext HTTP endpoint |
| CYBER007 | CWE-78 | ERROR | Command injection |
| CYBER008 | CWE-327 | ERROR | Deprecated cryptographic algorithm |
| CYBER009 | CWE-532 | WARNING | Sensitive data in logs |
| CYBER010 | CWE-502 | WARNING | Unvalidated deserialization |
| CYBER011 | CWE-125 | WARNING | Unchecked slice indexing |
| CYBER012 | CWE-400 | WARNING | Unbounded allocation |
| CYBER013 | CWE-295 | ERROR | TLS certificate bypass |
| CYBER014 | CWE-367 | WARNING | TOCTOU race condition |
| CYBER015 | CWE-732 | WARNING | Insecure file permissions |
| CYBER016 | CWE-526 | WARNING | Environment secret exposure |
| CYBER017 | CWE-22 | ERROR | Path from user input |
| CYBER018 | CWE-415 | WARNING | ManuallyDrop use-after-free risk |
| CYBER019 | CWE-134 | WARNING | Format string from external data |
| CYBER020 | CWE-20 | WARNING | Unchecked from_utf8 |

---

## Source annotations

Add traceability annotations in comments to link source code to requirements:

```rust
//fusa:req REQ-FUSA001     // this file/function implements this requirement
//fusa:test REQ-FUSA001    // this test covers this requirement
//fusa:sec-test REQ-CYBER001  // this is a security test

//fusa:unsafe: required for FFI callback; bounds verified by caller
unsafe { register_callback(ptr); }
```

Then run `rsfusa trace` to see coverage:

```
TRACE MATRIX — 12/15 requirements traced, 10/15 tested
```

---

## Configuration (`.fusa.json`)

```json
{
  "configVersion": "1.0",
  "project": { "name": "my-project", "version": "1.0.0" },
  "standard": "iso26262",
  "asil": "ASIL-B",
  "sourceDirs": ["src"],
  "excludePaths": ["target/", "tests/fixtures/"]
}
```

Standards: `iso26262` · `iec61508` · `do178c` · `iso21434` · `iec62443` · `misra` · `unece` · `generic`

Integrity levels: `asil` (QM / ASIL-A–D) · `sil` (SIL-1–4) · `dal` (DAL-A–D)

---

## Output formats

| Format | Commands | Use case |
|--------|----------|----------|
| `text` | all | Terminal output |
| `json` | all | CI processing, FuSaOps |
| `html` | `check`, `report` | Safety submission |
| `sarif` | `check`, `report` | GitHub Code Scanning |
| `md` | `check`, `report`, `trace` | Documentation |

JSON output follows the [x-FuSa spec v1.9](https://github.com/SoundMatt/FuSaOps) common header (§3.1) so FuSaOps can consume rust-FuSa output without tool-specific adapters.

---

## CI integration

```yaml
- name: Safety check
  run: rsfusa check --format json --output check-report.json

- name: Qualify
  run: rsfusa qualify

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the full workflow including lint, analyze, trace, safety documents, macOS, and cross-compile jobs.

---

## FuSaOps integration

rust-FuSa implements the x-FuSa spec v1.9 interface:

```yaml
# docker-compose.yml
services:
  rust-fusa:
    image: ghcr.io/soundmatt/rust-fusa:latest
    volumes: [".:/project"]
    command: check --format json --output check-report.json
```

Tool registry entry:
```json
{ "language": "rust", "binary": "rsfusa", "tool": "rust-FuSa", "image": "ghcr.io/soundmatt/rust-fusa" }
```

---

## Documentation

- [Tool Safety Manual](docs/tool-safety-manual.md)
- [Qualification](docs/qualification.md)
- [Release Process](docs/release-process.md)
- [Command: check](docs/commands/check.md)
- [Command: trace](docs/commands/trace.md)
- [Command: lint](docs/commands/lint.md)
- [Command: analyze](docs/commands/analyze.md)
- [Command: release](docs/commands/release.md)
- [Command: comp](docs/commands/comp.md)
- [Standard: ISO 26262](docs/standards/iso26262.md)
- [Standard: IEC 61508](docs/standards/iec61508.md)
- [Standard: ISO 21434](docs/standards/iso21434.md)
- [Standard: DO-178C](docs/standards/do178c.md)
- [Changelog](CHANGELOG.md)
- [Roadmap](ROADMAP.md)
- [Incident Response](INCIDENT-RESPONSE.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

---

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).
