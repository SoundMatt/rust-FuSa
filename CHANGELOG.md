# Changelog

All notable changes to rust-FuSa are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-06-11

### Added

- **41 CLI commands** reaching full feature parity with the x-FuSa spec v1.9 command surface
- **§9.2 SHOULD commands**: `lint`, `analyze`, `diff`, `verify`, `vuln`, `cyber`, `coverage`, `coupling`, `fmea`, `tara`, `safety-case`, `boundary`, `hara`
- **§9.3 MAY commands**: `iso26262`, `iec61508`, `do178c`, `iso21434`, `unece`, `misra`, `disposition`, `badge`, `sas`, `sci`, `impact`, `metrics`, `fix`, `sign`, `req`, `pr`, `template`, `hooks`
- **ANA001–ANA006**: Static analysis rules — function length, nesting depth, parameter count, raw pointer dereference, integer truncating cast, multiple returns
- **CYBER001–CYBER020**: CWE-mapped cybersecurity rules — hardcoded credentials (CWE-798), SQL injection (CWE-89), path traversal (CWE-22), weak RNG (CWE-330), unchecked arithmetic (CWE-190), cleartext HTTP (CWE-319), command injection (CWE-78), deprecated crypto (CWE-327), and 12 more
- **HARA**: Full Hazard Analysis and Risk Assessment file (`.fusa-hara.json`) with 5 hazards, safety goals, and ISO 26262 ASIL derivation
- **FMEA**: Design FMEA generated from `pub fn` declarations with failure mode mapping and risk classification
- **Boundary diagram**: Dependency graph in both Graphviz DOT and Mermaid format
- **TARA**: Threat Analysis and Risk Assessment with STRIDE mapping per ISO 21434
- **Safety case**: GSN-structured safety argument with evidence checklist and Mermaid diagram
- **90+ requirements** in `.fusa-reqs.json` covering all command areas with full traceability
- `//fusa:req` and `//fusa:test` annotations throughout source code
- CI: lint, analyze, trace, SARIF upload, safety documents, macOS matrix job

### Changed

- Version bumped to **0.2.0**
- `capabilities` output now lists all 41 commands in `must`/`should`/`may` sections
- `check` and `engine` now run all rule sets (FUSA, LINT, ANA, CYBER) by default
- CI workflow expanded with safety document generation and evidence artifact upload

---

## [0.1.0] — 2026-06-11

### Added

- Initial release of rust-FuSa
- §9.1 MUST commands: `version`, `capabilities`, `init`, `check`, `report`, `trace`, `qualify`, `release`, `audit-pack`
- FUSA001–FUSA007 structural rules (config, manifest, license, README, CI, unsafe, unwrap)
- LINT001–LINT006 Rust-specific lint rules
- x-FuSa spec v1.9 JSON schemas (§3.1 common header, §4.2 fingerprints, §5 trace matrix, §6 qualify hash, §7 SBOM, §8 audit-pack)
- Tool qualification suite with 16 deterministic test cases
- SARIF 2.1.0 output format
- HTML, Markdown, and text report formats
- Dockerfile (Alpine base, static musl binary)
