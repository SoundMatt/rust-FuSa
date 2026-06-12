# Changelog

All notable changes to rust-FuSa are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.4] — 2026-06-12

### Fixed

- **spec v1.10 conformance** — `SPEC_VERSION` updated from `"1.9"` to `"1.10"` in all JSON headers (§3.1)
- **`comp` JSON schema** — output now matches spec v1.10 §13 canonical shape: top-level `totalFunctions`, `violations`, `maxComplexity`, `results[]` with `name` field (was `summary.{}` / `functions[]`)
- **`--output` §2.2 invariant** — `comp` and `qualify` no longer write to stdout when `--output <file>` is given; progress/confirmation messages go to stderr
- **`qualify` progress** — all progress lines (`running … case(s)`, `passed`, failure detail) now go to stderr so `--format json` stdout is clean
- **`comp --dal`** — added canonical `--dal DAL-A|B|C|D` flag; emits optional `dal` field in JSON report; backward-compat `--dal-a`/`--dal-b`/etc. kept
- **`audit-pack` evidence list** — added `comp-report.json`; removed `provenance.intoto.jsonl` (deferred in v1.10)

### Tests

- 4 new conformance tests: `comp_dal_flag_canonical`, `check_output_no_double_write`, `comp_output_no_double_write`, `check_ruleid_format_invariant`
- Total: **47 tests**, all green

### Changed

- Version bumped to **0.2.4**
- Docker image and docs updated to spec v1.10

---

## [0.2.3] — 2026-06-12

### Added

- **`comp`** (§9.2 SHOULD) — Cyclomatic complexity (McCabe V(G)) analysis per DO-178C §6.3.4; walks all `.rs` files, counts decision points per function, exits 1 on threshold violations
- `docs/commands/comp.md` reference documentation
- Requirements REQ-COMP001–REQ-COMP005 added to `.fusa-reqs.json`

### Changed

- Version bumped to **0.2.3**
- `capabilities` output updated to list all **44 commands** (was 43)
- README and docs updated to reflect 44-command surface
- Docker image `ARG VERSION` updated to 0.2.3

---

## [0.2.1] — 2026-06-12

### Added

- **`iec62443`** (§9.3 MAY) — IEC 62443 IACS security gap report covering parts 2-1, 2-4, 3-2, 3-3, 4-1, and 4-2 (10 requirements)
- **`slsa`** (§9.3 MAY) — SLSA supply-chain levels gap report covering L1 provenance, L2 hosted build/VCS, L3 hermetic build, SBOM, and vulnerability scan (8 requirements)
- `docs/standards/iec62443.md` and `docs/standards/slsa.md` reference documentation
- Requirements REQ-IEC62443001–REQ-IEC62443005 and REQ-SLSA001–REQ-SLSA005 added to `.fusa-reqs.json`

### Changed

- Version bumped to **0.2.1**
- `capabilities` output updated to list all **43 commands** (was 41)
- README and docs updated to reflect 43-command surface

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
