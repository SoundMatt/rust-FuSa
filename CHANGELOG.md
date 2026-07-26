# Changelog

All notable changes to rust-FuSa are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## v0.3.3 — 2026-07-26

### Fixed

- **Cargo.lock version mismatch** — `Cargo.lock` was not updated when version was bumped
  to 0.3.2, causing `cargo build --locked` in the Release CI to fail with "cannot update
  the lock file". Lock file is now regenerated and committed at v0.3.3.

---

## v0.3.2 — 2026-07-26

### Fixed

- **aarch64 cross-compilation linker** — `.cargo/config.toml` now uses
  `aarch64-linux-gnu-gcc` (provided by the `gcc-aarch64-linux-gnu` apt package
  that CI already installs) instead of `aarch64-linux-musl-gcc` (musl variant
  not present on the CI runner), fixing the "linker not found" error on Release CI.

---

## v0.3.1 — 2026-07-26

### Added

- **Smoke tests for 12 untested subcommands** — badge, coupling, disposition, fix, hooks, impact, metrics, pr, sas, sci, sign, and template each gain at least one unit test covering their primary behaviour (smoke test: run in a temp dir, assert exit code 0 and non-empty output). Tests carry `//fusa:test` annotations for the corresponding requirement IDs.
- **Requirement annotations** — `//fusa:req` annotations added to all 12 previously unannotated cmd files (badge.rs, coupling.rs, disposition.rs, fix.rs, hooks.rs, impact.rs, metrics.rs, pr.rs, sas.rs, sci.rs, sign.rs, template.rs).
- **35 new requirements** in `.fusa-reqs.json` covering REQ-BADGE001–003, REQ-COUPLING001–003, REQ-DISP001–003, REQ-FIX001–002, REQ-HOOKS001–003, REQ-IMPACT001–003, REQ-METRICS001–003, REQ-PR001–003, REQ-SAS001–003, REQ-SCI001–003, REQ-SIGN001–003, REQ-TEMPLATE001–003.

### Tests

- 21 new tests. Total: **105 tests**, all green.

---

## v0.3.0 — 2026-07-26

### Added

- **HLR/LLR decomposition validation (`trace`)** — the trace command now validates HLR/LLR parent-child relationships: every LLR must reference an existing HLR parent; every HLR must have at least one LLR child. Severity is ERROR for DAL-A/ASIL-D projects, WARNING otherwise. New `--strict-hlr-llr` flag forces ERROR regardless of integrity level. Text, Markdown, and JSON renderers updated to display hierarchy metrics (hlrCount, llrCount, hlrWithLlr). Closes #19.

- **Tool Qualification Display (`qualify`)** — the qualify command now supports `--qualification-method` (self/independent), `--qualifier`, and `--record-uri` flags. Computes a qualification badge shown in stderr: `independently-qualified`, `self-qualified`, or `unqualified`. All fields persisted in qualify-report.json. Closes #20.

- **MC/DC Coverage (`coverage`)** — the coverage command now supports `--mcdc`, `--mcdc-file <llvm-json>`, and `--mcdc-threshold <pct>` flags. Parses LLVM MC/DC records; a condition is covered only when covered_true_count > 0 AND covered_false_count > 0. Hard gate: exit 1 when any function has uncovered conditions below threshold. Structured `mcdc` section added to the JSON report. Closes #21.

- **V&V Independence (`qualify`)** — the qualify command now supports `--implementation-author`, `--independent-reviewer`, `--independent-test-executor`, and `--achievable-asil` flags. Computes `independenceStatus`: `independent` when reviewer differs from author, `non-independent` otherwise. All fields persisted in qualify-report.json. Closes #22.

### Changed

- 16 new requirements added to `.fusa-reqs.json` (REQ-TRACE-HLR001–004, REQ-QUALIFY-TQ001–003, REQ-QUALIFY-VV001–004, REQ-COVERAGE-MCDC001–004).
- Coverage struct gains optional `hlrCount`, `llrCount`, `hlrWithLlr` fields (omitted from JSON when no HLR/LLR requirements exist).
- Qualification hash canonical form updated to include qualification_method, qualifier_identity, implementation_author, independent_reviewer, independent_test_executor.

### Tests

- 17 new tests covering all 4 features.
- Total: **84 tests**, all green.

---

## v0.2.9 — 2026-07-25

- Fix SPEC_VERSION from "1.10" to "1.10.4"
- Add docker-publish.yml — publish ghcr.io/soundmatt/rust-fusa on tag push

---

## [0.2.7] — 2026-06-13

### Fixed

- **`cyber` stdout clean on `--output` (§2.2)** — `cyber` no longer renders the text summary to stdout when `--output <file>` is given; stdout is clean for piping. Confirmation line moved to stderr.
- **Standards text mode stdout clean on `--output` (§2.2)** — `iso26262`, `iec61508`, `do178c`, `iso21434`, `unece`, `misra`, `iec62443`, `slsa` no longer print the text gap-report table to stdout when `--output <file>` is given; JSON is written to the file, stdout is clean.

### Tests

- 2 new tests: `cyber_output_stdout_clean`, `standards_output_stdout_clean`
- Total: **53 tests**, all green

### Changed

- Version bumped to **0.2.7**

---

## [0.2.6] — 2026-06-12

### Fixed

- **`--sec-tested` gate (§5 MUST)** — gate now checks `sec_tested_requirements` (requirements with `sec-test` tags) instead of `tested_requirements` (all test tags); closes #10
- **Gap-report JSON canonical schema (§9.3 MUST)** — renamed `requirements` → `objectives`, `"met"` → `"satisfied"`, added `"partial": 0` to summary, added `"findings": []` per objective; closes #9
- **Standards + audit-pack progress to stderr (§2.2 MUST)** — confirmation/progress lines from `audit-pack` and all `standards` commands moved to stderr; stdout is clean for piping; closes #8

### Tests

- 3 new tests: `gap_report_objectives_status_canonical`, `audit_pack_stdout_clean`, `trace_sec_tested_gate_uses_sec_test_tags`
- Total: **51 tests**, all green

### Changed

- Version bumped to **0.2.6**

---

## [0.2.5] — 2026-06-12

### Fixed

- **`endLine`/`endColumn` span population (§4 MAY)** — `Location.end_line` and `Location.end_column` changed from `u32` (always `0`) to `Option<u32>` (absent when unknown); all lint, cyber, and analysis rules now populate column + endLine + endColumn for single-line token matches
- Fields are omitted from JSON output when absent (not emitted as `0`), preventing consumer confusion

### Added

- `Location::at_col(file, line, col, end_col)` constructor for full span
- `REQ-LOC001` requirement: findings SHOULD include endLine/endColumn when derivable

### Tests

- 1 new test: `check_json_end_line_end_column` — verifies endLine = line and endColumn > column for LINT002 findings
- Total: **48 tests**, all green

### Changed

- Version bumped to **0.2.5**

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
