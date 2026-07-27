# Changelog

All notable changes to rust-FuSa are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## v0.3.8 — 2026-07-27

### Added

- **Function-tag coverage: 86% → 100%** — eight source files carried zero
  `//fusa:req` tags and so contributed zero covered `pub fn`s to
  `trace --func-coverage`: `src/report.rs` (JSON/SARIF/HTML rendering) and
  six CLI-wrapper files, `src/cmd/{analyze,auditpack,cyber,diff,init,lint}.rs`.
  `src/report.rs` now carries the existing `REQ-RPT001`, `REQ-RPT002`,
  `REQ-RPT003`, `REQ-HTML001-003` tags (previously only referenced from
  `cmd/check.rs`, never from the file that actually implements them).
  `cmd/auditpack.rs` now carries the existing `REQ-AUDIT001`/`REQ-AUDIT002`
  as a second, genuine impl location (the CLI entry point that drives
  `pack()` end-to-end). Five new HLR requirements were registered for
  CLI-surface behaviour that had no requirement at all: `REQ-ANA007`
  (dedicated `analyze` subcommand), `REQ-LINT007` (dedicated `lint`
  subcommand), `REQ-CYBER021` (`cyber`'s `cyber-report.json` / `--output`
  file-write behaviour), `REQ-DIFF001` (fingerprint-based report diff), and
  `REQ-INIT001` (`init` scaffolds `.fusa.json` + `.fusa-reqs.json`) — all
  five are tested by existing `main.rs` integration tests, now tagged, plus
  one new test, `diff_detects_introduced_and_resolved`, since the only prior
  `diff` test (`diff_no_args`) never exercised the actual fingerprint-diff
  logic. `src/cmd/mod.rs` (pure module declarations, no `pub fn`) is the only
  remaining untagged file and does not affect the gate's denominator.
- `.fusa-reqs.json` requirement count: 226 → 231.

## v0.3.7 — 2026-07-27

### Added

- **`trace --func-coverage N`** (x-FuSa spec §1.4.1 item 2) — gates on
  public-function annotation density using rust-FuSa's file-header tagging
  convention: a `pub fn` counts as covered if its containing `.rs` file
  carries at least one `//fusa:req` tag anywhere in it (the interim
  placement granularity §1.4.1 explicitly permits, pending a future
  per-function retrofit). `N=0` disables the gate (default); the command
  exits `1` when density falls below `N`. New `trace::scan_func_coverage`
  skips the top-level `tests/` integration-test directory, `build.rs`, and
  the body of any `#[cfg(test)]` item, since test helpers aren't part of the
  public API surface this gate measures.
- **Dangling `//fusa:test <ID>` detection** (x-FuSa spec §1.4.1 item 3) — an
  annotation referencing a requirement id that doesn't exist in
  `.fusa-reqs.json` now produces a `REQ002` WARNING finding, the same
  treatment as a malformed annotation, moved into `scan_annotations` itself
  so the check runs in the same pass instead of a separate post-scan loop.

### Fixed

- **`rsfusa trace` silently dropped its own annotation-scan findings** —
  `cmd::trace::run` bound `trace::build`'s second return value to `_findings`
  and never looked at it again, so malformed-annotation and dangling-id
  `WARNING`s (already computed, just never surfaced) never reached the user
  on any invocation. `trace` now prints them to stderr alongside the
  existing HLR/LLR validation output — required for the new dangling-id
  check to actually be "never silently accepted" per §1.4.1, rather than
  computed and discarded like before.

## v0.3.6 — 2026-07-27

### Fixed

- **CI: clippy `items_after_test_module` errors** in `src/cmd/diff.rs`,
  `src/cmd/init.rs`, `src/cmd/vuln.rs` — the v0.3.5 coverage-expansion commit
  added `#[cfg(test)] mod tests { ... }` blocks in the middle of each file,
  with the `parse()` function defined after the test module. Moved `parse()`
  above the test module in all three files (clippy denies items placed after
  a test module). Also removed a redundant `use std::io::Write;` inside
  `diff.rs`'s test module (already brought in via `use super::*;`).
- **Release workflow: intermittent asset-name collision** — both release
  matrix targets (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`)
  build a binary literally named `rsfusa`; uploading both under that same
  filename let `softprops/action-gh-release`'s create-then-update sequence
  race, occasionally 404ing on the second asset (broke the v0.3.5 release).
  `.github/workflows/release.yml` now copies each target's binary to its
  matrix-specific artifact name (`rsfusa-linux-amd64` / `rsfusa-linux-arm64`)
  before upload, so the two release assets never collide on filename.

## v0.3.5 — 2026-07-27

### Fixed

- **SPEC_VERSION** updated from `1.10.4` to `1.10.12` to match x-FuSa spec.
- **VERSION constant** updated from `0.3.1` to `0.3.5` to match `Cargo.toml`.
- **Hardcoded version assertions** in existing tests updated to use constants.

### Added

- **Coverage expansion** — added `#[cfg(test)]` modules in five low-coverage files:
  - `src/cmd/diff.rs` (parse, load_report, run — all code paths)
  - `src/cmd/req.rs` (cmd_show, cmd_import, cmd_export, csv_escape, truncate)
  - `src/report.rs` (render_json, render_text, render_sarif, render_html, html_escape, CheckReport::new)
  - `src/cmd/vuln.rs` (parse, process_audit_json, scan_cargo_lock)
  - `src/cmd/hooks.rs` (cmd_install, cmd_remove, cmd_show, parse_dir)
  - `src/cmd/init.rs` (parse, run with all flag combinations)

---

## v0.3.4 — 2026-07-26

### Fixed

- **Dockerfile multi-platform build** — removed explicit `--target x86_64-unknown-linux-musl`
  from the Docker build step. The Release CI builds `linux/amd64,linux/arm64` via QEMU, so
  on the arm64 builder the explicit x86_64 target caused `can't find crate for 'std'`
  (cross-compiler sysroot not installed). Using `cargo build --release` without an explicit
  target lets `rust:alpine` use the native musl target for each platform.

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
