# rust-FuSa Roadmap

This document outlines planned improvements to rust-FuSa. Items are ordered by rough priority.

## v0.3.0 — Enhanced static analysis

- **ANA007**: Detect missing `#[must_use]` on safety-critical return types
- **ANA008**: Flag `std::process::exit` calls outside of `main`
- **LINT007**: Detect missing error propagation (`let _ = ...` suppression)
- **Macro expansion awareness**: Track `unwrap` inside `vec![]` and similar macros
- `rsfusa coverage` with native `cargo llvm-cov` integration (no external tools required)
- `rsfusa coupling` with graphical cycle detection report

## v0.4.0 — Tool integration

- `cargo-fusa` as a Cargo subcommand alias
- VS Code extension with inline diagnostics
- Pre-built binary releases for `linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`
- Container image on `ghcr.io/soundmatt/rust-fusa` with OCI labels per x-FuSa spec §15

## v0.5.0 — Standards depth

- **IEC 62443** cybersecurity gap report (`rsfusa iec62443`)
- **SLSA Level 2** provenance with signed build attestations (`rsfusa slsa`)
- **MISRA Rust 2023** rule subset mapping
- `rsfusa tara` with automatic attack tree generation

## Backlog

- Incremental scanning (only re-scan changed files)
- Multi-crate workspace support
- Configurable rule severity overrides in `.fusa.json`
- Web UI for interactive report browsing
- `rsfusa report --format pdf` via headless browser
