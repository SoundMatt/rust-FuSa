# Release Process

## Version numbering

rust-FuSa follows Semantic Versioning: `MAJOR.MINOR.PATCH`.

- **PATCH**: Bug fixes, documentation corrections, performance improvements
- **MINOR**: New commands, new rules, non-breaking behaviour changes
- **MAJOR**: Breaking changes to JSON schemas, exit codes, or CLI surface

## Pre-release checklist

- [ ] All CI jobs pass on `main` (build-test, cross-compile, macos)
- [ ] `rsfusa qualify` passes with no failures
- [ ] `cargo test` passes with no failures
- [ ] `CHANGELOG.md` updated with all changes for this version
- [ ] Version bumped in `src/types.rs` (`VERSION` constant)
- [ ] Version referenced in `README.md`

## Release steps

```bash
# 1. Bump version
# Edit src/types.rs: VERSION = "X.Y.Z"

# 2. Update CHANGELOG.md — add release date to [Unreleased] section

# 3. Build and verify
cargo build --release --locked
./target/release/rsfusa qualify
./target/release/rsfusa version

# 4. Generate safety evidence
./target/release/rsfusa release
./target/release/rsfusa fmea
./target/release/rsfusa boundary
./target/release/rsfusa safety-case
./target/release/rsfusa audit-pack

# 5. Commit and tag
git add -A
git commit -m "chore: release v$(./target/release/rsfusa version | awk '{print $2}' | head -1)"
git tag vX.Y.Z
git push origin main --tags
```

## Artefacts produced

| File | Description |
|------|-------------|
| `sbom.json` | Software Bill of Materials (x-FuSa §7) |
| `provenance.json` | Build provenance with git commit and toolchain |
| `artifact-manifest.json` | SHA-256 manifest of all evidence files |
| `qualify-report.json` | Tool qualification results |
| `audit-pack.zip` | All evidence bundled for submission |

## Binary distribution

Pre-built binaries are not yet published automatically. Build from source:

```bash
cargo build --release --locked
# Binary at target/release/rsfusa
```

For static musl builds (Linux):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --locked
```
