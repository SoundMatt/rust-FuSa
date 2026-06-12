# SLSA — Supply-chain Levels for Software Artifacts

SLSA (Supply-chain Levels for Software Artifacts) is a security framework for protecting software supply chains. rust-FuSa maps build and evidence artefacts to SLSA L1–L3 requirements.

## Gap report

```bash
rsfusa slsa --dir .
rsfusa slsa --dir . --format json --output slsa-report.json
```

## Requirement mapping

| Clause | Title | Evidence file |
|--------|-------|---------------|
| SLSA-L1.provenance | Build provenance document | `provenance.json` |
| SLSA-L1.build-process | Documented build process (CI workflow) | `.github/workflows/ci.yml` |
| SLSA-L2.version-control | Version-controlled source | `.git` |
| SLSA-L2.hosted-build | Hosted CI (GitHub Actions) | `.github/workflows/ci.yml` |
| SLSA-L3.hermetic | Hermetic build (locked dependencies) | `Cargo.lock` |
| SLSA-L3.sbom | SBOM for supply-chain transparency | `sbom.json` |
| SLSA-L3.audit-pack | Signed audit evidence archive | `audit-pack.zip` |
| SLSA-L3.vuln-scan | Dependency vulnerability scan | `vuln.json` |

## Generating evidence

```bash
rsfusa release --dir .      # provenance.json, sbom.json (SLSA-L1, L3)
rsfusa vuln --dir .         # vuln.json (SLSA-L3.vuln-scan)
rsfusa audit-pack --dir .   # audit-pack.zip (SLSA-L3.audit-pack)
```

Cargo.lock, .git, and .github/workflows/ci.yml are checked for existence; they are present by default in any properly managed Rust project hosted on GitHub.

## SLSA levels

| Level | Description | rust-FuSa support |
|-------|-------------|-------------------|
| L1 | Provenance exists | `rsfusa release` generates `provenance.json` |
| L2 | Hosted source + build | GitHub repo + Actions CI workflow |
| L3 | Hermetic, isolated build | `Cargo.lock` + pinned CI actions |
| L4 | Reproducible build | Not currently verified by rust-FuSa |
