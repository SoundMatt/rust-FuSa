# rsfusa release

Generate release evidence artefacts: SBOM, build provenance, and artifact manifest.

## Usage

```
rsfusa release [--dir <path>]
```

## Outputs

| File | Schema | Description |
|------|--------|-------------|
| `sbom.json` | x-FuSa §7 | Software Bill of Materials — all Cargo dependencies with hashes |
| `provenance.json` | x-FuSa §3.1 | Build provenance — git commit, branch, toolchain, timestamp |
| `artifact-manifest.json` | x-FuSa §8 | SHA-256 manifest of all evidence files |

## SBOM format (x-FuSa §7)

```json
{
  "schemaVersion": "1.9",
  "kind": "sbom",
  "module": { "name": "rsfusa", "version": "0.2.0" },
  "components": [
    {
      "name": "serde",
      "version": "1.0.200",
      "hash": "sha256:abc123..."
    }
  ]
}
```

Hashes are formatted as `algo:value` (e.g. `sha256:...`).

## CI integration

Run `rsfusa release` in CI after tests pass to generate fresh evidence artefacts for each build. Upload them as CI artefacts and include in the audit pack:

```bash
rsfusa release
rsfusa audit-pack
```

## Examples

```bash
rsfusa release
rsfusa release --dir /path/to/project
```
