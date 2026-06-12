# Tool Qualification

rust-FuSa is qualified as a software tool supporting functional safety activities per ISO 26262-8 §11 (Tool Confidence Level 2).

## Running the qualification suite

```
rsfusa qualify
```

This runs all built-in qualification cases and writes `qualify-report.json`. Exit code 1 if any case fails.

## Qualification hash

The qualification report includes a deterministic hash computed over all case results (excluding timestamps) using RFC 8785 canonical JSON per x-FuSa spec §6. This hash can be compared across builds to verify reproducibility.

## What the suite covers

The qualification suite verifies:

- All §9.1 MUST commands respond to correct input with exit code 0
- Error inputs produce exit code 1 or 2 as appropriate
- JSON output from `version --format json` conforms to §3.1 schema
- `capabilities --format json` lists all 43 commands and all rule IDs
- `check` detects known-bad patterns (FUSA001–FUSA005, LINT001–LINT002)
- Fingerprint computation is deterministic (digit normalisation, NFC)
- `release` generates `sbom.json`, `provenance.json`, `artifact-manifest.json`
- `audit-pack` creates a valid ZIP with `manifest.json`

## CI integration

CI runs `rsfusa qualify` on every push and pull request. The qualify report is uploaded as a build artefact. A failing qualify step blocks merge.

## Regenerating qualification evidence

```bash
rsfusa qualify
rsfusa release
rsfusa audit-pack
```

Commit `qualify-report.json`, `sbom.json`, `provenance.json`, and `audit-pack.zip` to the safety evidence archive before certification submission.
