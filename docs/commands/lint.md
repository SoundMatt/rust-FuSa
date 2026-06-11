# rsfusa lint

Run only the LINT* Rust coding standard rules. A focused alternative to `rsfusa check` for style and idiom checks.

## Usage

```
rsfusa lint [--dir <path>] [--format text|json] [--output <file>] [--strict] [--no-color]
```

## Rules

| Rule | Description | Severity |
|------|-------------|----------|
| LINT001 | `unsafe` block without `//fusa:unsafe` justification | ERROR |
| LINT002 | `.unwrap()` in non-test code | WARNING |
| LINT003 | `.expect()` in non-test code | WARNING |
| LINT004 | `todo!()` or `unimplemented!()` macro | WARNING |
| LINT005 | `std::mem::transmute` usage | ERROR |
| LINT006 | `std::mem::forget` usage | WARNING |

## Suppressing findings

Add `//fusa:unsafe` on the line immediately before an `unsafe` block:

```rust
//fusa:unsafe: required for FFI callback registration; bounds verified by caller
unsafe { register_callback(ptr); }
```

## Examples

```bash
rsfusa lint
rsfusa lint --strict --format json --output lint-report.json
```
