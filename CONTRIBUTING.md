# Contributing to rust-FuSa

Thank you for your interest in contributing.

## Developer Certificate of Origin (DCO)

All contributions must be signed off under the
[Developer Certificate of Origin v1.1](https://developercertificate.org).

Add a `Signed-off-by` trailer to every commit:

```
git commit -s -m "feat: add awesome thing"
```

## Development

```bash
# Build
cargo build

# Test
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt

# Self-check the tool on itself
cargo run -- check --dir .
```

## Submitting changes

1. Fork the repository and create a feature branch.
2. Ensure `cargo test`, `cargo clippy`, and `cargo fmt --check` all pass.
3. Run `rsfusa check --strict` on your changes.
4. Open a pull request with a clear description of the change and its safety rationale.

## Code style

- No `unsafe` without a `//fusa:unsafe <justification>` annotation.
- No `.unwrap()` in library/tool code — use `?` or `.expect("reason")`.
- All public functions in safety-critical paths should have a `//fusa:req` annotation.
