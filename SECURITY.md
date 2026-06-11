# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

rust-FuSa is a static analysis and evidence-generation tool. Its attack surface is
limited to:

- **Input parsing** — `.fusa.json`, `.fusa-reqs.json`, `Cargo.toml`, `Cargo.lock`
- **File-system traversal** — scanning the project root passed via `--dir`

### How to report

Do **not** open a public GitHub issue for security vulnerabilities.

Send a report to **matt@jellybaby.com** with:

1. A description of the vulnerability
2. Steps to reproduce (ideally a minimal proof of concept)
3. The rust-FuSa version (`rsfusa version`)
4. Your assessment of severity and exploitability

You will receive an acknowledgement within **72 hours** and a resolution
timeline within **7 days**.
