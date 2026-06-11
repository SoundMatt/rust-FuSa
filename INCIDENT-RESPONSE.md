# Incident Response

This document describes how to handle reported security vulnerabilities and safety-critical defects in rust-FuSa.

## Scope

An **incident** is any confirmed or suspected:

- Security vulnerability in rsfusa itself (e.g. path traversal in `--dir`, HMAC weakness in `sign`)
- False negative in a qualified safety rule that could cause a real project to miss a violation
- Incorrect ASIL derivation producing a lower integrity level than warranted
- Evidence integrity failure (e.g. hash mismatch in audit pack)

## Reporting

Report security vulnerabilities privately via **GitHub Security Advisories**:

1. Go to https://github.com/SoundMatt/rust-FuSa/security/advisories/new
2. Complete the template — include reproduction steps, rsfusa version, and affected commands
3. Do **not** open a public GitHub issue for security vulnerabilities

For safety-critical defects (false negatives, wrong ASIL), open a GitHub Issue with the label `safety-defect`.

## Severity classification

| Severity | Examples |
|----------|---------|
| **Critical** | False negative in qualified FUSA/LINT rule; ASIL derivation error |
| **High** | Hardcoded credential not detected (CYBER001); audit pack hash incorrect |
| **Medium** | Incorrect line number in finding; SARIF output schema deviation |
| **Low** | Cosmetic output difference; non-safety documentation error |

## Response SLA

| Severity | Acknowledgement | Patch |
|----------|----------------|-------|
| Critical | 24 hours | 72 hours |
| High | 48 hours | 7 days |
| Medium | 7 days | 30 days |
| Low | 30 days | Next release |

## Resolution process

1. **Triage**: Reproduce the incident and classify severity
2. **Contain**: If the incident affects evidence integrity, notify downstream users immediately
3. **Fix**: Implement fix on a private branch; add qualification test case covering the failure
4. **Verify**: Run `rsfusa qualify` — all cases must pass including the new regression test
5. **Release**: Tag a patch release; update CHANGELOG.md with CVE or defect reference
6. **Disclose**: Publish GitHub Security Advisory after patch is available

## Post-incident review

For Critical and High incidents, complete a post-incident review within 14 days covering:

- Root cause
- Detection gap (why didn't existing tests catch this?)
- New qualification test cases added
- Process improvements

## Contact

Primary maintainer: Matt Jones — open a GitHub issue or security advisory.
