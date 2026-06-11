# rsfusa analyze

Run only the ANA* static analysis rules. Checks for structural code quality issues relevant to safety-critical software.

## Usage

```
rsfusa analyze [--dir <path>] [--format text|json] [--output <file>] [--strict] [--no-color]
```

## Rules

| Rule | Description | Severity | Standard reference |
|------|-------------|----------|--------------------|
| ANA001 | Function body exceeds 60 lines | WARNING | ISO 26262 6.4.5 |
| ANA002 | Code nesting depth exceeds 5 levels | WARNING | ISO 26262 6.4.5 |
| ANA003 | Function has more than 7 parameters | WARNING | ISO 26262 6.4.5 |
| ANA004 | Raw pointer dereference without `//fusa:unsafe` | WARNING | ISO 26262 6.4.7 |
| ANA005 | Integer truncating cast (`as u8/i8/u16/i16`) | WARNING | ISO 26262 6.4.6 |
| ANA006 | Function has more than 3 explicit return points | INFO | MISRA C:2023 15.5 |

## Rationale

Complex functions with many parameters, deep nesting, and multiple exits are harder to review, test, and verify against safety requirements. ANA rules flag these patterns to prompt refactoring or formal justification.

## Examples

```bash
rsfusa analyze
rsfusa analyze --format json --output analyze-report.json
```
