# rsfusa comp

Cyclomatic complexity (McCabe V(G)) analysis per DO-178C §6.3.4.

## Synopsis

```
rsfusa comp [--dir <path>] [--threshold <N>] [--dal-a|--dal-b|--dal-c|--dal-d]
            [--format text|json] [--output <file>]
```

## Description

`comp` walks all `.rs` files in the project (excluding `target/`) and computes the McCabe cyclomatic complexity V(G) for each function. V(G) = 1 + number of decision points, where decision points are: `if`, `while`, `for`, `loop`, `match`, `&&`, `||`.

Functions exceeding the threshold are reported as violations. Exit code 1 is returned when violations exist.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dir <path>` | current directory | Project root to scan |
| `--threshold <N>` | 10 (DAL-B) | Maximum permitted V(G) |
| `--dal-a` | — | Set threshold to 4 (DAL-A per DO-178C) |
| `--dal-b` | — | Set threshold to 10 (DAL-B, default) |
| `--dal-c` | — | Set threshold to 15 (DAL-C) |
| `--dal-d` | — | Set threshold to 20 (DAL-D) |
| `--format text\|json` | `text` | Output format |
| `--output <file>` | stdout | Write report to file |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No threshold violations |
| 1 | One or more functions exceed the threshold |
| 2 | Usage error — invalid flags |
| 3 | Runtime error — I/O failure |

## Examples

```bash
# Text report with default DAL-B threshold (10)
rsfusa comp

# Strict DAL-A threshold (4)
rsfusa comp --dal-a

# JSON report saved to file
rsfusa comp --format json --output comp-report.json

# Custom threshold
rsfusa comp --threshold 8 --format json --output comp-report.json
```

## JSON output

```json
{
  "schemaVersion": "1.9",
  "kind": "comp-report",
  "tool": "rust-FuSa",
  "toolVersion": "0.2.3",
  "language": "rust",
  "generatedAt": "...",
  "threshold": 10,
  "functions": [
    {
      "file": "src/cmd/check.rs",
      "line": 42,
      "function": "run",
      "complexity": 7,
      "exceedsThreshold": false
    }
  ],
  "summary": {
    "totalFunctions": 120,
    "violations": 0,
    "maxComplexity": 9
  }
}
```

## Standard reference

DO-178C §6.3.4 requires measurement of cyclomatic complexity (structural coverage criterion MC/DC for DAL-A). DAL thresholds follow common avionics and safety tool convention:

| DAL | Threshold |
|-----|-----------|
| A | 4 |
| B | 10 |
| C | 15 |
| D | 20 |

## Requirements

REQ-COMP001 · REQ-COMP002 · REQ-COMP003 · REQ-COMP004 · REQ-COMP005
