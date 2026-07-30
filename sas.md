# Software Accomplishment Summary (SAS)

**DO-178C §11.20**

| Field | Value |
|-------|-------|
| Project | rust-FuSa |
| Version | 0.1.0 |
| Standard | iso26262 |
| DAL/ASIL | unclassified |
| Generated | 2026-07-30T20:12:41Z |
| Tool | rust-FuSa 0.3.17 (spec 1.15.2) |

> **:warning: INFORMATIONAL ONLY.** This is **not** a certification-basis DO-178C §11.20 accomplishment summary. This project's configured standard is `iso26262` with DAL/ASIL `unclassified` — not an actively-classified `do178c` project with a real DAL. The checklist below is a heuristic §11 evidence-presence scan only and carries no certification weight until the project is genuinely classified under DO-178C.

## Software Life Cycle Data (DO-178C §11)

| Clause | Data Item | Evidence | Status |
|--------|-----------|----------|--------|
| 11.1 | Plan for Software Aspects of Certification (PSAC) | — | :x: Missing |
| 11.2 | Software Development Plan (SDP) | — | :x: Missing |
| 11.3 | Software Verification Plan (SVP) | — | :x: Missing |
| 11.4 | Software Configuration Management Plan (SCMP) | — | :x: Missing |
| 11.5 | Software Quality Assurance Plan (SQAP) | — | :x: Missing |
| 11.6 | Software Requirements Standards | — | :x: Missing |
| 11.7 | Software Design Standards | — | :x: Missing |
| 11.8 | Software Code Standards | — | :x: Missing |
| 11.9 | Software Requirements Data | `.fusa-reqs.json` | :white_check_mark: Present |
| 11.10 | Design Description | `boundary.mermaid` | :white_check_mark: Present |
| 11.11 | Source Code | `src` | :white_check_mark: Present |
| 11.12 | Executable Object Code | — | :x: Missing |
| 11.13 | Software Verification Cases and Procedures | — | :x: Missing |
| 11.14 | Software Verification Results | `check-report.json` | :white_check_mark: Present |
| 11.15 | Software Life Cycle Environment Configuration Index | `Cargo.lock` | :white_check_mark: Present |
| 11.16 | Software Configuration Index (SCI) | `sci.json` | :white_check_mark: Present |
| 11.17 | Problem Reports | — | :x: Missing |
| 11.18 | Software Configuration Management Records | — | :x: Missing |
| 11.19 | Software Quality Assurance Records | `qualify-report.json` | :white_check_mark: Present |
| 11.20 | Software Accomplishment Summary (SAS) | `sas.md` | :white_check_mark: Present |

## Conformance Statement

8 of 20 §11 data items have automatically-detected evidence in this repository.

This SAS was generated automatically by rust-FuSa 0.3.17. A qualified safety engineer must review and sign this document before submission.
