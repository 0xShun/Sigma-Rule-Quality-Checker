# Sigma Rule Test Report — ✅ PASSED

| Field | Value |
|---|---|
| **Rule file** | `powershell_encoded.yml` |
| **Rule title** | Suspicious PowerShell Execution with Encoded Command |
| **Status** | test |
| **Tested at** | 2026-03-04T09:09:24.410538Z |
| **Overall result** | ✅ PASSED |

---
## Stage 1 — Syntax Validation ✅

**Result:** PASSED

No syntax errors found.

---
## Stage 2 — Log Matching ⚠️

**Log file used:** `NOT FOUND`
**Matches found:** 0

> ⚠️ No matching log file found in `/logs/` for this rule's logsource.
> Add a sample log file to enable log matching.

---
## Stage 3 — Noise Assessment ⚠️

**Noise level:** Medium

**Warnings:**
- Single 'selection' condition with no additional filters — check specificity
- No filter/exclusion block found — consider adding one to reduce false positives

---
## Summary

| Test | Result |
|---|---|
| Syntax validation | ✅ Pass |
| Log matching | ⚠️ No match |
| Noise level | ⚠️ Medium |
