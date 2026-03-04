#!/usr/bin/env python3
"""
Sigma Rule Tester
-----------------
Tests pushed Sigma rules through three stages:
  1. Syntax validation   — required fields, YAML structure
  2. Log matching        — pattern match against /logs/ JSON samples
  3. Noise heuristics    — detect overly broad conditions

Writes a detailed report to /reports/passed/ or /reports/failed/
"""

import sys
import os
import json
import yaml
import re
import datetime
from pathlib import Path


# ── Constants ─────────────────────────────────────────────────────────────────

REPO_ROOT    = Path(__file__).parent.parent
LOGS_DIR     = REPO_ROOT / "logs"
REPORTS_PASS = REPO_ROOT / "reports" / "passed"
REPORTS_FAIL = REPO_ROOT / "reports" / "failed"

REQUIRED_FIELDS = ["title", "status", "logsource", "detection"]
VALID_STATUSES  = ["stable", "test", "experimental", "deprecated", "unsupported"]

# Maps Sigma logsource (product, category) → log subfolder/filename
LOG_MAP = {
    ("windows", "process_creation"):   "windows/process_creation.json",
    ("windows", "network_connection"): "windows/network_connection.json",
    ("windows", "dns_query"):          "windows/network_connection.json",
    ("linux",   "process_creation"):   "linux/auditd.json",
    ("linux",   None):                 "linux/auditd.json",
    (None,      "dns"):                "network/dns_queries.json",
    ("network", None):                 "network/dns_queries.json",
    (None,      "proxy"):              "network/proxy_traffic.json",
}

# Noise heuristic patterns — conditions that are too broad
NOISE_PATTERNS = [
    (r"Image\|endswith:\s*['\"]\\\\[a-z]+\.exe['\"]$",
     "Image match with no ParentImage or CommandLine filter — too broad"),
    (r"CommandLine\|contains:\s*['\"][a-z]{1,3}['\"]",
     "Very short CommandLine contains match — high false positive risk"),
    (r"\*\.\*",
     "Wildcard *.* in condition — extremely broad"),
    (r"condition:\s*selection$",
     "Single 'selection' condition with no additional filters — check specificity"),
    (r"User\|contains:\s*['\"]admin['\"]",
     "Broad User filter on 'admin' — matches many legitimate admin accounts"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_yaml(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_logs(log_file: Path):
    if not log_file.exists():
        return None
    with open(log_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]


def resolve_log_file(logsource: dict) -> Path | None:
    product  = logsource.get("product")
    category = logsource.get("category")
    service  = logsource.get("service")

    for (p, c), path in LOG_MAP.items():
        if (p is None or p == product) and (c is None or c == category or c == service):
            return LOGS_DIR / path
    return None


# ── Stage 1 — Syntax Validation ───────────────────────────────────────────────

def validate_syntax(rule_path: Path, rule: dict) -> tuple[bool, list[str]]:
    errors = []

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: '{field}'")

    # Status check
    status = rule.get("status", "")
    if status not in VALID_STATUSES:
        errors.append(f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}")

    # Detection block checks
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("Missing 'condition' inside detection block")
        if len(detection) < 2:
            errors.append("Detection block has no selection — only condition found")
    else:
        errors.append("Detection block is malformed — must be a YAML mapping")

    # Logsource check
    logsource = rule.get("logsource", {})
    if not isinstance(logsource, dict) or not logsource:
        errors.append("Logsource block is missing or empty")
    elif "product" not in logsource and "category" not in logsource and "service" not in logsource:
        errors.append("Logsource must have at least one of: product, category, service")

    # Title check
    title = rule.get("title", "")
    if not title or len(title.strip()) < 5:
        errors.append("Title is missing or too short (minimum 5 characters)")

    # Tab character check
    raw = rule_path.read_text(encoding="utf-8")
    if "\t" in raw:
        errors.append("Tab characters found in YAML — use spaces only")

    return len(errors) == 0, errors


# ── Stage 2 — Log Matching ────────────────────────────────────────────────────

def match_logs(rule: dict, logs: list[dict]) -> tuple[bool, int, list[str]]:
    """
    Pattern matches detection selections against log entries.
    Returns: (any_match, match_count, match_descriptions)
    """
    detection  = rule.get("detection", {})
    condition  = detection.get("condition", "")
    selections = {k: v for k, v in detection.items() if k != "condition"}

    if not selections or not logs:
        return False, 0, []

    matches     = []
    match_count = 0

    for log_entry in logs:
        entry_matched = _evaluate_condition(condition, selections, log_entry)
        if entry_matched:
            match_count += 1
            desc = _describe_match(log_entry)
            if desc not in matches:
                matches.append(desc)

    return match_count > 0, match_count, matches[:5]  # cap at 5 examples


def _evaluate_condition(condition: str, selections: dict, log_entry: dict) -> bool:
    """Evaluate a simple Sigma condition against a single log entry."""
    # Build a map of selection_name → did_it_match
    sel_results = {}
    for sel_name, sel_criteria in selections.items():
        sel_results[sel_name] = _match_selection(sel_criteria, log_entry)

    # Parse condition: supports 'selection', 'sel1 and sel2', 'sel1 or sel2', 'not sel1'
    cond = condition.strip().lower()

    # Replace selection names with their bool results
    for name, result in sel_results.items():
        cond = cond.replace(name.lower(), str(result).lower())

    try:
        # Safe eval of simple boolean expression
        cond = cond.replace("true", "True").replace("false", "False")
        return bool(eval(cond))  # noqa: S307
    except Exception:
        # Fallback: if any selection matched, consider it a match
        return any(sel_results.values())


def _match_selection(criteria, log_entry: dict) -> bool:
    """Match a selection block (dict or list of dicts) against a log entry."""
    if isinstance(criteria, list):
        # List of criteria — any match (OR)
        return any(_match_selection(c, log_entry) for c in criteria)

    if not isinstance(criteria, dict):
        return False

    # All criteria in the dict must match (AND)
    for field_expr, expected in criteria.items():
        if not _match_field(field_expr, expected, log_entry):
            return False
    return True


def _match_field(field_expr: str, expected, log_entry: dict) -> bool:
    """
    Evaluate a single Sigma field modifier expression.
    Supports: contains, endswith, startswith, re, exact match.
    """
    parts    = field_expr.split("|")
    field    = parts[0]
    modifier = parts[1].lower() if len(parts) > 1 else "exact"

    # Get field value from log — case-insensitive key lookup
    log_val = None
    for k, v in log_entry.items():
        if k.lower() == field.lower():
            log_val = str(v)
            break

    if log_val is None:
        return False

    candidates = expected if isinstance(expected, list) else [expected]

    for candidate in candidates:
        candidate = str(candidate)
        if modifier == "contains":
            if candidate.lower() in log_val.lower():
                return True
        elif modifier == "endswith":
            if log_val.lower().endswith(candidate.lower()):
                return True
        elif modifier == "startswith":
            if log_val.lower().startswith(candidate.lower()):
                return True
        elif modifier == "re":
            if re.search(candidate, log_val, re.IGNORECASE):
                return True
        else:  # exact or wildcard
            pattern = re.escape(candidate).replace(r"\*", ".*").replace(r"\?", ".")
            if re.fullmatch(pattern, log_val, re.IGNORECASE):
                return True

    return False


def _describe_match(log_entry: dict) -> str:
    keys = ["Image", "CommandLine", "EventID", "DestinationIp",
            "DestinationHostname", "QueryName", "User", "process_name"]
    parts = []
    for k in keys:
        for lk, lv in log_entry.items():
            if lk.lower() == k.lower() and lv:
                parts.append(f"{k}={lv}")
                break
    return " | ".join(parts) if parts else str(log_entry)[:120]


# ── Stage 3 — Noise Heuristics ────────────────────────────────────────────────

def check_noise(rule_path: Path) -> tuple[str, list[str]]:
    """
    Heuristic noise check on raw rule text.
    Returns: (noise_level, list_of_warnings)
    """
    raw      = rule_path.read_text(encoding="utf-8")
    warnings = []

    for pattern, message in NOISE_PATTERNS:
        if re.search(pattern, raw, re.IGNORECASE | re.MULTILINE):
            warnings.append(message)

    # Additional: check if there's a filter/exclude section (good practice)
    detection = yaml.safe_load(raw).get("detection", {})
    has_filter = any("filter" in k.lower() for k in detection.keys())
    if not has_filter and len(detection) <= 2:
        warnings.append("No filter/exclusion block found — consider adding one to reduce false positives")

    if len(warnings) == 0:
        level = "Low"
    elif len(warnings) <= 2:
        level = "Medium"
    else:
        level = "High"

    return level, warnings


# ── Report Writer ─────────────────────────────────────────────────────────────

def write_report(rule_path: Path, rule: dict, passed: bool, results: dict):
    REPORTS_PASS.mkdir(parents=True, exist_ok=True)
    REPORTS_FAIL.mkdir(parents=True, exist_ok=True)

    folder   = REPORTS_PASS if passed else REPORTS_FAIL
    stem     = rule_path.stem
    ts       = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = folder / f"{stem}__{ts}.md"

    status_icon = "✅ PASSED" if passed else "❌ FAILED"
    now         = datetime.datetime.utcnow().isoformat() + "Z"

    lines = [
        f"# Sigma Rule Test Report — {status_icon}",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Rule file** | `{rule_path.name}` |",
        f"| **Rule title** | {rule.get('title', 'N/A')} |",
        f"| **Status** | {rule.get('status', 'N/A')} |",
        f"| **Tested at** | {now} |",
        f"| **Overall result** | {status_icon} |",
        f"",
    ]

    # ── Stage 1
    syntax_pass   = results["syntax"]["passed"]
    syntax_errors = results["syntax"]["errors"]
    lines += [
        f"---",
        f"## Stage 1 — Syntax Validation {'✅' if syntax_pass else '❌'}",
        f"",
        f"**Result:** {'PASSED' if syntax_pass else 'FAILED'}",
        f"",
    ]
    if syntax_errors:
        lines.append("**Errors found:**")
        for e in syntax_errors:
            lines.append(f"- {e}")
    else:
        lines.append("No syntax errors found.")
    lines.append("")

    # ── Stage 2
    log_result  = results["log_match"]
    lines += [
        f"---",
        f"## Stage 2 — Log Matching {'✅' if log_result['matched'] else '⚠️'}",
        f"",
        f"**Log file used:** `{log_result['log_file']}`",
        f"**Matches found:** {log_result['match_count']}",
        f"",
    ]
    if log_result["log_file"] == "NOT FOUND":
        lines.append("> ⚠️ No matching log file found in `/logs/` for this rule's logsource.")
        lines.append("> Add a sample log file to enable log matching.")
    elif log_result["matched"]:
        lines.append("**Matching log entries (up to 5):**")
        for m in log_result["matches"]:
            lines.append(f"- `{m}`")
    else:
        lines.append("> Rule did not match any entries in the sample log file.")
        lines.append("> This may indicate the detection logic needs tuning, or the log sample needs updating.")
    lines.append("")

    # ── Stage 3
    noise_level    = results["noise"]["level"]
    noise_warnings = results["noise"]["warnings"]
    noise_icon     = {"Low": "✅", "Medium": "⚠️", "High": "❌"}.get(noise_level, "⚠️")
    lines += [
        f"---",
        f"## Stage 3 — Noise Assessment {noise_icon}",
        f"",
        f"**Noise level:** {noise_level}",
        f"",
    ]
    if noise_warnings:
        lines.append("**Warnings:**")
        for w in noise_warnings:
            lines.append(f"- {w}")
    else:
        lines.append("No noise issues detected.")
    lines.append("")

    # ── Summary
    lines += [
        f"---",
        f"## Summary",
        f"",
        f"| Test | Result |",
        f"|---|---|",
        f"| Syntax validation | {'✅ Pass' if syntax_pass else '❌ Fail'} |",
        f"| Log matching | {'✅ Matched' if log_result['matched'] else '⚠️ No match'} |",
        f"| Noise level | {noise_icon} {noise_level} |",
        f"",
    ]

    if not passed:
        lines += [
            f"---",
            f"## What to Fix",
            f"",
        ]
        if syntax_errors:
            lines.append("### Syntax errors to resolve:")
            for e in syntax_errors:
                lines.append(f"1. {e}")
            lines.append("")
        if not log_result["matched"] and log_result["log_file"] != "NOT FOUND":
            lines.append("### Log matching:")
            lines.append("- Review your detection conditions against the sample log fields")
            lines.append("- Ensure field names match exactly (case-sensitive in some backends)")
            lines.append("")
        if noise_warnings:
            lines.append("### Noise reduction:")
            for w in noise_warnings:
                lines.append(f"- {w}")
            lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  Report written → {out_path.relative_to(REPO_ROOT)}")
    return out_path


# ── Main ──────────────────────────────────────────────────────────────────────

def test_rule(rule_path: Path) -> bool:
    print(f"\n{'='*60}")
    print(f"Testing: {rule_path.name}")
    print(f"{'='*60}")

    # Load rule
    try:
        rule = load_yaml(rule_path)
    except yaml.YAMLError as e:
        print(f"  ✗ YAML parse error: {e}")
        write_report(rule_path, {}, False, {
            "syntax":    {"passed": False, "errors": [f"YAML parse error: {e}"]},
            "log_match": {"matched": False, "match_count": 0, "matches": [], "log_file": "N/A"},
            "noise":     {"level": "Unknown", "warnings": []},
        })
        return False

    # Stage 1 — Syntax
    print("  Stage 1: Syntax validation...")
    syntax_pass, syntax_errors = validate_syntax(rule_path, rule)
    print(f"    {'✅ Pass' if syntax_pass else '❌ Fail'} — {len(syntax_errors)} error(s)")

    # Stage 2 — Log matching
    print("  Stage 2: Log matching...")
    logsource = rule.get("logsource", {})
    log_file  = resolve_log_file(logsource)
    logs      = load_logs(log_file) if log_file else None

    if log_file is None or logs is None:
        log_file_str = "NOT FOUND"
        matched, match_count, match_descs = False, 0, []
        print(f"    ⚠️  No log file found for logsource: {logsource}")
    else:
        log_file_str = str(log_file.relative_to(REPO_ROOT))
        matched, match_count, match_descs = match_logs(rule, logs)
        print(f"    {'✅' if matched else '⚠️ '} {match_count} match(es) in {log_file_str}")

    # Stage 3 — Noise
    print("  Stage 3: Noise heuristics...")
    noise_level, noise_warnings = check_noise(rule_path)
    print(f"    Noise level: {noise_level} ({len(noise_warnings)} warning(s))")

    # Determine overall pass/fail
    # Rule PASSES if: syntax is valid + at least some log match (or no log file) + noise not High
    overall_pass = syntax_pass and (matched or log_file_str == "NOT FOUND") and noise_level != "High"

    results = {
        "syntax":    {"passed": syntax_pass, "errors": syntax_errors},
        "log_match": {"matched": matched, "match_count": match_count,
                      "matches": match_descs, "log_file": log_file_str},
        "noise":     {"level": noise_level, "warnings": noise_warnings},
    }

    write_report(rule_path, rule, overall_pass, results)
    print(f"\n  Overall: {'✅ PASSED' if overall_pass else '❌ FAILED'}")
    return overall_pass


def main():
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        print("No rule files specified.")
        sys.exit(0)

    rule_files = sys.argv[1].strip().split()
    all_passed = True

    for f in rule_files:
        path = REPO_ROOT / f.strip()
        if not path.exists():
            print(f"File not found, skipping: {path}")
            continue
        if not test_rule(path):
            all_passed = False

    print(f"\n{'='*60}")
    print(f"Pipeline complete — {'ALL PASSED ✅' if all_passed else 'SOME FAILED ❌'}")
    print(f"{'='*60}")
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()