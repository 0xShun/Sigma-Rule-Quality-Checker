#!/usr/bin/env python3
"""
test_sigma_rules.py

Tests Sigma rules against JSON log samples.
Each rule in rules/<type>/ is evaluated against all JSON logs in logs/json/<type>/.

Exit codes:
    0  — All rules matched at least one log record (all tests passed)
    1  — One or more rules matched nothing (strict mode: pipeline fails)
    2  — One or more rules had parsing/evaluation errors

Usage:
    python3 scripts/test_sigma_rules.py
    python3 scripts/test_sigma_rules.py --type windows
    python3 scripts/test_sigma_rules.py --report-file results/test_report.md
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT    = Path(__file__).resolve().parent.parent
RULES_ROOT   = REPO_ROOT / "rules"
JSON_ROOT    = REPO_ROOT / "logs" / "json"
RESULTS_ROOT = REPO_ROOT / "results"

LOG_TYPES = ["windows", "linux", "network", "cloud", "apache"]


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleResult:
    rule_file:    Path
    rule_title:   str
    rule_id:      str
    rule_level:   str
    log_type:     str
    status:       str          # "pass" | "no_match" | "error"
    matched_logs: list[str] = field(default_factory=list)   # log filenames that hit
    match_count:  int = 0
    error_msg:    str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Sigma condition evaluator
# ─────────────────────────────────────────────────────────────────────────────

class SigmaEvaluator:
    """
    Pure-Python Sigma rule evaluator.

    Supports:
      - Field value matching: string, int, list (OR semantics)
      - Modifiers: |contains, |endswith, |startswith, |re, |cidr (basic)
      - Nested field access via dot notation: event_data.CommandLine
      - Detection condition: AND / OR / NOT / grouped identifiers
      - Wildcards: * in string values
    """

    def __init__(self, rule: dict):
        self.rule = rule
        self.detection = rule.get("detection", {})

    # ── Public entry point ────────────────────────────────────────────────

    def matches(self, record: dict) -> bool:
        """Return True if the record matches the rule's detection logic."""
        condition_str = self.detection.get("condition", "")
        if not condition_str:
            return False
        return self._eval_condition(condition_str, record)

    # ── Condition parser ─────────────────────────────────────────────────

    def _eval_condition(self, condition: str, record: dict) -> bool:
        """
        Evaluate a Sigma condition string against a record.
        Handles: identifier, not X, X and Y, X or Y, (X), 1 of X*, all of X*
        """
        condition = condition.strip()

        # Handle parentheses
        if condition.startswith("(") and condition.endswith(")"):
            return self._eval_condition(condition[1:-1], record)

        # 'not' prefix
        if condition.lower().startswith("not "):
            return not self._eval_condition(condition[4:].strip(), record)

        # Split on ' and ' / ' or ' (case-insensitive, left-to-right)
        # We do a simple left-split respecting parentheses depth
        for op in (" and ", " or "):
            idx = self._find_operator(condition, op)
            if idx != -1:
                left  = condition[:idx].strip()
                right = condition[idx + len(op):].strip()
                if op.strip() == "and":
                    return self._eval_condition(left, record) and self._eval_condition(right, record)
                else:
                    return self._eval_condition(left, record) or self._eval_condition(right, record)

        # '1 of <selection>*' / 'all of <selection>*'
        lower = condition.lower()
        if lower.startswith("1 of "):
            pattern = condition[5:].rstrip("*")
            return any(
                self._eval_selection(k, record)
                for k in self.detection
                if k != "condition" and k.startswith(pattern)
            )
        if lower.startswith("all of "):
            pattern = condition[7:].rstrip("*")
            return all(
                self._eval_selection(k, record)
                for k in self.detection
                if k != "condition" and k.startswith(pattern)
            )

        # Plain identifier
        return self._eval_selection(condition, record)

    def _find_operator(self, s: str, op: str) -> int:
        """Find the first occurrence of op outside parentheses (case-insensitive)."""
        depth = 0
        s_lower = s.lower()
        op_lower = op.lower()
        i = 0
        while i < len(s):
            if s[i] == "(":
                depth += 1
            elif s[i] == ")":
                depth -= 1
            elif depth == 0 and s_lower[i:i+len(op)] == op_lower:
                return i
            i += 1
        return -1

    # ── Selection evaluator ───────────────────────────────────────────────

    def _eval_selection(self, name: str, record: dict) -> bool:
        """Evaluate a named detection selection block against a record."""
        block = self.detection.get(name)
        if block is None:
            log.warning("Unknown detection identifier: %r", name)
            return False

        if isinstance(block, dict):
            return self._eval_map(block, record)
        if isinstance(block, list):
            # List of maps — any map can match (OR)
            return any(self._eval_map(item, record) for item in block if isinstance(item, dict))
        return False

    def _eval_map(self, mapping: dict, record: dict) -> bool:
        """All keys in a mapping must match (AND semantics within a selection)."""
        for field_expr, expected in mapping.items():
            if not self._eval_field(field_expr, expected, record):
                return False
        return True

    # ── Field / modifier matching ─────────────────────────────────────────

    def _eval_field(self, field_expr: str, expected: Any, record: dict) -> bool:
        """
        Evaluate a single field expression (with optional |modifier) against the record.
        """
        parts    = field_expr.split("|")
        field    = parts[0]
        modifier = parts[1].lower() if len(parts) > 1 else None

        actual = self._get_field(field, record)

        # Normalize to list for uniform handling
        actuals = actual if isinstance(actual, list) else [actual]

        # expected can be a scalar or a list (OR semantics)
        expecteds = expected if isinstance(expected, list) else [expected]

        return any(
            self._match_value(a, e, modifier)
            for a in actuals
            for e in expecteds
            if a is not None
        )

    def _get_field(self, field: str, record: dict) -> Any:
        """Retrieve a field value using dot notation for nested dicts."""
        parts = field.split(".")
        val: Any = record
        for part in parts:
            if isinstance(val, dict):
                val = val.get(part)
            else:
                return None
        return val

    def _match_value(self, actual: Any, expected: Any, modifier: str | None) -> bool:
        """Apply the modifier logic to compare actual vs expected."""
        if actual is None:
            return False

        actual_str   = str(actual).lower()
        expected_str = str(expected).lower()

        if modifier is None:
            # Exact match with wildcard support
            return self._wildcard_match(actual_str, expected_str)

        if modifier == "contains":
            return expected_str in actual_str

        if modifier == "endswith":
            return actual_str.endswith(expected_str)

        if modifier == "startswith":
            return actual_str.startswith(expected_str)

        if modifier == "re":
            import re
            try:
                return bool(re.search(expected_str, actual_str, re.IGNORECASE))
            except re.error:
                return False

        if modifier == "cidr":
            import ipaddress
            try:
                return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
            except ValueError:
                return False

        if modifier in ("gt", "gte", "lt", "lte"):
            try:
                a, e = float(actual), float(expected)
                return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[modifier]
            except (ValueError, TypeError):
                return False

        # Unknown modifier — fall back to exact
        log.debug("Unknown modifier %r, falling back to exact match", modifier)
        return self._wildcard_match(actual_str, expected_str)

    @staticmethod
    def _wildcard_match(actual: str, pattern: str) -> bool:
        """Simple glob-style wildcard matching (* only)."""
        import fnmatch
        return fnmatch.fnmatch(actual, pattern)


# ─────────────────────────────────────────────────────────────────────────────
# Rule loader
# ─────────────────────────────────────────────────────────────────────────────

def load_rule(path: Path) -> dict | None:
    """Load and minimally validate a Sigma YAML rule file."""
    try:
        with path.open(encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
        if not isinstance(rule, dict):
            raise ValueError("Rule file is not a YAML mapping")
        if "detection" not in rule:
            raise ValueError("Missing required 'detection' key")
        if "condition" not in rule.get("detection", {}):
            raise ValueError("Missing 'condition' inside detection")
        return rule
    except Exception as exc:
        log.error("Failed to load rule %s: %s", path, exc)
        return None


def load_json_logs(json_dir: Path) -> dict[str, list[dict]]:
    """Load all JSON log files from a directory. Returns {filename: [records]}."""
    result: dict[str, list[dict]] = {}
    if not json_dir.exists():
        return result
    for jf in sorted(json_dir.rglob("*.json")):
        try:
            records = json.loads(jf.read_text(encoding="utf-8"))
            if isinstance(records, dict):
                records = [records]
            result[jf.name] = records
        except Exception as exc:
            log.warning("Could not load log file %s: %s", jf, exc)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Test runner
# ─────────────────────────────────────────────────────────────────────────────

def test_rule(rule_path: Path, log_type: str) -> RuleResult:
    """Run a single Sigma rule against all JSON logs for its type."""
    rule = load_rule(rule_path)

    result = RuleResult(
        rule_file  = rule_path,
        rule_title = rule.get("title", "Unknown") if rule else "Unknown",
        rule_id    = rule.get("id", "no-id") if rule else "no-id",
        rule_level = rule.get("level", "unknown") if rule else "unknown",
        log_type   = log_type,
        status     = "error" if not rule else "no_match",
    )

    if not rule:
        result.error_msg = "Failed to parse rule file"
        return result

    json_dir = JSON_ROOT / log_type
    log_files = load_json_logs(json_dir)

    if not log_files:
        result.status    = "error"
        result.error_msg = f"No JSON log files found in {json_dir}"
        return result

    evaluator = SigmaEvaluator(rule)

    for filename, records in log_files.items():
        for record in records:
            try:
                if evaluator.matches(record):
                    result.match_count += 1
                    if filename not in result.matched_logs:
                        result.matched_logs.append(filename)
            except Exception as exc:
                result.status    = "error"
                result.error_msg = f"Error evaluating record in {filename}: {exc}"
                log.debug("Evaluation error on record %s: %s", record, exc)
                return result

    result.status = "pass" if result.match_count > 0 else "no_match"
    return result


def run_tests(log_types: list[str]) -> list[RuleResult]:
    """Run all rules for the given log types and return results."""
    all_results: list[RuleResult] = []

    for log_type in log_types:
        rules_dir = RULES_ROOT / log_type
        if not rules_dir.exists():
            log.warning("Rules directory not found, skipping: %s", rules_dir)
            continue

        rule_files = sorted(rules_dir.rglob("*.yml"))
        if not rule_files:
            log.info("[%s] No rule files found.", log_type)
            continue

        log.info("[%s] Testing %d rule(s)...", log_type, len(rule_files))

        for rule_path in rule_files:
            log.info("  Rule: %s", rule_path.name)
            result = test_rule(rule_path, log_type)

            icon = {"pass": "✓", "no_match": "✗", "error": "⚠"}.get(result.status, "?")
            if result.status == "pass":
                log.info("    %s PASS — %d match(es) in: %s",
                         icon, result.match_count, ", ".join(result.matched_logs))
            elif result.status == "no_match":
                log.warning("    %s NO MATCH — rule fired against nothing (FAIL)", icon)
            else:
                log.error("    %s ERROR — %s", icon, result.error_msg)

            all_results.append(result)

    return all_results


# ─────────────────────────────────────────────────────────────────────────────
# Report generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_markdown_report(results: list[RuleResult]) -> str:
    """Generate a Markdown test report from the results list."""
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(results)
    passed    = sum(1 for r in results if r.status == "pass")
    no_match  = sum(1 for r in results if r.status == "no_match")
    errors    = sum(1 for r in results if r.status == "error")

    overall = "✅ PASSED" if (no_match == 0 and errors == 0) else "❌ FAILED"

    lines = [
        f"# Sigma Rule Test Report",
        f"",
        f"**Generated:** {now}  ",
        f"**Overall:** {overall}  ",
        f"",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total rules tested | {total} |",
        f"| ✅ Passed (matched logs) | {passed} |",
        f"| ❌ No match (strict fail) | {no_match} |",
        f"| ⚠️ Errors | {errors} |",
        f"",
        f"---",
        f"",
        f"## Results by Rule",
        f"",
    ]

    # Group by log type
    by_type: dict[str, list[RuleResult]] = {}
    for r in results:
        by_type.setdefault(r.log_type, []).append(r)

    for log_type, type_results in sorted(by_type.items()):
        lines.append(f"### {log_type.capitalize()}")
        lines.append("")
        lines.append("| Status | Rule | Level | ID | Matched Logs |")
        lines.append("|--------|------|-------|----|--------------|")

        for r in type_results:
            icon = {"pass": "✅", "no_match": "❌", "error": "⚠️"}.get(r.status, "?")
            matched = ", ".join(r.matched_logs) if r.matched_logs else (r.error_msg or "—")
            lines.append(
                f"| {icon} | {r.rule_title} | {r.rule_level} | `{r.rule_id}` | {matched} |"
            )

        lines.append("")

    # Failures section
    failures = [r for r in results if r.status in ("no_match", "error")]
    if failures:
        lines += [
            "---",
            "",
            "## ❌ Failures Detail",
            "",
        ]
        for r in failures:
            lines += [
                f"### `{r.rule_file.name}` — {r.rule_title}",
                f"- **Type:** {r.log_type}",
                f"- **Status:** {r.status}",
                f"- **ID:** `{r.rule_id}`",
            ]
            if r.status == "no_match":
                lines.append(
                    "- **Reason:** Rule matched zero records across all log samples. "
                    "Add a log sample that exercises this rule, or fix the detection logic."
                )
            elif r.status == "error":
                lines.append(f"- **Error:** {r.error_msg}")
            lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Test Sigma rules against JSON log samples.")
    parser.add_argument(
        "--type",
        choices=LOG_TYPES,
        help="Only test rules of this log type (default: all).",
    )
    parser.add_argument(
        "--report-file",
        type=Path,
        default=RESULTS_ROOT / "test_report.md",
        help="Path to write the Markdown report (default: results/test_report.md).",
    )
    args = parser.parse_args()

    types_to_test = [args.type] if args.type else LOG_TYPES
    results       = run_tests(types_to_test)

    if not results:
        log.warning("No rules were tested.")
        sys.exit(0)

    # Write report
    report_path: Path = args.report_file
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(generate_markdown_report(results), encoding="utf-8")
    log.info("Report written to: %s", report_path)

    # Summary
    passed   = sum(1 for r in results if r.status == "pass")
    no_match = sum(1 for r in results if r.status == "no_match")
    errors   = sum(1 for r in results if r.status == "error")

    log.info("─" * 50)
    log.info("RESULTS: %d passed | %d no-match | %d errors", passed, no_match, errors)

    if no_match > 0:
        log.error("PIPELINE FAIL: %d rule(s) matched no log samples.", no_match)
        log.error("Every committed rule must have at least one matching log sample.")
        sys.exit(1)

    if errors > 0:
        log.error("PIPELINE FAIL: %d rule(s) had evaluation errors.", errors)
        sys.exit(2)

    log.info("All rules passed ✓")
    sys.exit(0)


if __name__ == "__main__":
    main()