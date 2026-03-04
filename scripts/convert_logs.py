
Imagine you are a detection engineer in a new cybersecurity company who is just setting up their tools. Part of you current projects is to make the follow project:

I am making a github actions pipeline to test the quality of the sigma rules pushed to that repo. The first I need to make is a folder that stored raw logs and a folder that stored the json version of those logs. because different types of logs have different format so I need you to make scripts for the github actions including the scripts to convert the logs in the raw folder and convert them to json because in the future I will be testing sigma against the json version of logs. I just created the repo now.

3:47 PM

Check available skills
Check available skills
Great, I have a clear picture of what's needed. Let me build out the full repo structure for you — log folders, conversion scripts per log type, and the GitHub Actions pipeline.

Here's the plan before I create the files:

logs/raw/ — stores raw logs organized by type (e.g., windows/, linux/, network/)
logs/json/ — mirrors the raw structure but holds converted JSON logs
scripts/convert_logs.py — handles conversion logic per log type (Windows Event XML, syslog, CEF, JSON passthrough, etc.)
.github/workflows/convert-logs.yml — GitHub Actions workflow that triggers on push and runs the conversion

Created 2 files, ran a command
Created 2 files, ran a command
Now let's add sample raw log files so the pipeline has something to work with immediately:


Created 6 files, ran a command
Created 6 files, ran a command
Now let's test the conversion script locally to make sure everything works:


Test the conversion script against all sample logs
Test the conversion script against all sample logs
All 4 log types converted with 0 failures. Let's quickly verify the JSON output looks correct:


Spot-check the JSON outputs
Spot-check the JSON outputs
Everything is clean. Now let's copy the full repo to outputs:


Ran a command, read a file
Ran a command, read a file
Here's what was built and verified (all 19 records parsed, 0 failures):

Repo structure:

logs/raw/windows/   ← Windows Event XML (.xml, .evtx_xml)
logs/raw/linux/     ← Syslog RFC 3164 / 5424 (.log, .syslog)
logs/raw/network/   ← CEF, LEEF, generic key=value (.cef, .leef, .log)
logs/raw/cloud/     ← AWS CloudTrail, Azure, JSON-Lines (.json, .jsonl)
logs/json/          ← Auto-generated, never edit by hand

scripts/convert_logs.py
.github/workflows/convert-logs.yml
How the pipeline behaves:

On push — it diffs which logs/raw/ subfolders changed and only converts those types (efficient, not all-or-nothing)
Manual trigger — lets you pick a specific log type from the Actions UI dropdown
After conversion it auto-commits the JSON back to the repo with [skip ci] to avoid infinite loops
Each parser handles real-world quirks:

Windows: strips XML namespaces, flattens EventData key=value pairs, handles both single <Event> and <Events> wrappers
Linux: handles both RFC 3164 and RFC 5424, falls back gracefully for non-standard lines
Network: auto-detects CEF vs LEEF vs generic by file extension and content
Cloud: handles CloudTrail's {"Records":[...]} envelope, Azure arrays, and JSON-Lines
When you're ready to add Sigma testing, you'll point the sigma engine at logs/json/<type>/ and the records will already be in a flat, queryable structure.

Convert logs
PY 
Convert logs
YML 
Readme
Document · MD 
I have made the folders and files and put the codes in their respective files. What is the next step

3:54 PM
Great progress! The natural next step is to build the Sigma rule testing part of the pipeline — which is the core purpose of the repo. Here's how I'd sequence it:

Step 1 — Add your first Sigma rules Create a rules/ folder organized by log type (e.g., rules/windows/, rules/linux/, etc.) and drop in some .yml Sigma rules to test against.

Step 2 — Build the Sigma testing script Write a scripts/test_sigma_rules.py that uses a Sigma backend library (like sigma-cli or pySigma) to run each rule against the matching JSON logs and report hits, misses, and errors.

Step 3 — Add the testing GitHub Actions workflow A second workflow (e.g., test-sigma-rules.yml) that triggers when either rules or JSON logs change, runs the test script, and reports results — ideally failing the pipeline if a rule matches nothing (no test coverage) or crashes.

Step 4 — Add a results/reporting layer Output a structured test report (JSON or Markdown summary) so you can see at a glance which rules fired, which didn't, and against which log samples.

Before I build any of that — a couple of quick questions to make sure I build it right for your setup:

The user hasn't responded yet. Let me wait for their input before proceeding.

Q: Which Sigma backend/library do you want to use for testing?
A: I'm not sure — recommend one

Q: What should happen when a rule doesn't match any log sample?
A: Fail the pipeline (strict — no untested rules)

3:55 PM
Recommendation: pySigma (Python library)

Here's why it's the better fit for your setup:

You're already in Python — your conversion script is Python, so the whole pipeline stays in one language with no CLI tool juggling
Programmatic control — you can build rich test reports, custom error messages, and per-rule pass/fail logic directly in code
No conversion step needed — sigma-cli converts rules to query languages (like Splunk SPL, Elastic DSL). Since you're testing rules directly against JSON logs in Python, pySigma's direct evaluation is the right fit
Better CI integration — exit codes, structured output, and failure reasons are all in your control
The specific packages you'll need are pySigma + pySigma-backend-python (which evaluates rules directly against Python dicts — perfect since your logs are already JSON).

For the strict pipeline behavior — a rule with no matching log sample will fail the pipeline hard. This enforces a good discipline: every rule you commit must have at least one log sample that proves it fires. No silent dead rules.

Ready to build it all? I'll create:

rules/ folder with example Sigma rules per log type
scripts/test_sigma_rules.py — the test engine
.github/workflows/test-sigma-rules.yml — the CI workflow
A Markdown test report that gets committed back on every run

Created 5 files, viewed a file, ran a command
Created 5 files, viewed a file, ran a command
Now the main test engine:


Created 2 files
Created 2 files
Now let's test everything end-to-end:


Ran 2 commands
Ran 2 commands
5/5 rules passing. Let's also verify the strict fail works correctly:


Verify strict failure mode works
Verify strict failure mode works
Strict mode works — exit code 1, pipeline would fail. Clean that up and copy to outputs:


Ran a command, read a file
Ran a command, read a file
All 5 rules passed, strict failure confirmed working. Here's what was added:

New files:

rules/
├── windows/  suspicious_cmd_execution.yml  (EID 4688 + cmd.exe + recon commands)
│             ntlm_network_logon.yml        (EID 4624 + LogonType 3 + NTLM)
├── linux/    ssh_invalid_user_brute_force.yml
├── network/  c2_traffic_blocked.yml        (CEF + act=block + cat=c2)
└── cloud/    aws_iam_user_created.yml      (CloudTrail CreateUser)

scripts/test_sigma_rules.py
.github/workflows/test-sigma-rules.yml
results/test_report.md                      ← auto-committed after every run
How the strictness works: Any rule that matches zero records across all log samples exits with code 1 and fails the pipeline. You verified this yourself — the test rule with eventid: 9999 immediately triggered the failure path.

Key Sigma features supported by the evaluator: |contains, |endswith, |startswith, |re, |cidr, wildcard *, not, and/or in conditions, 1 of selection*, dot-notation for nested fields like event_data.CommandLine.

The next logical step after this would be adding a requirements.txt and a pre-commit hook so engineers can run the same tests locally before pushing.

Test sigma rules
PY 
Test sigma rules
YML 
Test report
Document · MD 
before I do the sigma rules part. I want to test first the log conversion. I will put firt Apache.log in the raw folder then run the workflow to test it.

3:58 PM
Good thinking — test the foundation before building on top of it. There's one problem to address first though: Apache logs aren't in the current converter.

The convert_logs.py script currently only handles windows, linux, network, and cloud — Apache logs have their own format (Combined Log Format) and would need to go in a dedicated folder like logs/raw/apache/.

Before you put the file in and run the workflow, let me add Apache support so it doesn't fail on you.

Q: What Apache log format(s) are you working with? (Select all that apply)
A: Combined Log Format (most common)

3:58 PM
Perfect. Let me add Apache Combined Log Format support to the converter now.


Read the current convert_logs.py
Read the current convert_logs.py
Now I have the full picture. I'll patch the script in-place — adding the Apache parser, the new folder entries, and wiring it into the dispatcher — then create the folder structure and test it.


Edited 4 files, ran 2 commands, viewed a file
Edited 4 files, ran 2 commands, viewed a file
Now create the Apache folder structure and a realistic sample log to test with:


Ran 3 commands, created a file
Ran 3 commands, created a file
15/15 records converted. One thing worth noting from the output — the SQLi line (/?id=1' OR '1'='1) breaks the request split because the single quotes confuse the space-based parser. That's actually real-world accurate (Apache itself would log it that way), but let me tighten the request parser to handle it gracefully:


Ran 3 commands, viewed a file, edited a file
Ran 3 commands, viewed a file, edited a file
The SQLi URI /?id=1' OR '1'='1 is now correctly preserved as the full URI instead of being split mid-payload. Now copy the updated files to outputs:


Ran a command, read a file
Ran a command, read a file
Apache support is fully wired in. Here's a summary of what changed and what to do now:

Changes made to convert_logs.py:

Added "apache": [".log", ".access_log"] to LOG_TYPE_EXTENSIONS
Added parse_apache_combined() — handles Combined and Common Log Format, normalises the timestamp to ISO 8601, splits the request line, and flattens key fields (method, uri_path, uri_query, status, client_ip, user_agent) to the top level for easy Sigma matching
Fixed the request parser to handle URIs with spaces (SQLi payloads, malformed requests) without corrupting the http_version field
Added the apache branch to the convert_file() dispatcher
What to do in your repo:

Replace your scripts/convert_logs.py with the updated version above
Create the folder logs/raw/apache/ and logs/json/apache/ (add a .gitkeep to the json one)
Drop your apache.log into logs/raw/apache/
Push — the convert-logs.yml workflow will detect the change and convert it automatically
Also update the choices list in convert-logs.yml to add apache to the manual trigger dropdown — a small but useful touch.

Convert logs
PY 
Access
Code · JSON 





Claude is AI and can make mistakes. Please double-check responses.
Convert logs · PY
Copy

#!/usr/bin/env python3
"""
convert_logs.py

Converts raw log files from logs/raw/ into JSON format in logs/json/.
Supports multiple log formats based on subfolder type:
  - windows/  : Windows Event Log XML (.evtx exported as XML, or raw .xml)
  - linux/    : Syslog format (.log, .syslog)
  - network/  : CEF, LEEF, or raw firewall/IDS logs (.log, .cef, .leef)
  - cloud/    : AWS CloudTrail, Azure, GCP (already JSON or JSON-lines)
  - apache/   : Apache Combined Log Format (.log, .access_log)

Usage:
    python3 scripts/convert_logs.py
    python3 scripts/convert_logs.py --type windows
    python3 scripts/convert_logs.py --dry-run
"""

import argparse
import json
import logging
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
RAW_ROOT  = REPO_ROOT / "logs" / "raw"
JSON_ROOT = REPO_ROOT / "logs" / "json"

# ── Supported extensions per log type ────────────────────────────────────────
LOG_TYPE_EXTENSIONS = {
    "windows": [".xml", ".evtx_xml"],   # exported XML from Windows Event Viewer / evtx2xml
    "linux":   [".log", ".syslog"],
    "network": [".log", ".cef", ".leef", ".txt"],
    "cloud":   [".json", ".jsonl", ".log"],
    "apache":  [".log", ".access_log"], # Apache Combined / Common Log Format
}


# ─────────────────────────────────────────────────────────────────────────────
# Parser functions — one per log type
# ─────────────────────────────────────────────────────────────────────────────

def parse_windows_xml(content: str) -> list[dict]:
    """
    Parse Windows Event Log XML.
    Handles both single <Event> documents and <Events> wrappers.
    """
    records = []
    # Wrap in a root tag if needed so we can handle multiple <Event> blocks
    if not content.strip().startswith("<Events"):
        content = f"<Events>{content}</Events>"

    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    ns = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    for event in root.findall(".//e:Event", ns):
        record: dict = {}

        # System section
        system = event.find("e:System", ns)
        if system is not None:
            provider = system.find("e:Provider", ns)
            if provider is not None:
                record["provider_name"]  = provider.get("Name", "")
                record["provider_guid"]  = provider.get("Guid", "")

            for tag in ["EventID", "Version", "Level", "Task", "Opcode",
                        "Keywords", "Channel", "Computer"]:
                el = system.find(f"e:{tag}", ns)
                if el is not None:
                    record[tag.lower()] = el.text

            time_el = system.find("e:TimeCreated", ns)
            if time_el is not None:
                record["timestamp"] = time_el.get("SystemTime", "")

            security = system.find("e:Security", ns)
            if security is not None:
                record["security_user_id"] = security.get("UserID", "")

        # EventData section
        event_data = event.find("e:EventData", ns)
        if event_data is not None:
            data: dict = {}
            for data_el in event_data.findall("e:Data", ns):
                name  = data_el.get("Name", f"Data_{len(data)}")
                value = data_el.text or ""
                data[name] = value
            record["event_data"] = data

        # UserData section (some events use this instead)
        user_data = event.find("e:UserData", ns)
        if user_data is not None:
            record["user_data"] = _xml_element_to_dict(user_data)

        record["log_type"] = "windows"
        records.append(record)

    return records


def _xml_element_to_dict(element) -> dict:
    """Recursively convert an XML element to a dict."""
    result = {}
    for child in element:
        tag = child.tag.split("}")[-1]  # strip namespace
        result[tag] = child.text or _xml_element_to_dict(child)
    return result


def parse_linux_syslog(content: str) -> list[dict]:
    """
    Parse traditional syslog (RFC 3164) and systemd journal export lines.
    Example:
      Mar  4 12:00:01 hostname sshd[1234]: message text
    """
    # RFC 3164
    SYSLOG_RE = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s[\d:]+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s+"
        r"(?P<message>.+)$"
    )
    # RFC 5424
    RFC5424_RE = re.compile(
        r"^<(?P<pri>\d+)>(?P<version>\d+)\s+"
        r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
        r"(?P<appname>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
        r"(?P<structured_data>\S+)\s+(?P<message>.+)$"
    )

    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        record: dict = {"raw": line, "log_type": "linux"}

        m = SYSLOG_RE.match(line)
        if m:
            record.update({
                "timestamp": m.group("timestamp"),
                "hostname":  m.group("hostname"),
                "process":   m.group("process"),
                "pid":       m.group("pid"),
                "message":   m.group("message"),
                "format":    "rfc3164",
            })
            records.append(record)
            continue

        m = RFC5424_RE.match(line)
        if m:
            record.update({
                "priority":        int(m.group("pri")),
                "timestamp":       m.group("timestamp"),
                "hostname":        m.group("hostname"),
                "appname":         m.group("appname"),
                "procid":          m.group("procid"),
                "msgid":           m.group("msgid"),
                "structured_data": m.group("structured_data"),
                "message":         m.group("message"),
                "format":          "rfc5424",
            })
            records.append(record)
            continue

        # Fallback: store raw line with minimal metadata
        record["message"] = line
        record["format"]  = "unknown"
        records.append(record)

    return records


def parse_cef(content: str) -> list[dict]:
    """
    Parse ArcSight CEF (Common Event Format) lines.
    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
    """
    CEF_HEADER_RE = re.compile(
        r"^CEF:(?P<cef_version>\d+)\|"
        r"(?P<device_vendor>[^|]*)\|"
        r"(?P<device_product>[^|]*)\|"
        r"(?P<device_version>[^|]*)\|"
        r"(?P<signature_id>[^|]*)\|"
        r"(?P<name>[^|]*)\|"
        r"(?P<severity>[^|]*)\|"
        r"(?P<extensions>.*)$"
    )

    def _parse_extensions(ext_str: str) -> dict:
        """Parse CEF key=value extensions, handling spaces in values."""
        result: dict = {}
        # Split on key= boundaries
        parts = re.split(r"(\w+)=", ext_str)
        keys   = parts[1::2]
        values = parts[2::2]
        for k, v in zip(keys, values):
            result[k.strip()] = v.strip()
        return result

    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        record: dict = {"raw": line, "log_type": "network", "format": "cef"}
        m = CEF_HEADER_RE.match(line)
        if m:
            record.update(m.groupdict())
            record["extensions"] = _parse_extensions(m.group("extensions"))
        else:
            record["message"] = line
            record["format"]  = "unknown_network"

        records.append(record)

    return records


def parse_leef(content: str) -> list[dict]:
    """
    Parse IBM QRadar LEEF (Log Event Extended Format) lines.
    LEEF:1.0|Vendor|Product|Version|EventID|key1=val1\tkey2=val2
    """
    LEEF_HEADER_RE = re.compile(
        r"^LEEF:(?P<leef_version>[\d.]+)\|"
        r"(?P<vendor>[^|]*)\|"
        r"(?P<product>[^|]*)\|"
        r"(?P<version>[^|]*)\|"
        r"(?P<event_id>[^|]*)\|"
        r"(?P<attributes>.*)$"
    )

    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        record: dict = {"raw": line, "log_type": "network", "format": "leef"}
        m = LEEF_HEADER_RE.match(line)
        if m:
            record.update({
                "leef_version": m.group("leef_version"),
                "vendor":       m.group("vendor"),
                "product":      m.group("product"),
                "version":      m.group("version"),
                "event_id":     m.group("event_id"),
            })
            attrs: dict = {}
            for pair in re.split(r"[\t]", m.group("attributes")):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    attrs[k.strip()] = v.strip()
            record["attributes"] = attrs
        else:
            record["message"] = line
            record["format"]  = "unknown_network"

        records.append(record)

    return records


def parse_network_generic(content: str) -> list[dict]:
    """
    Fallback for network logs that are not CEF or LEEF.
    Tries to detect format and delegates; otherwise stores raw lines.
    """
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if lines and lines[0].startswith("CEF:"):
        return parse_cef(content)
    if lines and lines[0].startswith("LEEF:"):
        return parse_leef(content)

    # Plain key=value or whitespace-delimited (e.g., firewall logs)
    records = []
    for line in lines:
        record: dict = {"raw": line, "log_type": "network", "format": "generic"}
        # Try key=value
        if "=" in line:
            for pair in line.split():
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    record[k] = v
        else:
            record["message"] = line
        records.append(record)

    return records


def parse_cloud_json(content: str, filepath: Path) -> list[dict]:
    """
    Parse cloud logs that are already JSON or JSON-Lines.
    Handles AWS CloudTrail envelope, Azure Activity Log arrays, flat JSON-L.
    """
    records = []
    content = content.strip()

    # Try JSON-Lines first
    lines = content.splitlines()
    if len(lines) > 1:
        all_json = True
        for line in lines:
            try:
                json.loads(line)
            except json.JSONDecodeError:
                all_json = False
                break
        if all_json:
            for line in lines:
                obj = json.loads(line)
                obj.setdefault("log_type", "cloud")
                obj.setdefault("format", "jsonl")
                records.append(obj)
            return records

    # Try full JSON
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cannot parse cloud log as JSON: {exc}") from exc

    # AWS CloudTrail envelope: {"Records": [...]}
    if isinstance(data, dict) and "Records" in data:
        for rec in data["Records"]:
            rec.setdefault("log_type", "cloud")
            rec.setdefault("format", "aws_cloudtrail")
            records.append(rec)
        return records

    # Azure: top-level array
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict):
                rec.setdefault("log_type", "cloud")
                rec.setdefault("format", "azure_activity")
                records.append(rec)
        return records

    # Single JSON object
    data.setdefault("log_type", "cloud")
    data.setdefault("format", "json_single")
    records.append(data)
    return records



def parse_apache_combined(content: str) -> list[dict]:
    """
    Parse Apache Combined Log Format (and Common Log Format as a subset).

    Combined:
      127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://ref.example/" "Mozilla/5.0"

    Common (no referer/user-agent):
      127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326

    Both formats handled — referer and user_agent are optional.
    """
    COMBINED_RE = re.compile(
        r'(?P<client_ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<auth_user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*?)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<response_bytes>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)")?'
        r'(?:\s+"(?P<user_agent>[^"]*)")?'
    )
    APACHE_TS_RE = re.compile(
        r'(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})\s([+-]\d{4})'
    )
    MONTH_MAP = {
        "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
        "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
        "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
    }

    def _normalise_timestamp(raw_ts: str) -> str:
        m = APACHE_TS_RE.match(raw_ts)
        if not m:
            return raw_ts
        day, mon, year, time_, tz = m.groups()
        month = MONTH_MAP.get(mon, mon)
        return f"{year}-{month}-{day}T{time_}{tz}"

    def _parse_request(req: str) -> dict:
        # Split on first space (method) and trailing HTTP/version so URIs
        # containing spaces (e.g. SQLi payloads) are preserved intact.
        import re as _re
        ver_match = _re.search(r'\s+(HTTP/[\d.]+)$', req)
        if ver_match:
            http_version = ver_match.group(1)
            remainder    = req[:ver_match.start()]
            space_idx    = remainder.find(" ")
            if space_idx != -1:
                return {
                    "method":       remainder[:space_idx],
                    "uri":          remainder[space_idx + 1:],
                    "http_version": http_version,
                }
        parts = req.split(" ", 2)
        if len(parts) == 3:
            return {"method": parts[0], "uri": parts[1], "http_version": parts[2]}
        return {"raw_request": req}

    records = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        record: dict = {"raw": line, "log_type": "apache", "format": "combined"}
        m = COMBINED_RE.match(line)
        if m:
            gd = m.groupdict()
            record["client_ip"]      = gd["client_ip"]
            record["ident"]          = gd["ident"]
            record["auth_user"]      = gd["auth_user"]
            record["timestamp_raw"]  = gd["timestamp"]
            record["timestamp"]      = _normalise_timestamp(gd["timestamp"])
            record["request"]        = _parse_request(gd["request"])
            record["status"]         = int(gd["status"])
            record["response_bytes"] = (
                int(gd["response_bytes"])
                if gd["response_bytes"] and gd["response_bytes"] != "-"
                else None
            )
            if gd.get("referer") is not None:
                record["referer"]    = gd["referer"] or None
            if gd.get("user_agent") is not None:
                record["user_agent"] = gd["user_agent"] or None
            # Flattened convenience fields for Sigma detection
            record["method"]       = record["request"].get("method", "")
            record["uri_path"]     = record["request"].get("uri", "").split("?")[0]
            record["uri_query"]    = (
                record["request"].get("uri", "").split("?", 1)[1]
                if "?" in record["request"].get("uri", "") else None
            )
            record["http_version"] = record["request"].get("http_version", "")
        else:
            log.warning("Line %d did not match Combined/Common format, storing raw.", lineno)
            record["format"]  = "unparsed"
            record["message"] = line

        records.append(record)
    return records

# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def convert_file(src: Path, dst: Path, log_type: str) -> int:
    """
    Convert a single raw log file to JSON and write it to dst.
    Returns the number of records written.
    """
    content = src.read_text(encoding="utf-8", errors="replace")

    try:
        if log_type == "windows":
            records = parse_windows_xml(content)
        elif log_type == "linux":
            records = parse_linux_syslog(content)
        elif log_type == "network":
            suffix = src.suffix.lower()
            if suffix == ".cef":
                records = parse_cef(content)
            elif suffix == ".leef":
                records = parse_leef(content)
            else:
                records = parse_network_generic(content)
        elif log_type == "cloud":
            records = parse_cloud_json(content, src)
        elif log_type == "apache":
            records = parse_apache_combined(content)
        else:
            raise ValueError(f"Unknown log_type: {log_type!r}")
    except Exception as exc:
        log.error("  ✗ Failed to parse %s: %s", src, exc)
        return 0

    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False, default=str)

    return len(records)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Convert raw logs to JSON.")
    parser.add_argument(
        "--type",
        choices=list(LOG_TYPE_EXTENSIONS.keys()),
        help="Only convert logs of this type (default: all).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be converted without writing files.",
    )
    args = parser.parse_args()

    types_to_process = [args.type] if args.type else list(LOG_TYPE_EXTENSIONS.keys())

    total_files   = 0
    total_records = 0
    failures      = 0

    for log_type in types_to_process:
        raw_dir  = RAW_ROOT  / log_type
        json_dir = JSON_ROOT / log_type

        if not raw_dir.exists():
            log.warning("Raw directory not found, skipping: %s", raw_dir)
            continue

        extensions = LOG_TYPE_EXTENSIONS[log_type]
        raw_files  = [
            f for f in raw_dir.rglob("*")
            if f.is_file() and f.suffix.lower() in extensions
        ]

        if not raw_files:
            log.info("[%s] No files to convert.", log_type)
            continue

        log.info("[%s] Found %d file(s) to convert.", log_type, len(raw_files))

        for src in sorted(raw_files):
            rel      = src.relative_to(raw_dir)
            dst      = json_dir / rel.with_suffix(".json")
            log.info("  → %s", rel)

            if args.dry_run:
                log.info("    (dry-run) would write → %s", dst)
                continue

            n = convert_file(src, dst, log_type)
            if n:
                log.info("    ✓ %d record(s) → %s", n, dst.relative_to(REPO_ROOT))
                total_files   += 1
                total_records += n
            else:
                failures += 1

    log.info(
        "Done. %d file(s) converted, %d total record(s), %d failure(s).",
        total_files, total_records, failures,
    )
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
