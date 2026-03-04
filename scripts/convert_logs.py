#!/usr/bin/env python3
"""
convert_logs.py

Converts raw log files from logs/raw/ into JSON format in logs/json/.
Supports multiple log formats based on subfolder type:
  - windows/  : Windows Event Log XML (.evtx exported as XML, or raw .xml)
  - linux/    : Syslog format (.log, .syslog)
  - network/  : CEF, LEEF, or raw firewall/IDS logs (.log, .cef, .leef)
  - cloud/    : AWS CloudTrail, Azure, GCP (already JSON or JSON-lines)

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