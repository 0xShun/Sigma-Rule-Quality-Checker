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

# -- Logging setup -------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# -- Paths ---------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
RAW_ROOT  = REPO_ROOT / "logs" / "raw"
JSON_ROOT = REPO_ROOT / "logs" / "json"

# -- Supported extensions per log type -----------------------------------------
LOG_TYPE_EXTENSIONS = {
    "windows": [".xml", ".evtx_xml"],
    "linux":   [".log", ".syslog"],
    "network": [".log", ".cef", ".leef", ".txt"],
    "cloud":   [".json", ".jsonl", ".log"],
    "apache":  [".log", ".access_log"],
}


# ------------------------------------------------------------------------------
# Parser functions
# ------------------------------------------------------------------------------

def parse_windows_xml(content: str) -> list[dict]:
    records = []
    if not content.strip().startswith("<Events"):
        content = f"<Events>{content}</Events>"
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    for event in root.findall(".//e:Event", ns):
        record: dict = {}
        system = event.find("e:System", ns)
        if system is not None:
            provider = system.find("e:Provider", ns)
            if provider is not None:
                record["provider_name"] = provider.get("Name", "")
                record["provider_guid"] = provider.get("Guid", "")
            for tag in ["EventID", "Version", "Level", "Task", "Opcode", "Keywords", "Channel", "Computer"]:
                el = system.find(f"e:{tag}", ns)
                if el is not None:
                    record[tag.lower()] = el.text
            time_el = system.find("e:TimeCreated", ns)
            if time_el is not None:
                record["timestamp"] = time_el.get("SystemTime", "")
            security = system.find("e:Security", ns)
            if security is not None:
                record["security_user_id"] = security.get("UserID", "")
        event_data = event.find("e:EventData", ns)
        if event_data is not None:
            data: dict = {}
            for data_el in event_data.findall("e:Data", ns):
                name  = data_el.get("Name", f"Data_{len(data)}")
                value = data_el.text or ""
                data[name] = value
            record["event_data"] = data
        user_data = event.find("e:UserData", ns)
        if user_data is not None:
            record["user_data"] = _xml_element_to_dict(user_data)
        record["log_type"] = "windows"
        records.append(record)
    return records


def _xml_element_to_dict(element) -> dict:
    result = {}
    for child in element:
        tag = child.tag.split("}")[-1]
        result[tag] = child.text or _xml_element_to_dict(child)
    return result


def parse_linux_syslog(content: str) -> list[dict]:
    SYSLOG_RE = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s[\d:]+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s+"
        r"(?P<message>.+)$"
    )
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
            record.update({"timestamp": m.group("timestamp"), "hostname": m.group("hostname"),
                           "process": m.group("process"), "pid": m.group("pid"),
                           "message": m.group("message"), "format": "rfc3164"})
            records.append(record)
            continue
        m = RFC5424_RE.match(line)
        if m:
            record.update({"priority": int(m.group("pri")), "timestamp": m.group("timestamp"),
                           "hostname": m.group("hostname"), "appname": m.group("appname"),
                           "procid": m.group("procid"), "msgid": m.group("msgid"),
                           "structured_data": m.group("structured_data"),
                           "message": m.group("message"), "format": "rfc5424"})
            records.append(record)
            continue
        record["message"] = line
        record["format"]  = "unknown"
        records.append(record)
    return records


def parse_cef(content: str) -> list[dict]:
    CEF_HEADER_RE = re.compile(
        r"^CEF:(?P<cef_version>\d+)\|(?P<device_vendor>[^|]*)\|(?P<device_product>[^|]*)\|"
        r"(?P<device_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<n>[^|]*)\|"
        r"(?P<severity>[^|]*)\|(?P<extensions>.*)$"
    )
    def _parse_extensions(ext_str):
        result = {}
        parts  = re.split(r"(\w+)=", ext_str)
        for k, v in zip(parts[1::2], parts[2::2]):
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
    LEEF_HEADER_RE = re.compile(
        r"^LEEF:(?P<leef_version>[\d.]+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
        r"(?P<version>[^|]*)\|(?P<event_id>[^|]*)\|(?P<attributes>.*)$"
    )
    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        record: dict = {"raw": line, "log_type": "network", "format": "leef"}
        m = LEEF_HEADER_RE.match(line)
        if m:
            record.update({"leef_version": m.group("leef_version"), "vendor": m.group("vendor"),
                           "product": m.group("product"), "version": m.group("version"),
                           "event_id": m.group("event_id")})
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
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if lines and lines[0].startswith("CEF:"):
        return parse_cef(content)
    if lines and lines[0].startswith("LEEF:"):
        return parse_leef(content)
    records = []
    for line in lines:
        record: dict = {"raw": line, "log_type": "network", "format": "generic"}
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
    records = []
    content = content.strip()
    lines = content.splitlines()
    if len(lines) > 1:
        all_json = all(_is_json(l) for l in lines if l.strip())
        if all_json:
            for line in lines:
                obj = json.loads(line)
                obj.setdefault("log_type", "cloud")
                obj.setdefault("format", "jsonl")
                records.append(obj)
            return records
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cannot parse cloud log as JSON: {exc}") from exc
    if isinstance(data, dict) and "Records" in data:
        for rec in data["Records"]:
            rec.setdefault("log_type", "cloud")
            rec.setdefault("format", "aws_cloudtrail")
            records.append(rec)
        return records
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict):
                rec.setdefault("log_type", "cloud")
                rec.setdefault("format", "azure_activity")
                records.append(rec)
        return records
    data.setdefault("log_type", "cloud")
    data.setdefault("format", "json_single")
    records.append(data)
    return records


def _is_json(line: str) -> bool:
    try:
        json.loads(line)
        return True
    except json.JSONDecodeError:
        return False


def parse_apache_combined(content: str) -> list[dict]:
    """
    Parse Apache Combined Log Format (and Common Log Format as a subset).

    Combined:
      127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://referer.example/" "Mozilla/5.0"

    Common (no referer/user-agent fields):
      127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
    """
    COMBINED_RE = re.compile(
        r'^(?P<client_ip>\S+)\s+'
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
        return f"{year}-{MONTH_MAP.get(mon, mon)}-{day}T{time_}{tz}"

    def _parse_request(req: str) -> dict:
        # Anchor on the trailing HTTP/version token so URIs containing spaces
        # (e.g. SQLi payloads) are kept intact.
        ver_match = re.search(r'\s+(HTTP/[\d.]+)$', req)
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
            # Flattened fields for Sigma detection
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


# ------------------------------------------------------------------------------
# Dispatcher
# ------------------------------------------------------------------------------

def convert_file(src: Path, dst: Path, log_type: str) -> int:
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
        log.error("  x Failed to parse %s: %s", src, exc)
        return 0

    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False, default=str)
    return len(records)


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

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
            rel = src.relative_to(raw_dir)
            dst = json_dir / rel.with_suffix(".json")
            log.info("  -> %s", rel)

            if args.dry_run:
                log.info("    (dry-run) would write -> %s", dst)
                continue

            n = convert_file(src, dst, log_type)
            if n:
                log.info("    ok %d record(s) -> %s", n, dst.relative_to(REPO_ROOT))
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