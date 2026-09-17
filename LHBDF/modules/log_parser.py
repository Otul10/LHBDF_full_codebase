"""
LHBDF - Step 1: Log Parser
---------------------------
Reads and parses authentication log files (CSV or JSON).
Each log entry is normalized into a standard dictionary format.
"""

import csv
import json
import os
from datetime import datetime

REQUIRED_FIELDS = {"timestamp", "ip_address", "username", "login_outcome"}
VALID_OUTCOMES  = {"success", "failure"}


def parse_log(filepath: str) -> list[dict]:
    """Auto-detect file format and parse accordingly."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".csv":
        return _parse_csv(filepath)
    elif ext == ".json":
        return _parse_json(filepath)
    else:
        raise ValueError(f"Unsupported format: '{ext}'. Use .csv or .json")


def _parse_csv(filepath: str) -> list[dict]:
    entries = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            entry = _normalize(row, i)
            if entry:
                entries.append(entry)
    return entries


def _parse_json(filepath: str) -> list[dict]:
    entries = []
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("JSON log must be a list of objects.")
    for i, row in enumerate(data, start=1):
        entry = _normalize(row, i)
        if entry:
            entries.append(entry)
    return entries


def _normalize(raw: dict, line: int) -> dict | None:
    row = {k.strip().lower(): str(v).strip().lower() for k, v in raw.items()}

    missing = REQUIRED_FIELDS - row.keys()
    if missing:
        print(f"  [WARN] Line {line}: missing fields {missing} — skipped.")
        return None

    if row["login_outcome"] not in VALID_OUTCOMES:
        print(f"  [WARN] Line {line}: unknown outcome '{row['login_outcome']}' — skipped.")
        return None

    ts = _parse_timestamp(row["timestamp"], line)
    if ts is None:
        return None

    return {
        "timestamp":      ts,
        "ip_address":     row["ip_address"],
        "username":       row["username"],
        "login_outcome":  row["login_outcome"],
        "request_source": row.get("request_source", "unknown"),
        "session_id":     row.get("session_id", "unknown"),
    }


def _parse_timestamp(value: str, line: int) -> datetime | None:
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ", "%d/%m/%Y %H:%M:%S"]:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    print(f"  [WARN] Line {line}: cannot parse timestamp '{value}' — skipped.")
    return None
