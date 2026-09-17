"""
Unit tests for scripts/adapt_honeypot_data.py

Covers the adapter's core logic in isolation (no real dataset dependency):
  - credential regex correctly parses "username: X, password: Y" messages
  - non-"SSH login" event types (SSH connect, SSH disconnect, exec_command)
    are excluded, since only login events carry a username to analyze
  - rows missing a parseable credential are skipped, not crashed on
  - every emitted row is mapped to login_outcome='failure' (the documented
    interpretive choice -- see module docstring)
  - timestamp microseconds are stripped to match LHBDF's expected format
  - output schema matches exactly what modules/log_parser.py expects
"""

import csv
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.adapt_honeypot_data import adapt, CRED_RE

EXPECTED_FIELDS = {"timestamp", "ip_address", "username", "login_outcome",
                   "request_source", "session_id"}


def _write_csv(rows, fieldnames):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _mk_src_row(event_type, ip="1.2.3.4", ts="2026-01-01T00:00:00.123456",
                 message="", session_id="sess-1"):
    return {
        "timestamp": ts, "ip": ip, "port": "51234", "event_type": event_type,
        "message": message, "command": "", "level": "WARNING",
        "session_id": session_id,
    }


SRC_FIELDS = ["timestamp", "ip", "port", "event_type", "message", "command",
              "level", "session_id"]


def test_credential_regex_parses_standard_message():
    m = CRED_RE.search("Bot entered username: root, password: toor123")
    assert m is not None
    assert m.group(1).strip() == "root"
    assert m.group(2).strip() == "toor123"


def test_credential_regex_handles_password_with_commas_or_colons():
    m = CRED_RE.search("Bot entered username: admin, password: p@ss:w0rd,ok")
    assert m is not None
    assert m.group(1).strip() == "admin"
    assert m.group(2).strip() == "p@ss:w0rd,ok"


def test_only_ssh_login_events_are_kept():
    rows = [
        _mk_src_row("SSH connect"),
        _mk_src_row("SSH login", message="Bot entered username: root, password: 123"),
        _mk_src_row("exec_command", message="whoami"),
        _mk_src_row("SSH disconnect"),
    ]
    src = _write_csv(rows, SRC_FIELDS)
    dst = tempfile.mktemp(suffix=".csv")
    out = adapt(src, dst)
    assert len(out) == 1
    assert out[0]["username"] == "root"


def test_rows_without_parseable_credentials_are_skipped_not_crashed():
    rows = [
        _mk_src_row("SSH login", message="malformed, no credentials here"),
        _mk_src_row("SSH login", message="Bot entered username: user1, password: pw1"),
    ]
    src = _write_csv(rows, SRC_FIELDS)
    dst = tempfile.mktemp(suffix=".csv")
    out = adapt(src, dst)
    assert len(out) == 1
    assert out[0]["username"] == "user1"


def test_every_row_mapped_to_failure_outcome():
    rows = [_mk_src_row("SSH login", message="Bot entered username: x, password: y")]
    src = _write_csv(rows, SRC_FIELDS)
    dst = tempfile.mktemp(suffix=".csv")
    out = adapt(src, dst)
    assert out[0]["login_outcome"] == "failure"


def test_timestamp_microseconds_stripped():
    rows = [_mk_src_row("SSH login", ts="2026-03-04T14:14:22.987654",
                         message="Bot entered username: root, password: 1")]
    src = _write_csv(rows, SRC_FIELDS)
    dst = tempfile.mktemp(suffix=".csv")
    out = adapt(src, dst)
    assert out[0]["timestamp"] == "2026-03-04T14:14:22"


def test_output_schema_matches_log_parser_expectations():
    rows = [_mk_src_row("SSH login", message="Bot entered username: root, password: 1")]
    src = _write_csv(rows, SRC_FIELDS)
    dst = tempfile.mktemp(suffix=".csv")
    adapt(src, dst)
    with open(dst, encoding="utf-8") as f:
        header = next(csv.reader(f))
    assert set(header) == EXPECTED_FIELDS


def test_missing_source_file_raises_helpful_error():
    try:
        adapt("/nonexistent/path.csv", tempfile.mktemp(suffix=".csv"))
        assert False, "expected FileNotFoundError"
    except FileNotFoundError as e:
        assert "zenodo.org" in str(e) or "doi.org" in str(e)
