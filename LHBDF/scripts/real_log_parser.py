"""
LHBDF - Real-World Log Parser (Step 20)
--------------------------------------------
Parses the real, publicly-published OpenSSH server log from the
LogHub dataset collection (Zhu et al., "Tools and Benchmarks for
Automated Log Parsing," ICSE 2019; https://github.com/logpai/loghub)
into LHBDF's internal authentication log schema.

This is a GENUINE production SSH server's log -- not synthetic.
It captures ~4 hours of real internet background traffic hitting an
internet-facing SSH server: automated scanning bots attempting common
usernames, occasional deliberate brute-force bursts, and exactly one
real successful login. This is used as a REALISTIC BACKGROUND/BASELINE
layer, into which LHBDF's controlled, labeled attack and normal
scenarios are injected (see inject_real_logs.py) to create a hybrid
evaluation dataset that is both realistic AND has trustworthy ground
truth labels.

Extraction rule: only lines containing an explicit authentication
OUTCOME are extracted ("Failed password for ..." -> failure,
"Accepted password for ..." -> success). Precursor lines like
"Invalid user X from IP" are informational and are not separately
counted, since the subsequent "Failed password for invalid user X"
line already captures that same failed attempt.
"""

import re
from datetime import datetime

# The raw log has no year; LogHub documents this capture as being from
# a server compromise study conducted in Dec 2014 (Zhu et al., ICSE 2019
# supplementary materials). We assign 2014 to keep chronological order
# and realistic date arithmetic; the absolute year is not meaningful to
# LHBDF's window-relative detection logic.
LOG_YEAR = 2014

_FAILED_RE   = re.compile(
    r"^(\w{3} +\d+ [\d:]+) \S+ sshd\[\d+\]: Failed password for "
    r"(?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)
_ACCEPTED_RE = re.compile(
    r"^(\w{3} +\d+ [\d:]+) \S+ sshd\[\d+\]: Accepted password for "
    r"(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)"
)


def parse_real_openssh_log(path: str) -> list[dict]:
    """
    Parses the real LogHub OpenSSH_2k.log file into LHBDF's internal
    entry schema: {timestamp, ip_address, username, login_outcome,
    request_source, session_id}.

    Returns entries sorted by timestamp.
    """
    entries = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")

            m = _FAILED_RE.match(line)
            if m:
                ts_str, user, ip, port = m.groups()
                entries.append(_build_entry(ts_str, ip, user, "failure", port))
                continue

            m = _ACCEPTED_RE.match(line)
            if m:
                ts_str, user, ip, port = m.groups()
                entries.append(_build_entry(ts_str, ip, user, "success", port))
                continue

    entries.sort(key=lambda e: e["timestamp"])
    return entries


def _build_entry(ts_str: str, ip: str, user: str, outcome: str, port: str) -> dict:
    # ts_str like "Dec 10 06:55:46" (possibly double-space before single-digit day)
    ts_str_norm = re.sub(r" +", " ", ts_str)
    dt = datetime.strptime(f"{LOG_YEAR} {ts_str_norm}", "%Y %b %d %H:%M:%S")
    return {
        "timestamp":      dt,
        "ip_address":     ip,
        "username":       user,
        "login_outcome":  outcome,
        "request_source": "ssh",
        "session_id":      f"real_{ip}_{port}",
    }


def summarize(entries: list[dict]) -> dict:
    ips = set(e["ip_address"] for e in entries)
    failures = sum(1 for e in entries if e["login_outcome"] == "failure")
    successes = sum(1 for e in entries if e["login_outcome"] == "success")
    return {
        "total_entries": len(entries),
        "unique_ips":    len(ips),
        "failures":      failures,
        "successes":     successes,
        "start":         entries[0]["timestamp"] if entries else None,
        "end":           entries[-1]["timestamp"] if entries else None,
    }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "loghub/OpenSSH/OpenSSH_2k.log"
    entries = parse_real_openssh_log(path)
    s = summarize(entries)
    print(f"Parsed {s['total_entries']} real auth events from {s['unique_ips']} unique real IPs")
    print(f"  Failures : {s['failures']}")
    print(f"  Successes: {s['successes']}")
    print(f"  Time span: {s['start']} -> {s['end']}")
