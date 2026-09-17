"""
Adapter: converts the Boiko & Niiakyi (2026) SSH honeypot dataset
(ssh_attacks_full.csv) into LHBDF's expected log schema
(timestamp, ip_address, username, login_outcome, request_source, session_id).

Dataset source: "A 4-Month Dataset of SSH Botnet Interactions and Command
Payloads" (Boiko & Niiakyi, 2026), Zenodo DOI: 10.5281/zenodo.19629700.
Place the raw ssh_attacks_full.csv under logs/raw/ before running, or
pass its path explicitly (see Usage below).

Interpretive note (documented for thesis writeup):
Every 'SSH login' event is mapped to login_outcome='failure'. The honeypot
is medium-interaction and accepts nearly all submitted credentials by design
(to observe post-auth behavior) -- of 4,689 sessions that attempted a login,
only 16 ever proceeded to real shell interaction. This acceptance is an
artifact of the collection methodology, not a reflection of what would
happen against a real hardened system, where these largely default/weak
credential guesses would fail. Treating every attempt as 'failure' is the
semantically honest mapping for LHBDF's brute-force/credential-stuffing
threat model.

Usage:
  python scripts/adapt_honeypot_data.py [src_csv] [dst_csv]
  (defaults: logs/raw/ssh_attacks_full.csv -> logs/honeypot_adapted.csv)
"""
import csv
import re
import sys
import os

DEFAULT_SRC = os.path.join("logs", "raw", "ssh_attacks_full.csv")
DEFAULT_DST = os.path.join("logs", "honeypot_adapted.csv")

CRED_RE = re.compile(r"username:\s*([^,]+),\s*password:\s*(.+)")


def adapt(src_path: str, dst_path: str) -> list[dict]:
    if not os.path.exists(src_path):
        raise FileNotFoundError(
            f"Source file not found: {src_path}\n"
            "Download 'honey_csv.tar.gz' from "
            "https://doi.org/10.5281/zenodo.19629700, extract "
            "ssh_attacks_full.csv, and place it at this path "
            "(or pass the path as the first argument)."
        )

    out_rows = []
    with open(src_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["event_type"] != "SSH login":
                continue
            m = CRED_RE.search(row["message"])
            if not m:
                continue
            username = m.group(1).strip()
            ts = row["timestamp"].split(".")[0]  # strip microseconds
            out_rows.append({
                "timestamp": ts,
                "ip_address": row["ip"],
                "username": username,
                "login_outcome": "failure",
                "request_source": "honeypot",
                "session_id": row["session_id"],
            })

    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(dst_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "ip_address", "username",
            "login_outcome", "request_source", "session_id"
        ])
        writer.writeheader()
        writer.writerows(out_rows)

    return out_rows


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    dst = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_DST

    rows = adapt(src, dst)
    print(f"Wrote {len(rows)} login-attempt rows to {dst}")
    print(f"Distinct IPs: {len(set(r['ip_address'] for r in rows))}")


if __name__ == "__main__":
    main()
