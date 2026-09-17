"""
Unit tests for modules/slow_attack_detector.py

Covers the core signature logic in isolation (no dataset dependency),
plus edge cases the real dataset doesn't exercise:
  - too few attempts (should NOT trigger)
  - short span (should NOT trigger)
  - multi-account IP (should NOT trigger — that's the fast path's job)
  - mostly-successful account (should NOT trigger)
  - irregular/random pacing (should NOT trigger — human, not scripted)
  - a clean low-and-slow signature (SHOULD trigger)
"""

import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.slow_attack_detector import detect_slow_attacks, merge_with_fast_path


def _mk(ip, username, outcome, ts):
    return {"ip_address": ip, "username": username, "login_outcome": outcome, "timestamp": ts}


def _evenly_spaced_failures(ip, username, n, gap_hours, start=None):
    start = start or datetime(2026, 1, 1, 0, 0, 0)
    return [_mk(ip, username, "failure", start + timedelta(hours=i * gap_hours)) for i in range(n)]


def test_clean_low_and_slow_signature_triggers():
    entries = _evenly_spaced_failures("10.0.0.1", "admin", n=8, gap_hours=3)
    findings = detect_slow_attacks(entries)
    assert len(findings) == 1
    f = findings[0]
    assert f["ip_address"] == "10.0.0.1"
    assert f["username"] == "admin"
    assert f["is_alert"] is True
    assert f["severity"] in ("HIGH", "MEDIUM")


def test_too_few_attempts_does_not_trigger():
    entries = _evenly_spaced_failures("10.0.0.2", "admin", n=3, gap_hours=3)
    findings = detect_slow_attacks(entries)
    assert findings == []


def test_short_span_does_not_trigger():
    # 8 failures but only 30 minutes apart total -> looks like a fast burst, not "slow"
    entries = _evenly_spaced_failures("10.0.0.3", "admin", n=8, gap_hours=0.05)
    findings = detect_slow_attacks(entries)
    assert findings == []


def test_multi_account_ip_does_not_trigger():
    # Same IP hitting many DIFFERENT accounts over a long span -> not single-account
    # persistence; this is the fast path's/multi-window's job, not ours.
    start = datetime(2026, 1, 1, 0, 0, 0)
    entries = []
    for i in range(8):
        entries.append(_mk("10.0.0.4", f"user{i}", "failure", start + timedelta(hours=i * 3)))
    findings = detect_slow_attacks(entries)
    assert findings == []


def test_mostly_successful_account_does_not_trigger():
    start = datetime(2026, 1, 1, 0, 0, 0)
    entries = [_mk("10.0.0.5", "bob", "success", start + timedelta(hours=i * 3)) for i in range(8)]
    findings = detect_slow_attacks(entries)
    assert findings == []


def test_irregular_random_pacing_does_not_trigger():
    # Sporadic, unevenly-spaced failures over a long span (a human forgetting
    # their password now and then) should NOT look like a scripted attack.
    start = datetime(2026, 1, 1, 0, 0, 0)
    offsets_hours = [0, 0.2, 11, 11.3, 30, 30.1, 30.2, 48]
    entries = [_mk("10.0.0.6", "carol", "failure", start + timedelta(hours=h)) for h in offsets_hours]
    findings = detect_slow_attacks(entries)
    assert findings == []


def test_empty_input_returns_empty():
    assert detect_slow_attacks([]) == []


def test_merge_with_fast_path_keeps_fast_path_finding_when_ip_already_flagged():
    fast = [{"ip_address": "10.0.0.1", "risk_score": 0.7, "is_alert": True}]
    slow = [{"ip_address": "10.0.0.1", "risk_score": 0.99, "is_alert": True}]
    combined = merge_with_fast_path(fast, slow)
    assert len(combined) == 1
    assert combined[0]["risk_score"] == 0.7  # fast-path finding wins, not overwritten


def test_merge_with_fast_path_adds_slow_only_ip():
    fast = [{"ip_address": "10.0.0.1", "risk_score": 0.7, "is_alert": True}]
    slow = [{"ip_address": "10.0.0.9", "risk_score": 0.95, "is_alert": True}]
    combined = merge_with_fast_path(fast, slow)
    ips = {c["ip_address"] for c in combined}
    assert ips == {"10.0.0.1", "10.0.0.9"}
