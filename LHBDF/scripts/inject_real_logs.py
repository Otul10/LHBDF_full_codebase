"""
LHBDF - Real-World Log Injection (Step 20)
================================================
Creates a HYBRID evaluation dataset by injecting LHBDF's controlled,
labeled attack and normal scenarios into a REAL production SSH
server's authentication log (LogHub OpenSSH_2k.log; Zhu et al.,
ICSE 2019). This directly addresses the "dataset realism" concern
raised in peer review: rather than evaluating purely on synthetic
data, this dataset combines genuine internet background traffic
(real scanning bots, real usernames, real IPs, real timing jitter)
with the same 7 labeled attack patterns and 5 normal patterns used
in the fully-synthetic evaluation, allowing a direct comparison of
detection performance between "clean synthetic" and "realistic
hybrid" conditions.

Composition of the hybrid dataset:
  - REAL background   : 518 events from 24 real attacking IPs
                         (genuine SSH scanning/brute-force noise,
                         UNLABELED -- excluded from strict Precision/
                         Recall/F1 scoring since no official ground
                         truth exists for them, but included in a
                         separate qualitative "bonus detection" check)
  - INJECTED normal    : 54 IPs, same 5 patterns as the synthetic
                          dataset (single user, typo, office NAT,
                          API monitoring, shared kiosk) -- LABELED 0
  - INJECTED attacks   : 50 IPs, same 7 patterns as the synthetic
                          dataset -- LABELED 1

Injected IPs use the 203.0.113.0/24 TEST-NET-3 documentation range
(RFC 5737), which can never collide with the real public IPs already
present in the background log.
"""

import csv
import json
import os
import random
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(__file__))
from real_log_parser import parse_real_openssh_log

random.seed(42)

# Real background log spans 2014-12-10 06:55:48 -> 11:04:45.
# Injected traffic is distributed across the FULL day surrounding that
# real incident, so the hybrid dataset reads as "one day of a real
# server's traffic, during which a real scanning incident occurred in
# the morning, plus additional labeled attack/normal activity."
DAY_BASE = datetime(2014, 12, 10, 0, 0, 0)
IPS = [f"203.0.113.{i}" for i in range(1, 105)]  # 104 injected IPs (RFC 5737)

ROWS = []      # will hold dict rows for CSV
GT   = {}      # injected-IP ground truth only


def add(ts, ip, user, outcome, source="web"):
    ROWS.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": ip, "username": user, "login_outcome": outcome,
        "request_source": source,
        "session_id": f"sess_{abs(hash(ip+str(ts))) % 9000 + 1000}",
    })


def rand_ts():
    return DAY_BASE + timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 55))


# ══════════════════════════════════════════════════════════════
#  1. LOAD REAL BACKGROUND LOG (unlabeled)
# ══════════════════════════════════════════════════════════════
real_entries = parse_real_openssh_log(
    os.path.join(os.path.dirname(__file__), "..", "logs", "OpenSSH_2k_real.log")
)
background_ips = sorted(set(e["ip_address"] for e in real_entries))
for e in real_entries:
    ROWS.append({
        "timestamp": e["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": e["ip_address"], "username": e["username"],
        "login_outcome": e["login_outcome"], "request_source": "ssh",
        "session_id": e["session_id"],
    })

# ══════════════════════════════════════════════════════════════
#  2. INJECTED ATTACKS (50 IPs, 7 patterns -- same as synthetic dataset)
# ══════════════════════════════════════════════════════════════
# A: Classic Brute-Force (10 IPs)
for i in range(10):
    ip = IPS[i]; GT[ip] = 1; t = rand_ts()
    user = random.choice(["admin", "root", "administrator"])
    n = random.randint(10, 15); gap = random.randint(8, 18)
    for j in range(n): add(t + timedelta(seconds=j*gap), ip, user, "failure")

# B: Stealthy BF (8 IPs)
for i in range(8):
    ip = IPS[10+i]; GT[ip] = 1; t = rand_ts()
    user = random.choice(["root", "sysadmin", "admin"])
    for j in range(4): add(t + timedelta(seconds=j*60), ip, user, "failure")

# C: Aggressive Cred Stuffing (10 IPs)
for i in range(10):
    ip = IPS[18+i]; GT[ip] = 1; t = rand_ts()
    n_u = random.randint(5, 8); gap = random.randint(12, 22); entry = 0
    for j in range(n_u):
        user = f"user{random.randint(1000,9999)}"
        for k in range(random.randint(1, 2)):
            add(t + timedelta(seconds=entry*gap), ip, user, "failure"); entry += 1

# D: Slow Cred Stuffing (7 IPs)
for i in range(7):
    ip = IPS[28+i]; GT[ip] = 1; t = rand_ts()
    for j in range(3): add(t + timedelta(seconds=j*70), ip, f"victim{j+1}", "failure")

# E: Bot Attack (5 IPs)
for i in range(5):
    ip = IPS[35+i]; GT[ip] = 1; t = rand_ts()
    for j in range(4): add(t + timedelta(seconds=j*30), ip, "svc_account", "failure")

# F: Successful Credential Stuffing (6 IPs) -- zero failures, all successes
for i in range(6):
    ip = IPS[40+i]; GT[ip] = 1; t = rand_ts()
    n_u = random.randint(8, 10); gap = 14
    for j in range(n_u):
        add(t + timedelta(seconds=j*gap), ip, f"stolen_acct{j+1}", "success")

# G: Low-and-Slow BF (4 IPs) -- ~3hr gaps across ~21 hours
for i in range(4):
    ip = IPS[46+i]; GT[ip] = 1
    user = "ceo_account" if i % 2 == 0 else "finance_admin"
    for h in [1, 4, 7, 10, 13, 16, 19, 22]:
        jitter = random.randint(0, 40)
        add(DAY_BASE + timedelta(hours=h, minutes=jitter), ip, user, "failure")

# ══════════════════════════════════════════════════════════════
#  3. INJECTED NORMAL TRAFFIC (54 IPs, 5 patterns)
# ══════════════════════════════════════════════════════════════
# N1: Single User Normal (14 IPs)
for i in range(14):
    ip = IPS[50+i]; GT[ip] = 0
    for _ in range(random.randint(1, 3)): add(rand_ts(), ip, f"user_{i+1}", "success")

# N2: Typo User (15 IPs)
for i in range(15):
    ip = IPS[64+i]; GT[ip] = 0; t = rand_ts(); user = f"typo_usr{i+1}"
    typos = random.randint(1, 2)
    for j in range(typos): add(t + timedelta(seconds=j*7), ip, user, "failure")
    add(t + timedelta(seconds=typos*7+4), ip, user, "success")

# N3: Office NAT (10 IPs)
for i in range(10):
    ip = IPS[79+i]; GT[ip] = 0; t = rand_ts(); n_emp = random.randint(4, 5)
    for j in range(n_emp):
        add(t + timedelta(minutes=j*2+random.randint(0, 1)), ip, f"emp_{i}_{j}", "success")

# N4: API Monitoring (5 IPs)
for i in range(5):
    ip = IPS[89+i]; GT[ip] = 0; t = rand_ts()
    for j in range(12): add(t + timedelta(seconds=j*25), ip, "healthcheck", "success", "api")

# N5: Shared Kiosk (10 IPs)
for i in range(10):
    ip = IPS[94+i]; GT[ip] = 0; t = rand_ts(); n_usr = random.randint(5, 7)
    for j in range(n_usr):
        bt = t + timedelta(minutes=j*4)
        if random.random() < 0.12: add(bt, ip, f"kiosk_{i}_{j}", "failure")
        add(bt + timedelta(seconds=8), ip, f"kiosk_{i}_{j}", "success")

# ══════════════════════════════════════════════════════════════
#  SAVE
# ══════════════════════════════════════════════════════════════
ROWS.sort(key=lambda r: r["timestamp"])
os.makedirs("logs", exist_ok=True)

with open("logs/hybrid_auth.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["timestamp","ip_address","username","login_outcome","request_source","session_id"])
    w.writeheader(); w.writerows(ROWS)

with open("logs/hybrid_ground_truth.json", "w") as f:
    json.dump(GT, f, indent=2)

with open("logs/hybrid_background_ips.json", "w") as f:
    json.dump({"background_ips": background_ips,
               "note": "Real IPs from LogHub OpenSSH_2k.log. Not included in "
                       "strict ground truth (no official labels exist), but "
                       "used for a separate qualitative detection check -- "
                       "see qualitative_background_check.py."}, f, indent=2)

attacks = sum(GT.values())
print(f"Hybrid dataset generated:")
print(f"  Total entries       : {len(ROWS)}  ({len(real_entries)} real + {len(ROWS)-len(real_entries)} injected)")
print(f"  Real background IPs : {len(background_ips)}  (unlabeled)")
print(f"  Injected labeled IPs: {len(GT)}  ({attacks} attack / {len(GT)-attacks} normal)")
print(f"  Saved: logs/hybrid_auth.csv, logs/hybrid_ground_truth.json, logs/hybrid_background_ips.json")
