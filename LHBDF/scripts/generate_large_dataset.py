"""
LHBDF — Large Dataset Generator (104 IPs)
Attacks: 50 (7 patterns) | Normal: 54 (5 patterns) | Entries: ~650-950

Attack patterns A-F operate within a single calendar day window
(seconds-to-minutes apart). Pattern G is deliberately spread across
~21 hours with ~3-hour gaps between events -- by construction this
is INVISIBLE to 5-minute and 1-hour sliding windows (no two events
of the same IP ever co-occur inside such a short window), and only
becomes detectable once a 24-hour window is used. This directly
demonstrates the necessity of multi-window analysis.
"""
import csv, json, random, os
from datetime import datetime, timedelta

random.seed(42)
BASE = datetime(2025, 4, 1, 6, 0, 0)
ROWS, GT = [], {}
IPS = [f"203.0.113.{i}" for i in range(1, 105)]   # 104 IPs

def add(ts, ip, user, outcome, source="web"):
    ROWS.append({"timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                 "ip_address": ip, "username": user,
                 "login_outcome": outcome, "request_source": source,
                 "session_id": f"sess_{abs(hash(ip+str(ts)))%9000+1000}"})

def rand_ts():
    return BASE + timedelta(days=random.randint(0,6),
                            hours=random.randint(6,22),
                            minutes=random.randint(0,55))

# ── A: Classic Brute-Force (10 IPs) — all models detect ────
for i in range(10):
    ip=IPS[i]; GT[ip]=1; t=rand_ts()
    user=random.choice(["admin","root","administrator"])
    n=random.randint(10,15); gap=random.randint(8,18)
    for j in range(n): add(t+timedelta(seconds=j*gap), ip, user, "failure")

# ── B: Stealthy BF (8 IPs) — 4 fails, 60s intervals, LHBDF advantage ──
for i in range(8):
    ip=IPS[10+i]; GT[ip]=1; t=rand_ts()
    user=random.choice(["root","sysadmin","admin"])
    for j in range(4): add(t+timedelta(seconds=j*60), ip, user, "failure")

# ── C: Aggressive Cred Stuffing (10 IPs) — all models detect ─
for i in range(10):
    ip=IPS[18+i]; GT[ip]=1; t=rand_ts()
    n_u=random.randint(5,8); gap=random.randint(12,22); entry=0
    for j in range(n_u):
        user=f"user{random.randint(1000,9999)}"
        for k in range(random.randint(1,2)):
            add(t+timedelta(seconds=entry*gap), ip, user, "failure"); entry+=1

# ── D: Slow Cred Stuffing (7 IPs) — 3 users, 70s, LHBDF advantage ──
for i in range(7):
    ip=IPS[28+i]; GT[ip]=1; t=rand_ts()
    for j in range(3): add(t+timedelta(seconds=j*70), ip, f"victim{j+1}", "failure")

# ── E: Bot Attack (5 IPs) — 4 fails, 30s intervals, LHBDF advantage ──
for i in range(5):
    ip=IPS[35+i]; GT[ip]=1; t=rand_ts()
    for j in range(4): add(t+timedelta(seconds=j*30), ip, "svc_account", "failure")

# ── F: Successful Credential Stuffing (6 IPs) — stolen VALID creds, ──
# ── ZERO failures, high diversity+velocity. F-only model is BLIND   ──
# ── to this; only U/V (hybrid) catches it. ──────────────────────────
for i in range(6):
    ip=IPS[40+i]; GT[ip]=1; t=rand_ts()
    n_u=random.randint(8,10); gap=14  # fixed gap -> max temporal regularity
    for j in range(n_u):
        add(t+timedelta(seconds=j*gap), ip, f"stolen_acct{j+1}", "success")

# ── G: Low-and-Slow Brute-Force (4 IPs) — 8 isolated failures spread ──
# ── ~3 hours apart across ONE calendar day (~21h span). Each pair of ──
# ── consecutive events is >2h apart, so NO 5-min or 1-hour window    ──
# ── can ever group 2+ of them together -- those scales see NOTHING.  ──
# ── Only a 24-hour window accumulates all 8 into one detection.      ──
for i in range(4):
    ip=IPS[46+i]; GT[ip]=1
    day_base = BASE + timedelta(days=random.randint(0,5))
    user = "ceo_account" if i % 2 == 0 else "finance_admin"
    for h in [1,4,7,10,13,16,19,22]:
        jitter = random.randint(0,40)
        add(day_base+timedelta(hours=h, minutes=jitter), ip, user, "failure")

# ── N1: Single User Normal (14 IPs) ─────────────────────────
for i in range(14):
    ip=IPS[50+i]; GT[ip]=0
    for _ in range(random.randint(1,3)): add(rand_ts(), ip, f"user_{i+1}", "success")

# ── N2: Typo User (15 IPs) ──────────────────────────────────
for i in range(15):
    ip=IPS[64+i]; GT[ip]=0; t=rand_ts(); user=f"typo_usr{i+1}"
    typos=random.randint(1,2)
    for j in range(typos): add(t+timedelta(seconds=j*7), ip, user, "failure")
    add(t+timedelta(seconds=typos*7+4), ip, user, "success")

# ── N3: Office NAT (10 IPs) — Username Diversity FP; LHBDF correct ─
for i in range(10):
    ip=IPS[79+i]; GT[ip]=0; t=rand_ts(); n_emp=random.randint(4,5)
    for j in range(n_emp):
        add(t+timedelta(minutes=j*2+random.randint(0,1)), ip, f"emp_{i}_{j}", "success")

# ── N4: API Monitoring (5 IPs) — Time-Window FP; LHBDF correct ──
for i in range(5):
    ip=IPS[89+i]; GT[ip]=0; t=rand_ts()
    for j in range(12): add(t+timedelta(seconds=j*25), ip, "healthcheck", "success", "api")

# ── N5: Shared Kiosk (10 IPs) — Username Diversity FP; LHBDF correct ─
for i in range(10):
    ip=IPS[94+i]; GT[ip]=0; t=rand_ts(); n_usr=random.randint(5,7)
    for j in range(n_usr):
        bt=t+timedelta(minutes=j*4)
        if random.random()<0.12: add(bt, ip, f"kiosk_{i}_{j}", "failure")
        add(bt+timedelta(seconds=8), ip, f"kiosk_{i}_{j}", "success")

ROWS.sort(key=lambda r: r["timestamp"])
os.makedirs("logs", exist_ok=True)
with open("logs/large_auth.csv","w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=["timestamp","ip_address","username","login_outcome","request_source","session_id"])
    w.writeheader(); w.writerows(ROWS)
with open("logs/large_ground_truth.json","w") as f:
    json.dump(GT, f, indent=2)

attacks=sum(GT.values())
print(f"Generated: {len(ROWS)} entries | {len(GT)} IPs | {attacks} attacks | {len(GT)-attacks} normal")
