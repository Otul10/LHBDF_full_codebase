# 🛡️ LHBDF — Lightweight Hybrid Behavioral Detection Framework

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Research](https://img.shields.io/badge/Type-M.Sc%20Research-teal.svg)]()
[![University](https://img.shields.io/badge/DIU-Cyber%20Security-navy.svg)]()

> **M.Sc. Cyber Security Research Project**  
> Daffodil International University — Spring 2025  
> **Student:** Ahnaf Tahmid Ridwan (251-56-014)

---

## 📌 Overview

**LHBDF** detects **brute-force** and **credential stuffing** attacks from authentication logs using a rule-based hybrid behavioral risk scoring framework — no machine learning required.

Unlike single-indicator methods, LHBDF combines **4 behavioral indicators** into a unified weighted risk score, making it lightweight, interpretable, and deployable in resource-constrained environments (SMBs).

---

## 🏗️ System Architecture

```
Auth Logs (CSV/JSON)
        │
        ▼
┌─────────────────┐
│  1. Log Parser  │  → Validates & normalizes entries
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│ 2. Feature Extractor │  → Extracts 4 behavioral indicators
│   (5-min windows)    │     per IP address
└────────┬─────────────┘
         │
         ▼
┌─────────────────┐
│ 3. Risk Scorer  │  → Risk = 0.35×F + 0.25×U + 0.25×V + 0.15×T
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│ 4. Alert Generator   │  → 🔴 HIGH | 🟡 MEDIUM | 🟢 LOW
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│ 5. Baseline Comparator│  → vs. Static Threshold, Time-Window,
│    + Evaluator        │     Username Diversity, Conv. Hybrid
└──────────────────────┘
```

---

## ⚖️ Risk Scoring Formula

```
Risk_Score = min(1.0,
             (0.35 × F_Score)   ← Failed Login Frequency
           + (0.25 × U_Score)   ← Username Diversity
           + (0.25 × V_Score)   ← Login Velocity
           + (0.15 × T_Score)   ← Temporal Behavior (bot regularity)
           + (0.10 × S_Score))  ← Success Ratio  ★ Step 17

Severity Levels (4-tier):
  🟣 CRITICAL   ≥ 0.80      →  Confirmed high-confidence attack
  🔴 HIGH       0.60–0.79   →  Alert — Investigate immediately
  🟡 SUSPICIOUS 0.40–0.59   →  Monitor closely
  🟢 NORMAL     < 0.40      →  Normal activity
```

**S_Score (Success Ratio)** = successful_attempts / total_attempts. Added as a 5th indicator to close a real detection gap: stolen-credential stuffing attacks replay *valid* credentials, producing zero or near-zero failures — meaning F_Score alone (and even F+U+V+T) can sit right at the alert boundary. S_Score directly captures "an unusually high proportion of successful logins from one source, combined with high diversity/velocity" as its own signal. The F/U/V/T weights are **unchanged** from the original 4-indicator formula by design — S_Score = 0 for any pure-failure attack, so the additive term contributes nothing and brute-force detection behavior is identical to before. The weight sum is 1.10; `min(score, 1.0)` keeps the output bounded.

---

## 📁 Project Structure

```
LHBDF/
├── main.py                     ← Run detection on any log file
├── evaluate.py                 ← Run evaluation against labeled dataset
├── ablation_study.py           ← Test 14 indicator-weight combinations (RQ4)
├── multi_window_analysis.py    ← Compare 5-min / 1-hour / 24-hour detection
├── adaptive_threshold_demo.py  ← Fixed vs. adaptive (μ+2σ) thresholds
├── roc_curve.py                ← ROC curve + AUC analysis
├── significance_testing.py     ← Paired t-test / Wilcoxon (bootstrap-based)
├── real_world_evaluation.py    ← Step 20: real SSH log + injected attacks
├── benchmark.py                ← CPU/RAM/latency/throughput benchmark
├── requirements.txt
├── logs/
│   ├── sample_auth.csv         ← Sample log for quick testing
│   ├── labeled_auth.csv        ← Small labeled dataset (11 IPs)
│   ├── ground_truth.json
│   ├── large_auth.csv          ← Main synthetic dataset (104 IPs, 7 attack patterns)
│   ├── large_ground_truth.json
│   ├── OpenSSH_2k_real.log     ← Real SSH server log (LogHub, Zhu et al. ICSE 2019)
│   ├── hybrid_auth.csv         ← Step 20: real log + injected labeled scenarios
│   ├── hybrid_ground_truth.json
│   └── hybrid_background_ips.json
├── scripts/
│   ├── generate_large_dataset.py  ← Regenerates the 104-IP synthetic dataset
│   ├── real_log_parser.py         ← Parses the real LogHub OpenSSH log format
│   └── inject_real_logs.py        ← Builds the Step 20 hybrid dataset
├── output/                     ← Reports saved here (auto-created)
└── modules/
    ├── log_parser.py           ← Step 1: Parse CSV/JSON logs
    ├── feature_extractor.py    ← Step 2: Extract 5 behavioral indicators
    ├── risk_scorer.py          ← Step 3: Weighted risk formula, 4-tier severity
    ├── attack_classifier.py    ← Step 18: Rule-based attack type classification
    ├── classification_report.py ← Step 18: Classification accuracy evaluation
    ├── alert_generator.py      ← Step 4: Terminal alerts + report
    ├── baseline_models.py      ← Step 5: 4 baseline detection models
    ├── comparator.py           ← Step 6: Side-by-side comparison table
    ├── evaluator.py            ← Step 7: Precision/Recall/F1/FPR
    ├── metrics_report.py       ← Step 7: Formatted metrics output
    ├── ablation.py             ← Indicator-combination testing engine
    ├── ablation_report.py      ← Ablation results formatting
    ├── multi_window.py         ← Multi-scale detection engine
    ├── multi_window_report.py  ← Multi-window results formatting
    ├── adaptive_threshold.py   ← Step 19: Median+3×MAD calibration engine
    ├── adaptive_threshold_report.py ← Adaptive threshold results formatting
    ├── roc_analysis.py         ← Threshold sweep + AUC computation
    ├── roc_report.py           ← ROC curve plotting (matplotlib)
    ├── significance_test.py    ← Bootstrap resampling + paired tests
    ├── significance_report.py  ← Significance test results formatting
    ├── background_check.py     ← Step 20: qualitative real-IP check engine
    ├── background_check_report.py ← Step 20: background check formatting
    └── resource_monitor.py     ← CPU-time-delta based benchmarking
```

---

## 🚀 Getting Started

### Requirements
- Python 3.10+
- No external packages needed (standard library only)

### Run Detection
```bash
# On sample log
python main.py logs/sample_auth.csv

# On your own log
python main.py path/to/your_log.csv
```

### Run Evaluation (Precision / Recall / F1)
```bash
python evaluate.py logs/large_auth.csv logs/large_ground_truth.json
```

### Run Ablation Study (which indicators matter most — RQ4)
```bash
python ablation_study.py logs/large_auth.csv logs/large_ground_truth.json
```

### Run Multi-Window Detection (5-min / 1-hour / 24-hour)
```bash
python multi_window_analysis.py logs/large_auth.csv logs/large_ground_truth.json
```

### Run Resource Consumption Benchmark
```bash
python benchmark.py logs/large_auth.csv
```

### Run Adaptive Threshold Comparison (Median + 3×MAD calibration)
```bash
python adaptive_threshold_demo.py logs/large_auth.csv logs/large_ground_truth.json
```

### Generate ROC Curve & AUC
```bash
python roc_curve.py logs/large_auth.csv logs/large_ground_truth.json
```

### Run Statistical Significance Testing (paired t-test / Wilcoxon)
```bash
python significance_testing.py logs/large_auth.csv logs/large_ground_truth.json
```

### Run Real-World Hybrid Evaluation (Step 20 — real SSH log + injected attacks)
```bash
python real_world_evaluation.py
```

---

## 📊 Evaluation Results

Results on the 104-IP labeled dataset (50 attacks across 7 patterns, 54 normal scenarios), using the default **5-minute window** and the **5-indicator formula (Step 17 — Success Ratio added)**:

| Model | TP | FP | TN | FN | Precision | Recall | F1-Score | FPR |
|---|---|---|---|---|---|---|---|---|
| **LHBDF (Proposed) ★** | **46** | **0** | 54 | 4 | 1.000 | 0.920 | **0.958** | 0.000 |
| Static Threshold | 20 | 0 | 54 | 30 | 1.000 | 0.400 | 0.571 | 0.000 |
| Time-Window Freq. | 18 | 5 | 49 | 32 | 0.783 | 0.360 | 0.493 | 0.093 |
| Username Diversity | 23 | 9 | 45 | 27 | 0.719 | 0.460 | 0.561 | 0.167 |
| Conventional Hybrid (equal-weight, 5 indicators) | 26 | 8 | 46 | 24 | 0.765 | 0.520 | 0.619 | 0.148 |

LHBDF still leads every baseline by a wide margin, but at a 5-minute window it **misses 4 attacks** — the deliberately included "low-and-slow" pattern (isolated failed logins spread ~3 hours apart across a full day). This is **expected and intentional**: those 4 attacks are structurally invisible to any 5-minute window by construction. See Multi-Window Detection below for the fix.

**Notable Step 17 result:** with Success Ratio now included, Conventional Hybrid's naive equal-weighting (0.20 × each of 5 indicators) **dropped sharply** from matching LHBDF (F1 = 0.958) down to F1 = 0.619. Diluting weight onto S_Score pulls weight away from the high-signal F and T indicators, causing several "stealthy brute-force" attacks (S_Score = 0, since they're pure-failure attacks) to fall just below the alert threshold under equal weighting. This is a genuine, important finding: **LHBDF's deliberately chosen differential weights are now clearly superior to naive equal-weighting**, once a 5th indicator is added — the earlier 4-indicator results (where LHBDF and Conventional Hybrid tied exactly) masked this because F/U/V/T alone happened to be robust to equal weighting on this dataset; adding S_Score is precisely what exposes the value of careful weight selection.

### Multi-Window Detection — Does Window Size Matter?

| Window Scale | Precision | Recall | F1-Score | FPR |
|---|---|---|---|---|
| 5-Min (Fast Brute-Force) | 1.000 | 0.920 | 0.958 | 0.000 |
| 1-Hour (Credential Stuffing) | 0.807 | 0.920 | 0.860 | 0.204 |
| 24-Hour (Low-and-Slow) | 0.820 | 1.000 | 0.901 | 0.204 |
| **Multi-Window (best-of-3) ★** | **0.820** | **1.000** | **0.901** | 0.204 |

Combining all three window scales raises Recall from 92.0% to **100%**, catching every attack including the low-and-slow pattern that a 5-minute window can never see by construction. **Honest tradeoff (revised under Step 17):** the FPR at longer windows rose from 0.074 (4-indicator formula) to 0.204 (5-indicator formula). We traced this directly: all 11 false positives are legitimate **Shared Kiosk** IPs, where 5–7 distinct users share a device and (correctly) produce mostly successful logins. At the 1-hour and 24-hour scales, this pattern now combines high Username Diversity *and* a high Success Ratio (S_Score ≈ 0.7–1.0, since almost every login legitimately succeeds) — a combination that closely resembles the stolen-credential attack signature S_Score was specifically designed to catch. This is a genuine and important limitation to document: **Success Ratio alone cannot distinguish "many people legitimately sharing a device" from "many stolen credentials being validated"** at longer time scales without an additional contextual signal (e.g., device fingerprinting or known-user allowlisting), which we flag as a concrete direction for future work.

### Ablation Study — Which Indicators Matter Most? (RQ4)

| Rank | Indicator Combination | F1-Score |
|---|---|---|
| 🥇 (tie) | LHBDF — Proposed Weights | **0.958** |
| 🥇 (tie) | Equal 4-Indicator, no S (legacy) | 0.958 |
| 6 | F only (Failed Login Frequency) | 0.889 |
| 15 | Equal Hybrid, 5 indicators (0.20 each) | 0.619 |
| 18 | S only (Success Ratio) | 0.150 |
| 20 | F + S (pairwise) | 0.000 |

No single indicator is sufficient on its own — **F alone misses every stolen-credential attack** (zero failures by design), dropping Recall to 0.800. **S alone performs poorly** (F1 = 0.150) because Success Ratio is high for both stolen-credential attacks *and* ordinary normal logins — it is only useful in combination with diversity/velocity signals, not standalone. Most strikingly, **F + S paired together score F1 = 0.000**: at 50/50 weight, brute-force attacks (high F, S≈0) and stolen-credential attacks (F≈0, high S) both average out to risk ≈ 0.5, just under the 0.60 alert threshold — demonstrating that F and S are *complementary opposites* that must be balanced against U/V/T, not relied on as a pair alone. LHBDF's full 5-indicator weighted combination matches the best possible 4-indicator equal-weight result (both F1 = 0.958), while clearly outperforming the naive 5-indicator equal-weight scheme (+0.339 F1) — directly demonstrating *why* careful weight allocation across all five indicators is necessary, not just convenient.

### Resource Consumption (Computational Overhead)

Measured on the 626-event, 104-IP dataset (5 batches, averaged):

| Metric | Value |
|---|---|
| Detection Latency | 13.09 ms (per-batch avg) |
| Throughput | 47,842 events/sec |
| CPU Utilization | 100.69% (single-threaded) |
| Peak RAM Usage | 15.36 MB |

This confirms the "lightweight" claim: the entire pipeline processes over 600 log entries in ~13 milliseconds using under 16 MB of RAM — no GPU, no cloud, no specialized hardware required. (The small latency increase versus the 4-indicator version reflects the additional S_Score computation per window; throughput remains far in excess of any realistic SMB authentication event rate.)

### Adaptive Thresholds — Median + 3×MAD Calibration vs. Fixed Constants

Step 19 replaces the earlier μ + 2σ method with **Median + 3×MAD** (Median Absolute Deviation) — a statistically more robust approach that requires no normality assumption and is unaffected by outliers in the baseline data (unlike the mean and standard deviation which are both sensitive to extreme values).

```
Threshold = median + 3 × MAD
where MAD = median of |x_i − median|
```

| Indicator | Median | MAD | Median+3×MAD | Fixed | Chosen (with floor) |
|---|---|---|---|---|---|
| Failed Login | 1.00 | 1.00 | 4.00 | 5 | **4.00** |
| Username Div. | 1.50 | 0.50 | 3.00 | 3 | **3.00** |
| Login Velocity | 3.00 | 0.00 | 3.00 | 10 | **5.00** (floor) |

**MAD = 0 for velocity:** The baseline velocity distribution has zero variance — every normal session in our dataset has exactly 3 login events. With MAD = 0, the formula collapses to the median (3.00), which would be too sensitive. The floor (5.0) prevents over-flagging while preserving the spirit of data-driven calibration.

| Mode | Precision | Recall | F1-Score | FPR |
|---|---|---|---|---|
| Fixed | 1.000 | 0.920 | **0.958** | 0.000 |
| Adaptive (Median+3×MAD) | 0.885 | 0.920 | 0.902 | 0.111 |

**Honest finding:** Median+3×MAD maintains identical Recall (0.920) but introduces 6 false positives (FPR 0.111). We traced all 6 to **Office NAT** normal IPs (3–5 employees sharing one IP, all successful logins): the tighter velocity threshold (5 vs. 10) raises V_Score from 0.30 to 0.60 for these IPs, and combined with their naturally high U_Score (multiple users) and S_Score (all successes), the composite score crosses the alert threshold. This is the same inherent indicator-level ambiguity documented in the multi-window section: "3 people successfully logging in from one IP" is behaviorally indistinguishable from "3 stolen credentials being validated" using only F, U, V, T, S. The Median+3×MAD method correctly tightens the velocity threshold based on actual baseline behavior — the false positives reflect a genuine limitation of the indicator set in shared-IP environments, not a flaw in the calibration method itself.

### ROC Curve & AUC

| Model | AUC | FPR (at default threshold) | TPR (at default threshold) |
|---|---|---|---|
| **LHBDF (Proposed)** | **0.930** | 0.000 | 0.920 |
| Conventional Hybrid (5-indicator equal-weight) | 0.820 | 0.148 | 0.520 |
| Static Threshold | — (binary, single point) | 0.000 | 0.400 |
| Time-Window Freq. | — (binary, single point) | 0.093 | 0.360 |
| Username Diversity | — (binary, single point) | 0.167 | 0.460 |

LHBDF clears AUC = 0.930, **clearly above** Conventional Hybrid's AUC = 0.820 and all three single-indicator baselines' fixed operating points. **This resolves the ambiguity noted in the original 4-indicator evaluation**, where LHBDF and Conventional Hybrid produced an identical AUC (0.930) and the README speculated that "a more adversarial dataset may be needed to show clearer separation between weighting strategies." Adding the 5th indicator (Success Ratio) turned out to be exactly that — it is the differential weighting (de-emphasizing S relative to F/U/V/T) that lets LHBDF avoid the false-positive-prone behavior the equal-weighted hybrid exhibits, producing a visibly and measurably better ROC curve.

### Statistical Significance Testing

A single evaluation run gives only one F1-score per model — there's no variance to run a paired test on directly. To test rigorously, we draw **1,000 bootstrap resamples** (with replacement) of the 104 labeled IPs and compute each model's F1-score on every resample using its already-known per-IP prediction, producing 1,000 paired (LHBDF, baseline) observations per comparison — a valid basis for a **paired t-test** and **Wilcoxon signed-rank test**.

| Comparison | Mean Δ F1 | 95% CI | t-test p-value | Wilcoxon p-value | Verdict |
|---|---|---|---|---|---|
| LHBDF vs. Static Threshold | +0.390 | [+0.265, +0.537] | p < 0.000001 | p < 0.000001 | **Significant** |
| LHBDF vs. Time-Window Freq. | +0.468 | [+0.338, +0.608] | p < 0.000001 | p < 0.000001 | **Significant** |
| LHBDF vs. Username Diversity | +0.404 | [+0.285, +0.541] | p < 0.000001 | p < 0.000001 | **Significant** |
| LHBDF vs. Conventional Hybrid | +0.343 | [+0.234, +0.464] | p < 0.000001 | p < 0.000001 | **Significant** |

LHBDF's improvement over **all four** baselines — including, now, Conventional Hybrid — is **statistically significant at α = 0.05** by both tests, with large effect sizes (+0.34 to +0.47 mean F1 difference). Under the earlier 4-indicator formula, LHBDF and Conventional Hybrid produced identical predictions on every IP, so no significance test applied to that comparison. Step 17's Success Ratio addition broke that tie decisively in LHBDF's favor.

### Real-World Hybrid Evaluation (Step 20)

All results above use a fully synthetic dataset. To address the "dataset realism" concern that any purely synthetic evaluation invites, this section evaluates LHBDF on a **hybrid dataset**: a genuine, published production SSH server's authentication log — [LogHub's `OpenSSH_2k.log`](https://github.com/logpai/loghub) (Zhu et al., *"Tools and Benchmarks for Automated Log Parsing,"* ICSE 2019) — with LHBDF's same 104 labeled attack/normal scenarios injected on top.

**Composition:**
- **Real background** — 518 genuine SSH events from 24 real attacking IPs (internet background scanning noise: invalid-user enumeration, password guessing, one genuine successful login), spanning ~4 real hours on Dec 10, 2014. These IPs are **unlabeled** — no official ground truth exists for them.
- **Injected (labeled)** — the same 104 IPs (50 attack / 54 normal) across all 7 attack patterns and 5 normal patterns used throughout this thesis, distributed across a full day surrounding the real incident. Injected IPs use the RFC 5737 documentation range (`203.0.113.0/24`), guaranteeing no collision with the real public IPs.

```bash
python real_world_evaluation.py
```

**Primary evaluation (strict, on the 104 labeled IPs only):**

| Model | Precision | Recall | F1-Score | FPR |
|---|---|---|---|---|
| **LHBDF (Proposed)** | 1.000 | 0.920 | **0.958** | 0.000 |
| Static Threshold | 1.000 | 0.400 | 0.571 | 0.000 |
| Time-Window Freq. | 0.773 | 0.340 | 0.472 | 0.093 |
| Username Diversity | 0.697 | 0.460 | 0.554 | 0.185 |
| Conventional Hybrid | 0.765 | 0.520 | 0.619 | 0.148 |

**LHBDF's F1-Score is essentially unchanged (0.958, identical to the pure-synthetic result)** despite 518 additional real, noisy background events mixed into the same log. AUC also holds at 0.930 (vs. 0.815 for Conventional Hybrid), and all four baseline comparisons remain statistically significant (p < 0.000001) via the same bootstrap paired t-test/Wilcoxon methodology. This demonstrates LHBDF's detection of the labeled scenarios is **not disrupted by realistic background traffic**.

**Qualitative check (supplementary — real attacking IPs have no official label):**

| Metric | Value |
|---|---|
| Real background IPs | 24 |
| Produced a scoreable feature window | 17 |
| Flagged HIGH/CRITICAL by LHBDF | 12 / 17 (**70.6%**) |

Since these real IPs were never officially labeled, this is *not* used for the primary Precision/Recall/F1 metrics above — but the raw log content makes their maliciousness obvious (e.g., one IP made 56 failed attempts across 9 usernames; another made 146 failed attempts against a single account). LHBDF independently flagged 70.6% of the ones with enough activity to score, with **attack-type classifications matching their actual observed behavior** (high-diversity IPs → CREDENTIAL_STUFFING; high-failure single-user IPs → BRUTE_FORCE) — despite never being tuned or trained on this real dataset. The remaining IPs that scored NORMAL had only 1–2 failed attempts, which is the same threshold at which a real legitimate user's typo would also sit — a conservative, defensible non-alert rather than a missed detection.

**A bug caught and fixed during this evaluation:** the ablation study and attack-classification accuracy modules originally iterated over *all* scored IPs (including the unlabeled real ones) and silently defaulted any IP missing from `ground_truth` to "normal." Since several real attacking IPs were correctly flagged by LHBDF, this caused them to be miscounted as false positives / classification errors — dropping the hybrid dataset's apparent ablation F1 to 0.860 and classification accuracy to 88.9%, even though the underlying detections were correct. Both modules were fixed to only score IPs present in `ground_truth` (matching the pattern already used correctly in `evaluator.py` and `multi_window.py`), restoring F1=0.958 and classification accuracy=100% — consistent with the primary evaluation. This is documented transparently rather than silently corrected, since it illustrates a real methodological trap when mixing labeled and unlabeled data in one evaluation.

---

## 📋 Log File Format

Your log file must be `.csv` or `.json` with these fields:

| Field | Required | Example |
|---|---|---|
| timestamp | ✅ | `2025-03-01 08:03:00` |
| ip_address | ✅ | `192.168.1.12` |
| username | ✅ | `carol` |
| login_outcome | ✅ | `failure` / `success` |
| request_source | ❌ | `web` / `api` |
| session_id | ❌ | `sess_001` |

---

## 🔬 Research Context

| Item | Detail |
|---|---|
| **Research Title** | A Novel Lightweight Hybrid Behavioral Detection Framework for Brute-Force and Credential Stuffing Attacks Using Authentication Log Data |
| **Type** | M.Sc. Cyber Security — Research Proposal |
| **University** | Daffodil International University |
| **Semester** | Spring 2025 |
| **Approach** | Rule-based (No ML) |
| **Target** | Resource-constrained SMB environments |

---

## 📄 License

MIT License — free to use for academic and research purposes.
