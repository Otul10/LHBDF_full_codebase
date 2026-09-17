"""
LHBDF - Adaptive Threshold Calibration
-------------------------------------------
Step 19: Replaces μ + 2σ with Median + 3 × MAD (Median Absolute
Deviation) for computing per-indicator detection thresholds.

    Threshold = median + 3 × MAD

where:
    median  = 50th percentile of baseline indicator values
    MAD     = median of |x_i - median| across all baseline values
    3       = the multiplier (analogous to the "2" in μ + 2σ)

WHY MEDIAN + 3×MAD IS BETTER THAN μ + 2σ:
  1. No normality assumption -- authentication event counts are rarely
     Gaussian; they tend to be right-skewed (most sessions have few
     events, rare heavy sessions inflate the mean).
  2. Robust to outliers -- a single unusually large baseline session
     inflates μ and σ, pulling the threshold up and potentially hiding
     real attacks. The median is completely unaffected by outliers.
  3. MAD is also robust -- it measures spread via the median (not mean)
     of absolute deviations, so extreme baseline windows don't distort
     the threshold as they do with σ.
  4. Still fully rule-based and non-ML -- just more statistically
     sound descriptive statistics.

EDGE CASE -- Zero MAD:
  When all baseline windows have the same count (MAD = 0, e.g.
  every normal session has exactly 3 login events), the formula
  collapses to just the median. A floor prevents the threshold from
  becoming too sensitive in such low-variance environments. Each
  indicator has a conservatively chosen floor that reflects the minimum
  number of events that should be considered normal before flagging:
    MIN_THRESHOLD_FAILED   = 3   (fewer than 3 failures is always normal)
    MIN_THRESHOLD_UNIQUE   = 2   (fewer than 2 unique users is normal)
    MIN_THRESHOLD_VELOCITY = 5   (fewer than 5 total events is normal)
"""

import math
from modules.feature_extractor import extract_features as _extract_raw, WINDOW_MINUTES

# Conservative floors -- prevent over-flagging when baseline variance is tiny
MIN_THRESHOLD_FAILED   = 3.0
MIN_THRESHOLD_UNIQUE   = 2.0
MIN_THRESHOLD_VELOCITY = 5.0   # raised from 3.0 to avoid velocity floor collapse

K = 3.0   # the "3" in "median + 3 × MAD"


def calibrate_thresholds(baseline_entries: list[dict],
                          window_minutes: int = WINDOW_MINUTES) -> dict:
    """
    Computes adaptive thresholds from a baseline of presumed-normal
    log entries using Median + 3×MAD (Step 19).

    Returns a dict with the 3 adaptive thresholds plus underlying
    statistics (for transparency/reporting).
    """
    features = _extract_raw(baseline_entries, window_minutes=window_minutes)

    failed_vals   = [f["failed_attempts"] for f in features]
    unique_vals   = [f["unique_users"]    for f in features]
    velocity_vals = [f["total_attempts"]  for f in features]

    failed_thresh   = _median_plus_k_mad(failed_vals,   MIN_THRESHOLD_FAILED)
    unique_thresh   = _median_plus_k_mad(unique_vals,   MIN_THRESHOLD_UNIQUE)
    velocity_thresh = _median_plus_k_mad(velocity_vals, MIN_THRESHOLD_VELOCITY)

    return {
        "threshold_failed":   failed_thresh,
        "threshold_unique":   unique_thresh,
        "threshold_velocity": velocity_thresh,
        "method":             "Median + 3×MAD",
        "stats": {
            "failed":   _describe(failed_vals),
            "unique":   _describe(unique_vals),
            "velocity": _describe(velocity_vals),
        },
        "baseline_windows": len(features),
    }


def _median_plus_k_mad(values: list[float], floor: float) -> float:
    """Compute median + K × MAD, bounded below by floor."""
    if not values:
        return floor
    n = len(values)
    sorted_v = sorted(values)
    # Median
    mid = n // 2
    median = sorted_v[mid] if n % 2 else (sorted_v[mid - 1] + sorted_v[mid]) / 2.0
    # MAD = median of |x_i - median|
    abs_devs = sorted([abs(v - median) for v in sorted_v])
    mad = abs_devs[mid] if n % 2 else (abs_devs[mid - 1] + abs_devs[mid]) / 2.0
    threshold = median + K * mad
    return round(max(threshold, floor), 2)


def _describe(values: list[float]) -> dict:
    """Extended stats: mean, std (for comparison), median, MAD, n, min, max."""
    if not values:
        return {"mean": 0.0, "std": 0.0, "median": 0.0, "mad": 0.0, "n": 0,
                "min": 0, "max": 0}
    n = len(values)
    sorted_v = sorted(values)
    mu    = sum(values) / n
    sigma = math.sqrt(sum((v - mu) ** 2 for v in values) / (n - 1)) if n >= 2 else 0.0
    mid   = n // 2
    median = sorted_v[mid] if n % 2 else (sorted_v[mid - 1] + sorted_v[mid]) / 2.0
    abs_devs = sorted([abs(v - median) for v in sorted_v])
    mad  = abs_devs[mid] if n % 2 else (abs_devs[mid - 1] + abs_devs[mid]) / 2.0
    return {
        "mean":   round(mu, 3),
        "std":    round(sigma, 3),
        "median": round(median, 3),
        "mad":    round(mad, 3),
        "n":      n,
        "min":    min(values),
        "max":    max(values),
    }


def extract_features_adaptive(entries: list[dict], thresholds: dict,
                               window_minutes: int = WINDOW_MINUTES) -> list[dict]:
    """Convenience wrapper: run extract_features with calibrated adaptive thresholds."""
    return _extract_raw(
        entries,
        window_minutes=window_minutes,
        threshold_failed=thresholds["threshold_failed"],
        threshold_unique=thresholds["threshold_unique"],
        threshold_velocity=thresholds["threshold_velocity"],
    )
