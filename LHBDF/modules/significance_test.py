"""
LHBDF - Statistical Significance Testing
---------------------------------------------
Tests whether LHBDF's F1-score improvement over each baseline model
is statistically significant, using a paired t-test and Wilcoxon
signed-rank test.

WHY BOOTSTRAP RESAMPLING IS NECESSARY:
A single evaluation run gives exactly ONE F1-score per model -- you
cannot run a paired test on two single numbers (there is no variance
to test). To get a valid paired sample, we draw B bootstrap resamples
(with replacement) of the labeled IPs, and on EACH resample compute
the F1-score of every model using its already-known, deterministic
per-IP prediction. This produces B paired (LHBDF_F1, baseline_F1)
observations -- one pair per resample -- which is what the paired
t-test and Wilcoxon signed-rank test actually require.

This is standard practice for significance testing when only one
fixed test set is available (no natural k-fold/repeated-trial
structure exists for a rule-based, non-trained classifier).
"""

import random
from scipy.stats import ttest_rel, wilcoxon


def bootstrap_f1_distributions(predictions: dict, ground_truth: dict,
                                n_bootstrap: int = 1000, seed: int = 42) -> dict:
    """
    predictions: {model_name: {ip: 0|1}}  -- precomputed binary predictions
    ground_truth: {ip: 0|1}

    Returns: {model_name: [f1_resample_1, f1_resample_2, ...]}  (length n_bootstrap)
    """
    rng = random.Random(seed)
    all_ips = list(ground_truth.keys())
    n = len(all_ips)

    distributions = {model: [] for model in predictions}

    for _ in range(n_bootstrap):
        sample_ips = [all_ips[rng.randrange(n)] for _ in range(n)]
        for model, preds in predictions.items():
            f1 = _f1_on_sample(sample_ips, preds, ground_truth)
            distributions[model].append(f1)

    return distributions


def _f1_on_sample(sample_ips: list, preds: dict, ground_truth: dict) -> float:
    tp = fp = fn = 0
    for ip in sample_ips:
        p = preds.get(ip, 0)
        g = ground_truth[ip]
        if p == 1 and g == 1: tp += 1
        elif p == 1 and g == 0: fp += 1
        elif p == 0 and g == 1: fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def run_significance_tests(distributions: dict, reference_model: str, alpha: float = 0.05) -> dict:
    """
    Compares `reference_model` (LHBDF) against every other model in
    `distributions` using a paired t-test and Wilcoxon signed-rank test
    on the bootstrap F1 distributions.
    """
    ref_dist = distributions[reference_model]
    results = {}

    for model, dist in distributions.items():
        if model == reference_model:
            continue

        diffs = [a - b for a, b in zip(ref_dist, dist)]
        mean_diff = sum(diffs) / len(diffs)

        result = {
            "mean_f1_reference": round(sum(ref_dist) / len(ref_dist), 4),
            "mean_f1_other":     round(sum(dist) / len(dist), 4),
            "mean_diff":         round(mean_diff, 4),
            "ci_95":             _bootstrap_ci(diffs),
        }

        # Paired t-test
        if all(d == 0 for d in diffs):
            result["t_stat"] = 0.0
            result["t_pvalue"] = 1.0
            result["t_note"] = "All paired differences are zero (identical predictions)."
        else:
            t_stat, t_p = ttest_rel(ref_dist, dist)
            result["t_stat"] = round(float(t_stat), 4)
            result["t_pvalue"] = float(t_p)
            result["t_note"] = None

        # Wilcoxon signed-rank test
        try:
            if all(d == 0 for d in diffs):
                raise ValueError("zero differences")
            w_stat, w_p = wilcoxon(ref_dist, dist)
            result["w_stat"] = round(float(w_stat), 4)
            result["w_pvalue"] = float(w_p)
            result["w_note"] = None
        except ValueError:
            result["w_stat"] = None
            result["w_pvalue"] = 1.0
            result["w_note"] = "All paired differences are zero (identical predictions) -- Wilcoxon undefined."

        result["significant_t"] = result["t_pvalue"] < alpha
        result["significant_w"] = result["w_pvalue"] < alpha
        results[model] = result

    return results


def _bootstrap_ci(diffs: list, confidence: float = 0.95) -> tuple:
    """Percentile-based 95% CI directly from the bootstrap difference distribution."""
    sorted_diffs = sorted(diffs)
    n = len(sorted_diffs)
    lower_idx = int((1 - confidence) / 2 * n)
    upper_idx = int((1 - (1 - confidence) / 2) * n) - 1
    upper_idx = min(upper_idx, n - 1)
    return (round(sorted_diffs[lower_idx], 4), round(sorted_diffs[upper_idx], 4))
