"""
HEAVEN — Synthetic Training Data Generator
Generates realistic training data for the risk model based on NVD/KEV/EPSS distributions.
"""

from __future__ import annotations

try:
    import numpy as np
except ImportError:
    np = None  # type: ignore[assignment]
from heaven.ml.feature_engine import FEATURE_NAMES


def generate_synthetic_dataset(n_samples: int = 5000, random_state: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic vulnerability data mimicking real-world distributions.
    Returns (X, y) where y=1 means "exploited in the wild".
    """
    rng = np.random.RandomState(random_state)
    n_features = len(FEATURE_NAMES)
    X = np.zeros((n_samples, n_features))

    # Generate features with realistic distributions
    idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

    # CVSS base (bimodal: many medium, some critical)
    X[:, idx["cvss_base_score"]] = np.clip(rng.beta(2, 3, n_samples) * 1.0, 0, 1)

    # Attack vector (mostly network)
    X[:, idx["attack_vector"]] = rng.choice([1.0, 0.75, 0.5, 0.25], n_samples, p=[0.6, 0.15, 0.2, 0.05])

    # Complexity (mostly low)
    X[:, idx["attack_complexity"]] = rng.choice([1.0, 0.5], n_samples, p=[0.7, 0.3])

    # Privileges (mixed)
    X[:, idx["privileges_required"]] = rng.choice([1.0, 0.66, 0.33], n_samples, p=[0.4, 0.35, 0.25])

    # User interaction
    X[:, idx["user_interaction"]] = rng.choice([1.0, 0.5], n_samples, p=[0.55, 0.45])

    # Scope
    X[:, idx["scope_changed"]] = rng.choice([0.0, 1.0], n_samples, p=[0.7, 0.3])

    # Impact scores
    for impact in ["conf_impact", "integ_impact", "avail_impact"]:
        X[:, idx[impact]] = rng.choice([0.0, 0.5, 1.0], n_samples, p=[0.2, 0.4, 0.4])

    # Exploit availability (20% have known exploits)
    X[:, idx["exploit_available"]] = rng.choice([0.0, 1.0], n_samples, p=[0.8, 0.2])

    # EPSS scores (long-tail distribution)
    X[:, idx["epss_score"]] = np.clip(rng.exponential(0.05, n_samples), 0, 1)

    # KEV (5% are in KEV)
    X[:, idx["in_kev"]] = rng.choice([0.0, 1.0], n_samples, p=[0.95, 0.05])

    # Vulnerability age
    X[:, idx["vuln_age_days"]] = rng.beta(2, 5, n_samples)

    # Asset exposure
    X[:, idx["asset_exposure"]] = rng.choice([1.0, 0.7, 0.3, 0.1], n_samples, p=[0.3, 0.2, 0.4, 0.1])

    # IAM privilege level
    X[:, idx["iam_privilege_level"]] = rng.choice([0.0, 0.25, 0.5, 0.75, 1.0], n_samples, p=[0.3, 0.25, 0.2, 0.15, 0.1])

    # Service criticality
    X[:, idx["service_criticality"]] = rng.beta(2, 3, n_samples)

    # Validation
    X[:, idx["has_validation"]] = rng.choice([0.0, 1.0], n_samples, p=[0.6, 0.4])
    X[:, idx["validation_confidence"]] = X[:, idx["has_validation"]] * rng.beta(3, 2, n_samples)

    # Chain potential
    X[:, idx["chain_potential"]] = rng.beta(1, 5, n_samples)

    # Honeypot (inverted)
    X[:, idx["honeypot_score_inv"]] = rng.choice([1.0, 0.5, 0.0], n_samples, p=[0.85, 0.1, 0.05])

    # Open ports
    X[:, idx["open_port_count"]] = rng.beta(1, 3, n_samples)

    # Banner quality
    X[:, idx["banner_info_quality"]] = rng.choice([0.0, 1.0], n_samples, p=[0.3, 0.7])

    # Generate labels using a realistic exploitation model
    # Higher probability if: high CVSS + exploit available + network accessible + low complexity
    logit = (
        2.0 * X[:, idx["cvss_base_score"]]
        + 3.0 * X[:, idx["exploit_available"]]
        + 5.0 * X[:, idx["in_kev"]]
        + 1.5 * X[:, idx["attack_vector"]]
        + 1.0 * X[:, idx["attack_complexity"]]
        + 1.0 * X[:, idx["asset_exposure"]]
        + 2.0 * X[:, idx["epss_score"]] * 10
        - 1.0 * X[:, idx["privileges_required"]]
        + 0.5 * X[:, idx["chain_potential"]]
        - 3.0  # bias
    )

    prob = 1 / (1 + np.exp(-logit))
    y = (rng.random(n_samples) < prob).astype(int)

    # Ensure ~15-25% positive rate
    positive_rate = np.mean(y)
    if positive_rate < 0.1 or positive_rate > 0.35:
        # Adjust bias and regenerate labels
        target_rate = 0.20
        bias_adjustment = np.log(target_rate / (1 - target_rate)) - np.log(positive_rate / max(1 - positive_rate, 1e-9))
        adjusted_logit = logit + bias_adjustment
        prob = 1 / (1 + np.exp(-adjusted_logit))
        y = (rng.random(n_samples) < prob).astype(int)

    return X, y
