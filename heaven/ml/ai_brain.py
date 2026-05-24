"""
HEAVEN — AI Decision Engine (The Autonomous Brain)
Decision-layer heuristics + classical statistics that drive scan ordering,
payload selection, and confidence calibration:

- Bayesian target prioritisation with UCB explore/exploit (BayesianPrioritiser)
- Isotonic-style confidence calibration with multi-source corroboration
  (ConfidenceCalibrator)
- Payload selector with effectiveness priors per tech stack
  (SmartPayloadSelector)
- Multi-armed-bandit scan strategy that adapts from observed rewards
  (ScanStrategyOptimizer)

The numeric priors (service vuln rates, payload effectiveness, calibration
curve, etc.) are loaded from `data/models/priors_bootstrap.json` at import
time. The shipped file is hand-curated bootstrap data, not trained from
scans — replace it with the output of `heaven train-priors` once you have
enough engagement history (see `data/models/priors_bootstrap.json` for the
schema). If the file is missing or invalid, the in-code _DEFAULTS fall back
in so the engine never crashes on a fresh install.
"""

from __future__ import annotations

import json
import math
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("ai.brain")


# ═══════════════════════════════════════════
# PRIORS LOADER
# Loads the bootstrap priors from disk; falls back to in-code defaults
# (which are kept in sync with the shipped JSON file) on any error.
# ═══════════════════════════════════════════

_PRIORS_LEARNED_PATH = Path(__file__).resolve().parents[2] / "data" / "models" / "priors_learned.json"
_PRIORS_BOOTSTRAP_PATH = Path(__file__).resolve().parents[2] / "data" / "models" / "priors_bootstrap.json"

_PRIORS_DEFAULTS: dict[str, Any] = {
    "service_priors": {
        "http": 0.7, "https": 0.65, "ssh": 0.3, "ftp": 0.6,
        "smb": 0.55, "rdp": 0.4, "mysql": 0.5, "postgres": 0.45,
        "redis": 0.7, "mongodb": 0.65, "elasticsearch": 0.6,
        "telnet": 0.8, "vnc": 0.5, "ldap": 0.4, "snmp": 0.6,
        "smtp": 0.35, "dns": 0.25, "nfs": 0.5, "docker": 0.7,
        "kubernetes": 0.6, "jenkins": 0.75, "grafana": 0.5,
    },
    "value_weights": {
        "database": 3.0, "admin_panel": 2.5, "api": 2.0,
        "file_server": 1.5, "mail": 1.3, "dns": 1.0,
        "web": 1.8, "auth": 2.2, "cicd": 2.8,
    },
    "calibration_curve": [
        [0.0, 0.02], [0.1, 0.04], [0.2, 0.08], [0.3, 0.15],
        [0.4, 0.25], [0.5, 0.40], [0.6, 0.58], [0.7, 0.72],
        [0.8, 0.85], [0.9, 0.94], [1.0, 0.99],
    ],
    "source_weights": {
        "validated_poc": 1.0, "time_based_blind": 0.85,
        "boolean_inference": 0.80, "error_based": 0.88,
        "banner_version": 0.70, "heuristic": 0.50,
        "fuzzing_anomaly": 0.40, "default_cred": 0.95,
    },
    "effectiveness_matrix": {
        "php":    {"sqli_union": 0.8, "sqli_boolean": 0.7, "ssti_twig": 0.6, "lfi": 0.9, "rce_system": 0.5},
        "python": {"ssti_jinja2": 0.8, "sqli_boolean": 0.6, "cmdi_subprocess": 0.5, "pickle_deser": 0.4},
        "java":   {"ssti_spring": 0.5, "deser_java": 0.6, "xxe": 0.7, "log4shell": 0.3, "sqli_prepared": 0.4},
        "node":   {"prototype_pollution": 0.5, "ssti_pug": 0.4, "nosql_injection": 0.7, "ssrf": 0.6},
        "asp.net":{"sqli_mssql": 0.6, "deser_viewstate": 0.5, "path_traversal": 0.5, "xxe": 0.4},
        "ruby":   {"ssti_erb": 0.6, "deser_marshal": 0.5, "cmdi": 0.5, "sqli_activerecord": 0.4},
    },
    "waf_bypass_priority": {
        "cloudflare":  ["unicode_normalize", "chunked_encoding", "case_alternation"],
        "aws_waf":     ["double_url_encode", "json_content_type", "unicode_normalize"],
        "modsecurity": ["comment_injection", "null_byte", "case_alternation"],
        "imperva":     ["whitespace_manipulation", "unicode_normalize", "comment_injection"],
    },
}


def _load_priors() -> dict[str, Any]:
    """Load priors from disk with preference: learned > bootstrap > in-code defaults.

    `priors_learned.json` is produced by `heaven train-priors` and contains
    empirical service vuln rates derived from past engagement data.
    `priors_bootstrap.json` is the hand-curated starter file. If neither
    is on disk (or both are corrupt), fall back to the in-code defaults
    so the engine never crashes.
    """
    for path, label in (
        (_PRIORS_LEARNED_PATH, "learned"),
        (_PRIORS_BOOTSTRAP_PATH, "bootstrap"),
    ):
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            merged = {**_PRIORS_DEFAULTS}
            for key in _PRIORS_DEFAULTS:
                if key in data:
                    merged[key] = data[key]
            merged["calibration_curve"] = [tuple(p) for p in merged["calibration_curve"]]
            if label == "learned":
                prov = data.get("_provenance", {})
                logger.info(
                    f"loaded learned priors (n_engagements={prov.get('engagement_count', '?')}, "
                    f"n_findings={prov.get('finding_count', '?')})"
                )
            else:
                logger.info(f"loaded bootstrap priors from {path}")
            return merged
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"priors file at {path} is invalid ({e}) — trying next")

    logger.info("no priors file on disk — using in-code bootstrap defaults")
    return _PRIORS_DEFAULTS


_PRIORS = _load_priors()


# ═══════════════════════════════════════════
# BAYESIAN TARGET PRIORITISER
# ═══════════════════════════════════════════

@dataclass
class TargetBelief:
    """Bayesian belief state about a target's exploitability."""
    host: str
    prior_vuln_prob: float = 0.5        # Prior belief it's vulnerable
    posterior_vuln_prob: float = 0.5     # Updated belief after evidence
    evidence_count: int = 0
    open_ports: int = 0
    banner_richness: float = 0.0        # How much info banners reveal
    response_anomalies: int = 0
    honeypot_prob: float = 0.0
    value_score: float = 0.5            # Expected value of attacking
    exploration_bonus: float = 1.0      # UCB exploration term

    @property
    def ucb_score(self) -> float:
        """Upper Confidence Bound score for explore/exploit balance."""
        exploitation = self.posterior_vuln_prob * self.value_score
        exploration = self.exploration_bonus / math.sqrt(1 + self.evidence_count)
        return exploitation + 0.5 * exploration


class BayesianPrioritiser:
    """
    Decides WHICH target to attack next using Bayesian inference.
    Updates beliefs as scan data comes in — like a pentester's intuition.
    """

    # Prior P(vulnerable | service). Loaded from data/models/priors_bootstrap.json
    # so it can be retrained without code changes. Shipped defaults are
    # hand-curated, not learned — see module docstring.
    SERVICE_PRIORS = _PRIORS["service_priors"]

    # Value multiplier per service category (impact if compromised).
    VALUE_WEIGHTS = _PRIORS["value_weights"]

    def __init__(self):
        self.beliefs: dict[str, TargetBelief] = {}
        self._history: list[dict] = []

    def initialise_beliefs(self, scan_results: dict) -> None:
        """Set initial priors from reconnaissance data."""
        for host_data in scan_results.get("hosts", []):
            host = host_data.get("host", "")
            ports = host_data.get("open_ports", [])

            # Calculate prior from service types
            service_priors = []
            for port in ports:
                service = port.get("service", "").lower()
                for svc_name, prior in self.SERVICE_PRIORS.items():
                    if svc_name in service:
                        service_priors.append(prior)
                        break

            prior = max(service_priors) if service_priors else 0.3
            banner_richness = sum(1 for p in ports if p.get("banner")) / max(len(ports), 1)

            # Estimate target value
            value = 1.0
            for port in ports:
                svc = port.get("service", "").lower()
                if any(db in svc for db in ["mysql", "postgres", "mongo", "redis"]):
                    value = max(value, self.VALUE_WEIGHTS["database"])
                elif any(a in svc for a in ["jenkins", "gitlab", "argocd"]):
                    value = max(value, self.VALUE_WEIGHTS["cicd"])
                elif "http" in svc:
                    value = max(value, self.VALUE_WEIGHTS["web"])

            self.beliefs[host] = TargetBelief(
                host=host, prior_vuln_prob=prior, posterior_vuln_prob=prior,
                open_ports=len(ports), banner_richness=banner_richness,
                value_score=min(value / 3.0, 1.0),
                honeypot_prob=host_data.get("honeypot_score", 0),
            )

        logger.info(f"Bayesian beliefs initialised for {len(self.beliefs)} targets")

    def update_belief(self, host: str, evidence: str, positive: bool) -> None:
        """Bayesian update after observing new evidence about a target."""
        if host not in self.beliefs:
            return

        belief = self.beliefs[host]

        # Likelihood ratios for different evidence types
        likelihood_ratios = {
            "open_port_found":      (1.3, 0.9),    # (P(evidence|vuln), P(evidence|safe))
            "banner_leaked":        (1.5, 0.7),
            "default_creds":        (3.0, 0.1),
            "sqli_detected":        (5.0, 0.05),
            "xss_detected":         (4.0, 0.1),
            "ssrf_detected":        (5.0, 0.05),
            "outdated_version":     (2.0, 0.5),
            "security_header_miss": (1.8, 0.6),
            "waf_detected":         (0.7, 1.5),    # WAF makes exploitation harder
            "honeypot_indicator":   (0.1, 2.0),    # Strong negative signal
            "vuln_confirmed":       (10.0, 0.01),
            "error_page_verbose":   (2.5, 0.3),
            "git_exposed":          (4.0, 0.1),
            "debug_mode":           (5.0, 0.05),
        }

        if evidence in likelihood_ratios:
            p_e_vuln, p_e_safe = likelihood_ratios[evidence]
            if not positive:
                p_e_vuln, p_e_safe = p_e_safe, p_e_vuln

            # Bayes theorem
            prior = belief.posterior_vuln_prob
            numerator = p_e_vuln * prior
            denominator = numerator + p_e_safe * (1 - prior)
            belief.posterior_vuln_prob = min(max(numerator / denominator, 0.01), 0.99)

        belief.evidence_count += 1
        self._history.append({
            "host": host, "evidence": evidence, "positive": positive,
            "posterior": belief.posterior_vuln_prob, "time": time.time(),
        })

    def get_next_targets(self, n: int = 5) -> list[TargetBelief]:
        """Get the top-N targets to attack next (explore/exploit balanced)."""
        candidates = [
            b for b in self.beliefs.values()
            if b.honeypot_prob < 0.5  # Skip likely honeypots
        ]
        return sorted(candidates, key=lambda b: b.ucb_score, reverse=True)[:n]

    def save_beliefs(self, path: Path) -> None:
        """Persist beliefs to JSON so future scans start with prior knowledge."""
        import json
        from dataclasses import asdict
        from pathlib import Path as _Path
        _Path(path).write_text(
            json.dumps({h: asdict(b) for h, b in self.beliefs.items()}, indent=2),
            encoding="utf-8",
        )

    def load_beliefs(self, path: Path) -> None:
        """Load persisted beliefs. Unknown fields are silently ignored."""
        import json
        from pathlib import Path as _Path
        p = _Path(path)
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            import dataclasses
            valid_fields = {f.name for f in dataclasses.fields(TargetBelief)}
            for host, vals in data.items():
                filtered = {k: v for k, v in vals.items() if k in valid_fields}
                self.beliefs[host] = TargetBelief(**filtered)
        except Exception:
            pass  # Corrupt persistence file — start fresh

    def summary(self) -> dict:
        top = self.get_next_targets(10)
        return {
            "total_targets": len(self.beliefs),
            "avg_vuln_probability": round(
                sum(b.posterior_vuln_prob for b in self.beliefs.values()) / max(len(self.beliefs), 1), 3
            ),
            "top_targets": [
                {"host": t.host, "vuln_prob": round(t.posterior_vuln_prob, 3),
                 "ucb": round(t.ucb_score, 3), "evidence": t.evidence_count}
                for t in top
            ],
            "total_evidence": sum(b.evidence_count for b in self.beliefs.values()),
        }


# ═══════════════════════════════════════════
# CONFIDENCE CALIBRATOR
# ═══════════════════════════════════════════

class ConfidenceCalibrator:
    """
    Calibrates raw scanner confidence scores into probability estimates.
    Uses piecewise-linear interpolation over a calibration curve, then
    boosts on independent-source corroboration.

    The curve and per-source weights are loaded from
    `data/models/priors_bootstrap.json`. The shipped values are hand-curated
    bootstrap data; the real calibration curve will be fit from labeled
    historical findings once `heaven train-priors` is implemented.
    """

    CALIBRATION_CURVE = _PRIORS["calibration_curve"]
    SOURCE_WEIGHTS = _PRIORS["source_weights"]

    @classmethod
    def calibrate(cls, raw_confidence: float, source: str = "heuristic",
                   corroborating_sources: int = 0) -> float:
        """
        Calibrate a raw confidence score to a true probability.
        Multi-source corroboration increases confidence.
        """
        # Apply source reliability weight
        source_weight = cls.SOURCE_WEIGHTS.get(source, 0.5)
        weighted = raw_confidence * source_weight

        # Apply calibration curve (linear interpolation)
        calibrated = cls._interpolate(weighted)

        # Corroboration boost (independent sources multiply confidence)
        if corroborating_sources > 0:
            # Each independent source reduces false positive rate by ~50%
            fp_rate = 1 - calibrated
            for _ in range(corroborating_sources):
                fp_rate *= 0.5
            calibrated = 1 - fp_rate

        return round(min(calibrated, 0.999), 4)

    @classmethod
    def _interpolate(cls, x: float) -> float:
        """Linear interpolation on calibration curve."""
        x = max(0, min(1, x))
        for i in range(len(cls.CALIBRATION_CURVE) - 1):
            x0, y0 = cls.CALIBRATION_CURVE[i]
            x1, y1 = cls.CALIBRATION_CURVE[i + 1]
            if x0 <= x <= x1:
                t = (x - x0) / (x1 - x0) if x1 != x0 else 0
                return y0 + t * (y1 - y0)
        return cls.CALIBRATION_CURVE[-1][1]

    @classmethod
    def calculate_accuracy_metrics(cls, findings: list[dict]) -> dict:
        """Calculate precision, recall, and accuracy from findings."""
        if not findings:
            return {"precision": 0, "recall": 0, "accuracy": 0, "f1": 0}

        tp = sum(1 for f in findings if f.get("validated") and f.get("confidence", 0) >= 0.7)
        fp = sum(1 for f in findings if not f.get("validated") and f.get("confidence", 0) >= 0.7)
        fn = sum(1 for f in findings if f.get("validated") and f.get("confidence", 0) < 0.7)
        tn = sum(1 for f in findings if not f.get("validated") and f.get("confidence", 0) < 0.7)

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-6)

        return {
            "precision": round(precision, 4), "recall": round(recall, 4),
            "accuracy": round(accuracy, 4), "f1": round(f1, 4),
            "true_positives": tp, "false_positives": fp,
            "false_negatives": fn, "true_negatives": tn,
        }


# ═══════════════════════════════════════════
# SMART PAYLOAD SELECTOR
# ═══════════════════════════════════════════

class SmartPayloadSelector:
    """
    AI-driven payload selection based on target profile.
    Instead of trying all payloads blindly, selects the most likely
    to succeed based on technology stack, WAF, and past results.
    """

    # Payload effectiveness priors: tech → payload_type → estimated success rate.
    # Loaded from data/models/priors_bootstrap.json so it can be retrained.
    EFFECTIVENESS_MATRIX = _PRIORS["effectiveness_matrix"]
    WAF_BYPASS_PRIORITY = _PRIORS["waf_bypass_priority"]

    @classmethod
    def select_payloads(cls, tech_stack: list[str], waf: str = "",
                         budget: int = 10) -> list[dict]:
        """
        Select the optimal set of payloads for maximum coverage with minimum requests.
        Like a pentester choosing their top 10 shots instead of spraying blindly.
        """
        candidates = []

        for tech in tech_stack:
            tech_lower = tech.lower()
            for lang, payloads in cls.EFFECTIVENESS_MATRIX.items():
                if lang in tech_lower or tech_lower in lang:
                    for payload_type, success_rate in payloads.items():
                        candidates.append({
                            "payload_type": payload_type,
                            "success_rate": success_rate,
                            "target_tech": lang,
                            "bypass_techniques": cls.WAF_BYPASS_PRIORITY.get(waf, []),
                        })

        # Sort by expected success rate and take top N
        def _success_rate(candidate: dict[str, object]) -> float:
            value = candidate.get("success_rate", 0.0)
            if isinstance(value, (int, float)):
                return float(value)
            return 0.0

        candidates.sort(key=_success_rate, reverse=True)
        selected = candidates[:budget]

        if not selected:
            # Fallback: universal payloads that work across all stacks
            selected = [
                {"payload_type": "sqli_boolean", "success_rate": 0.5, "target_tech": "universal"},
                {"payload_type": "xss_reflected", "success_rate": 0.5, "target_tech": "universal"},
                {"payload_type": "ssrf_metadata", "success_rate": 0.4, "target_tech": "universal"},
                {"payload_type": "path_traversal", "success_rate": 0.4, "target_tech": "universal"},
                {"payload_type": "cors_misconfig", "success_rate": 0.6, "target_tech": "universal"},
            ]

        if selected:
            logger.info(f"AI selected {len(selected)} payloads (top hit rate: "
                         f"{selected[0]['success_rate']:.0%})")
        return selected


# ═══════════════════════════════════════════
# SCAN STRATEGY OPTIMIZER
# ═══════════════════════════════════════════

class ScanStrategyOptimizer:
    """
    Reinforcement-learning-inspired scan strategy that adapts in real-time.
    Tracks which scan actions produce results and shifts focus accordingly.
    """

    def __init__(self):
        # Multi-armed bandit state for each scan action
        self.arms = {
            "port_scan": {"tries": 0, "successes": 0, "reward": 0.0},
            "web_crawl": {"tries": 0, "successes": 0, "reward": 0.0},
            "subdomain_enum": {"tries": 0, "successes": 0, "reward": 0.0},
            "js_analysis": {"tries": 0, "successes": 0, "reward": 0.0},
            "endpoint_fuzz": {"tries": 0, "successes": 0, "reward": 0.0},
            "sqli_test": {"tries": 0, "successes": 0, "reward": 0.0},
            "xss_test": {"tries": 0, "successes": 0, "reward": 0.0},
            "ssrf_test": {"tries": 0, "successes": 0, "reward": 0.0},
            "auth_test": {"tries": 0, "successes": 0, "reward": 0.0},
            "fuzzing": {"tries": 0, "successes": 0, "reward": 0.0},
        }
        self.total_tries = 0

    def select_action(self, epsilon: float = 0.1) -> str:
        """Select next scan action using epsilon-greedy strategy.

        Reads from the project-wide seedable RNG so scans become
        deterministic when HEAVEN_SEED is set (heaven scan --seed N).
        """
        from heaven.utils.seeding import get_random
        rng = get_random()
        self.total_tries += 1

        # Explore with probability epsilon
        if rng.random() < epsilon:
            return rng.choice(list(self.arms.keys()))

        # Exploit: choose action with highest average reward
        best_action = max(
            self.arms.keys(),
            key=lambda a: (self.arms[a]["reward"] / max(self.arms[a]["tries"], 1))
                          + math.sqrt(2 * math.log(max(self.total_tries, 1)) / max(self.arms[a]["tries"], 1))
        )
        return best_action

    def record_result(self, action: str, success: bool, reward: float = 1.0) -> None:
        """Record the result of a scan action."""
        if action in self.arms:
            self.arms[action]["tries"] += 1
            if success:
                self.arms[action]["successes"] += 1
            self.arms[action]["reward"] += reward if success else -0.1

    def get_strategy_report(self) -> dict:
        """Get current strategy effectiveness."""
        return {
            action: {
                "tries": data["tries"],
                "success_rate": round(data["successes"] / max(data["tries"], 1), 3),
                "avg_reward": round(data["reward"] / max(data["tries"], 1), 3),
            }
            for action, data in self.arms.items()
            if data["tries"] > 0
        }
