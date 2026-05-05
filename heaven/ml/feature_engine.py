"""
HEAVEN — ML Feature Engineering
Constructs feature vectors from scan data for the risk prediction model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    import numpy as np
except ImportError:
    np = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("ml.features")

# Feature column definitions
FEATURE_NAMES = [
    "cvss_base_score", "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope_changed", "conf_impact", "integ_impact", "avail_impact",
    "exploit_available", "epss_score", "in_kev", "vuln_age_days",
    "asset_exposure", "iam_privilege_level", "service_criticality",
    "has_validation", "validation_confidence", "chain_potential",
    "honeypot_score_inv", "open_port_count", "banner_info_quality",
]

ATTACK_VECTOR_MAP = {"NETWORK": 1.0, "ADJACENT_NETWORK": 0.75, "LOCAL": 0.5, "PHYSICAL": 0.25}
COMPLEXITY_MAP = {"LOW": 1.0, "HIGH": 0.5}
PRIVILEGES_MAP = {"NONE": 1.0, "LOW": 0.66, "HIGH": 0.33}
EXPOSURE_MAP = {"external": 1.0, "dmz": 0.7, "internal": 0.3, "isolated": 0.1}


@dataclass
class VulnFeatures:
    """Feature vector for a single vulnerability."""
    vuln_id: str
    features: dict[str, float]
    raw_data: dict[str, Any]

    def to_array(self) -> np.ndarray:
        return np.array([self.features.get(f, 0.0) for f in FEATURE_NAMES])


def parse_cvss_vector(vector: str) -> dict[str, float]:
    """Parse CVSS v3.1 vector string into numeric features."""
    features = {
        "attack_vector": 0.5, "attack_complexity": 0.5, "privileges_required": 0.5,
        "user_interaction": 0.5, "scope_changed": 0.0,
        "conf_impact": 0.5, "integ_impact": 0.5, "avail_impact": 0.5,
    }
    if not vector:
        return features

    impact_map = {"HIGH": 1.0, "LOW": 0.5, "NONE": 0.0}
    ui_map = {"NONE": 1.0, "REQUIRED": 0.5}

    for component in vector.split("/"):
        if ":" not in component:
            continue
        key, val = component.split(":", 1)
        if key == "AV":
            features["attack_vector"] = ATTACK_VECTOR_MAP.get(val, 0.5)
        elif key == "AC":
            features["attack_complexity"] = COMPLEXITY_MAP.get(val, 0.5)
        elif key == "PR":
            features["privileges_required"] = PRIVILEGES_MAP.get(val, 0.5)
        elif key == "UI":
            features["user_interaction"] = ui_map.get(val, 0.5)
        elif key == "S":
            features["scope_changed"] = 1.0 if val == "CHANGED" else 0.0
        elif key == "C":
            features["conf_impact"] = impact_map.get(val, 0.5)
        elif key == "I":
            features["integ_impact"] = impact_map.get(val, 0.5)
        elif key == "A":
            features["avail_impact"] = impact_map.get(val, 0.5)

    return features


_SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.0, "high": 7.5, "medium": 5.5, "low": 3.5, "info": 1.0,
}

_VULN_TYPE_CVSS: dict[str, float] = {
    "docker_socket_exposed": 9.8, "rce": 9.8, "command_injection": 9.8,
    "remote_code_execution": 9.8, "os_command_injection": 9.8,
    "sqli": 9.0, "sql_injection": 9.0, "blind_sqli": 9.0,
    "ssrf": 8.6, "server_side_request_forgery": 8.6,
    "xxe": 8.2, "xml_external_entity": 8.2,
    "lfi": 7.5, "path_traversal": 7.5, "directory_traversal": 7.5,
    "ssti": 8.1, "server_side_template_injection": 8.1,
    "idor": 6.5, "broken_access_control": 6.5,
    "csrf": 6.5, "open_redirect": 6.1,
    "xss": 6.1, "reflected_xss": 6.1, "stored_xss": 7.5, "dom_xss": 6.1,
    "jwt_none_alg": 8.1, "jwt_weak_secret": 7.5,
    "default_credentials": 9.8, "weak_credentials": 7.5,
    "dmarc_missing": 5.3, "spf_analysis": 5.3, "no_rate_limit": 5.3,
    "info_disclosure": 4.3, "sensitive_data_exposure": 6.5,
    "security_misconfiguration": 6.5,
    "mx_enumeration": 2.0, "dkim_found": 2.0, "dns_enum": 2.0,
    "subdomain_takeover": 8.1,
    "request_smuggling": 8.6, "http_request_smuggling": 8.6,
    "race_condition": 7.5, "insecure_deserialization": 8.1,
    "smb_exposed": 8.1, "rdp_exposed": 7.5, "ssh_exposed": 5.3,
    "open_port": 3.0, "service_enumeration": 2.0,
}


def _cvss_from_finding(vuln_data: dict) -> float:
    """Derive a realistic CVSS baseline from severity + vuln_type."""
    explicit = vuln_data.get("cvss_base") or vuln_data.get("predicted_cvss_score")
    if explicit:
        try:
            v = float(explicit)
            if v > 0:
                return v
        except (TypeError, ValueError):
            pass
    vt = (vuln_data.get("vuln_type") or "").lower().replace("-", "_").replace(" ", "_")
    if vt in _VULN_TYPE_CVSS:
        return _VULN_TYPE_CVSS[vt]
    for key, score in _VULN_TYPE_CVSS.items():
        if key in vt or vt in key:
            return score
    sev = (vuln_data.get("severity") or "info").lower()
    return _SEVERITY_CVSS.get(sev, 5.0)


def extract_features(vuln_data: dict) -> VulnFeatures:
    """Extract feature vector from vulnerability data dict."""
    features = {}

    # Base CVSS — derived from severity/vuln_type when raw cvss_base is absent
    features["cvss_base_score"] = _cvss_from_finding(vuln_data) / 10.0

    # CVSS vector components
    vector_features = parse_cvss_vector(vuln_data.get("cvss_vector", ""))
    features.update(vector_features)

    # Exploit intelligence
    features["exploit_available"] = 1.0 if vuln_data.get("exploit_available") else 0.0
    features["epss_score"] = vuln_data.get("epss_score", 0.0)
    features["in_kev"] = 1.0 if vuln_data.get("in_kev") else 0.0

    # Vulnerability age (normalized, older = lower urgency)
    age_days = vuln_data.get("vuln_age_days", 0)
    features["vuln_age_days"] = min(age_days / 3650.0, 1.0)  # Normalize to 10 years

    # Asset context
    features["asset_exposure"] = EXPOSURE_MAP.get(vuln_data.get("exposure", "internal"), 0.3)
    features["iam_privilege_level"] = vuln_data.get("iam_level", 0) / 4.0
    features["service_criticality"] = vuln_data.get("criticality", 1) / 5.0

    # Validation results
    features["has_validation"] = 1.0 if vuln_data.get("validated") else 0.0
    features["validation_confidence"] = vuln_data.get("validation_confidence", 0.0)

    # Chain potential
    features["chain_potential"] = vuln_data.get("chain_score", 0.0)

    # Honeypot (inverted — high honeypot score = lower risk)
    features["honeypot_score_inv"] = 1.0 - vuln_data.get("honeypot_score", 0.0)

    # Network context
    features["open_port_count"] = min(vuln_data.get("open_ports", 0) / 100.0, 1.0)
    features["banner_info_quality"] = 1.0 if vuln_data.get("has_banner") else 0.0

    return VulnFeatures(
        vuln_id=vuln_data.get("vuln_id", ""),
        features=features,
        raw_data=vuln_data,
    )


def batch_extract(vuln_list: list[dict]) -> tuple[np.ndarray, list[str]]:
    """Extract features for a batch of vulnerabilities."""
    feature_vectors = []
    vuln_ids = []
    for v in vuln_list:
        vf = extract_features(v)
        feature_vectors.append(vf.to_array())
        vuln_ids.append(vf.vuln_id)

    if feature_vectors:
        return np.vstack(feature_vectors), vuln_ids
    return np.empty((0, len(FEATURE_NAMES))), []
