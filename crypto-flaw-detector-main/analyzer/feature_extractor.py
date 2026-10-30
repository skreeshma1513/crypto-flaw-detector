"""Turns static-analysis findings into the numeric features the ML model uses."""
from analyzer.static_analyzer import RULES

FEATURE_NAMES = ["weak_algorithm", "hardcoded_secret", "weak_random", "short_key",
                 "insecure_tls", "weak_cipher_mode", "deprecated_api",
                 "password_hash_issue", "finding_count", "severity_score"]
SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}


def extract_features(findings):
    """Binary flag per misuse category + finding_count + summed severity weight."""
    feats = {name: 0 for name in FEATURE_NAMES}
    for f in findings:
        feats[RULES[f["rule_id"]][4]] = 1
    feats["finding_count"] = len(findings)
    feats["severity_score"] = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    return feats
