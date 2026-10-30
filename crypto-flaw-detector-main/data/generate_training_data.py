"""Generates data/training_data.csv: synthetic examples of Python crypto-API misuse patterns.
Each row = one code unit's feature vector; label follows the misuse severity plus ~4% noise."""
import csv, os, random

rng = random.Random(42)
HEAD = ["weak_algorithm", "hardcoded_secret", "weak_random", "short_key", "insecure_tls",
        "weak_cipher_mode", "deprecated_api", "password_hash_issue", "finding_count",
        "severity_score", "risk_category"]
# (feature, probability of appearing, severity weight) - mirrors analyzer rules
MISUSES = [("weak_algorithm", .35, 4), ("hardcoded_secret", .25, 8), ("weak_random", .25, 6),
           ("short_key", .15, 6), ("insecure_tls", .20, 8), ("weak_cipher_mode", .15, 6),
           ("deprecated_api", .15, 3), ("password_hash_issue", .12, 6)]


def label(score, flags):
    if flags["hardcoded_secret"] and flags["insecure_tls"] or score >= 22: return "CRITICAL"
    if score >= 10: return "HIGH"
    if score >= 3: return "MEDIUM"
    return "LOW"


rows = []
for _ in range(800):
    flags = {n: int(rng.random() < p) for n, p, _w in MISUSES}
    if rng.random() < 0.2:                       # clean/secure code samples
        flags = {n: 0 for n in flags}
    count = sum(flags.values()) + (rng.randint(0, 2) if any(flags.values()) else 0)
    score = sum(w + rng.randint(-1, 1) for n, _p, w in MISUSES if flags[n])
    cat = label(score, flags)
    if rng.random() < 0.04:                      # label noise so the model must generalise
        cat = rng.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    rows.append([flags[n] for n, _, _ in MISUSES] + [count, max(score, 0), cat])

os.makedirs(os.path.dirname(os.path.abspath(__file__)), exist_ok=True)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_data.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(HEAD); w.writerows(rows)
print(f"Wrote {len(rows)} rows")
