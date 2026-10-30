"""Loads model.pkl (auto-trains if missing) and predicts the risk category for a feature dict."""
import os
import joblib, pandas as pd
from ai_model.train_model import MODEL, train

MIDPOINT = {"LOW": 20, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 95}
_cache = None


def _load():
    global _cache
    if _cache is None:
        if not os.path.exists(MODEL):
            train(verbose=False)
        _cache = joblib.load(MODEL)
    return _cache


def predict_risk(features):
    bundle = _load()
    X = pd.DataFrame([[features[n] for n in bundle["features"]]], columns=bundle["features"])
    probs = bundle["model"].predict_proba(X)[0]
    by_class = dict(zip(bundle["model"].classes_, probs))
    category = max(by_class, key=by_class.get)
    return {"prediction": category, "confidence": round(float(by_class[category]), 4),
            "probabilities": {k: round(float(v), 4) for k, v in by_class.items()},
            # risk_score = expected value of the class midpoints (0-100)
            "risk_score": round(sum(MIDPOINT[k] * v for k, v in by_class.items()))}
