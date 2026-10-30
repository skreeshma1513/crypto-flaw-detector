import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer.static_analyzer import analyze_source
from analyzer.feature_extractor import extract_features
from ai_model.predict import predict_risk


def test_prediction_shape_and_ordering():
    clean = predict_risk(extract_features([]))
    bad_src = "import hashlib,random,requests\nKEY='abcdefgh12'\nhashlib.md5(b'')\nrandom.random()\nrequests.get('u',verify=False)"
    bad = predict_risk(extract_features(analyze_source(bad_src)))
    assert bad["prediction"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert 0 <= bad["confidence"] <= 1
    assert bad["risk_score"] > clean["risk_score"]
