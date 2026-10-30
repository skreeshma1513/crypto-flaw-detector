import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from analyzer.static_analyzer import analyze_source
from analyzer.feature_extractor import extract_features
from analyzer.risk_engine import combine


def ids(src): return {f["rule_id"] for f in analyze_source(src)}

def test_md5(): assert "CRY001" in ids("import hashlib\nhashlib.md5(b'x')")
def test_sha1(): assert "CRY002" in ids("import hashlib\nhashlib.sha1(b'x')")
def test_weak_random(): assert "CRY005" in ids("import random\nt=random.randint(1,9)")
def test_secrets_ok(): assert "CRY005" not in ids("import secrets\nt=secrets.token_hex(8)")
def test_hardcoded_secret(): assert "CRY006" in ids("SECRET_KEY = 'abcd1234efgh'")
def test_tls_off(): assert "CRY009" in ids("import requests\nrequests.get('u', verify=False)")
def test_empty(): 
    with pytest.raises(ValueError): analyze_source("   ")
def test_malformed():
    with pytest.raises(ValueError): analyze_source("def (:")
def test_risk_scoring():
    f = analyze_source("import requests\nrequests.get('u', verify=False)")
    ai = {"risk_score": 80}
    r = combine(f, ai)
    assert r["risk_level"] in ("HIGH", "CRITICAL") and r["risk_score"] >= 70
