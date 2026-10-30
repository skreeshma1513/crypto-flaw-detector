import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
config.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")   # isolated test database
import app as app_module


def client():
    app_module.db.init_db()
    return app_module.app.test_client()


def test_full_flow():
    c = client()
    assert c.get("/").status_code == 200
    assert c.get("/upload").status_code == 200
    r = c.post("/analyze", data={"sample": "1"})
    assert r.status_code == 302
    page = c.get(r.headers["Location"])
    assert page.status_code == 200 and b"CRY009" in page.data
    assert c.get("/history").status_code == 200
    assert b"Security Summary" in c.get("/report/1").data
    assert c.get("/report/1?download=txt").status_code == 200
    assert c.get("/api/stats").get_json()["total_scans"] >= 1


def test_errors():
    c = client()
    assert c.get("/results/9999").status_code == 404
    r = c.post("/analyze", data={"code_text": "   "}, follow_redirects=True)
    assert b"empty" in r.data
    r = c.post("/analyze", data={"code_text": "def ("}, follow_redirects=True)
    assert b"Malformed" in r.data
