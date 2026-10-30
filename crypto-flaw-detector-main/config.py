"""Central configuration. Folders are created automatically at start-up."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "scans.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORT_DIR = os.path.join(BASE_DIR, "reports", "generated")
SAMPLE_FILE = os.path.join(BASE_DIR, "data", "sample_protocol.py")
ALLOWED_EXTENSIONS = {".py", ".txt"}
MAX_UPLOAD_BYTES = 1 * 1024 * 1024          # 1 MB
SECRET_KEY = "change-me-for-production"     # only used for flash messages
PROJECT_TITLE = "An AI-Driven Framework for Automated Discovery of Flaws in Cryptographic Protocol Implementations"

for _d in (UPLOAD_DIR, REPORT_DIR, os.path.dirname(DB_PATH)):
    os.makedirs(_d, exist_ok=True)
