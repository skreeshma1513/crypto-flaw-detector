"""Real-time scanner: watches realtime/watch/ and scans every new or changed .py/.txt file.
Uses polling (standard library only). Files are only read and parsed, never executed.
Usage:  python realtime/watcher.py            (Ctrl+C to stop)
        python realtime/watcher.py --once     (scan what is there, then exit)"""
import json, os, sys, time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from analyzer.static_analyzer import analyze_source          # noqa: E402
from analyzer.feature_extractor import extract_features      # noqa: E402
from analyzer.risk_engine import combine                     # noqa: E402
from ai_model.predict import predict_risk                    # noqa: E402

WATCH_DIR = os.path.join(ROOT, "realtime", "watch")
LOG_FILE = os.path.join(ROOT, "realtime", "results", "realtime_log.jsonl")
MAX_BYTES = 1_000_000
ALLOWED = (".py", ".txt")


def scan_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    findings = analyze_source(source)
    ai = predict_risk(extract_features(findings))
    result = combine(findings, ai)
    return {"time": datetime.now().isoformat(timespec="seconds"), "file": os.path.basename(path),
            "risk_score": result["risk_score"], "risk_level": result["risk_level"],
            "ai_prediction": ai["prediction"], "ai_confidence": ai["confidence"],
            "findings": findings}


def handle(path):
    name = os.path.basename(path)
    try:
        if os.path.getsize(path) > MAX_BYTES:
            raise ValueError("file larger than 1 MB")
        rec = scan_file(path)
    except Exception as exc:                                  # keep the watcher alive
        print(f"[{datetime.now():%H:%M:%S}] {name}: SKIPPED - {exc}")
        return
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(json.dumps(rec) + "\n")
    print(f"\n[{rec['time']}] {name}: score {rec['risk_score']}/100 {rec['risk_level']} "
          f"| AI {rec['ai_prediction']} ({rec['ai_confidence']:.0%}) | {len(rec['findings'])} findings")
    for f in rec["findings"]:
        print(f"   line {f['line']:>3}  {f['severity']:<8} {f['rule_id']} {f['title']}")


def run(once=False, interval=2):
    os.makedirs(WATCH_DIR, exist_ok=True)
    seen = {}
    print(f"Watching {WATCH_DIR}  (drop .py files here; Ctrl+C to stop)")
    while True:
        for entry in os.scandir(WATCH_DIR):
            if entry.is_file() and entry.name.lower().endswith(ALLOWED):
                stamp = (entry.stat().st_mtime, entry.stat().st_size)
                if seen.get(entry.path) != stamp:             # new or modified
                    seen[entry.path] = stamp
                    handle(entry.path)
        if once:
            return
        time.sleep(interval)


if __name__ == "__main__":
    try:
        run(once="--once" in sys.argv)
    except KeyboardInterrupt:
        print("\nWatcher stopped.")
