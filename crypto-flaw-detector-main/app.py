"""Flask application: routes, validation and the analysis pipeline.
Uploaded code is only read and parsed (AST). It is NEVER executed."""
from functools import wraps
import os
import sqlite3
from datetime import datetime

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.utils import secure_filename

import config
from ai_model.predict import predict_risk
from analyzer.feature_extractor import extract_features
from analyzer.risk_engine import combine, level_for, static_score
from analyzer.static_analyzer import analyze_source
from database import db

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES
db.init_db()   # create tables automatically


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to access this security scanner feature.", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def run_pipeline(filename, source):
    """static analysis -> features -> AI prediction -> combined risk -> save to SQLite."""
    findings = analyze_source(source)                      # raises ValueError on empty/malformed code
    features = extract_features(findings)
    try:
        ai = predict_risk(features)                         # auto-trains model.pkl if missing
    except Exception:                                       # model problem: fall back to static only
        s = static_score(findings)
        ai = {"prediction": level_for(s), "confidence": 0.0, "risk_score": s}
        flash("AI model unavailable - result is based on static analysis only.", "warning")
    risk = combine(findings, ai)
    return db.save_scan(filename, risk, ai, findings)


# ------------------------------------------------------------------ auth routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next") or request.args.get("next")

        if not username or not password:
            flash("Please enter both workstation username and passphrase.", "error")
            return render_template("login.html", active_tab="login", next_url=next_url)

        user = db.verify_user(username, password)
        if user:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user.get("role", "Security Analyst")
            flash(f"Welcome back, {user['username']}! Session authenticated.", "success")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("index"))
        else:
            flash("Invalid username or passphrase. (Tip: Use the Demo button for quick access).", "error")
            return render_template("login.html", active_tab="login", next_url=next_url)

    next_url = request.args.get("next", "")
    return render_template("login.html", active_tab=request.args.get("tab", "login"), next_url=next_url)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "Security Analyst").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    next_url = request.form.get("next") or request.args.get("next")

    if not username or len(username) < 3:
        flash("Workstation username must be at least 3 characters.", "error")
        return render_template("login.html", active_tab="register", next_url=next_url)

    if len(password) < 4:
        flash("Security passphrase must be at least 4 characters long.", "error")
        return render_template("login.html", active_tab="register", next_url=next_url)

    if password != confirm:
        flash("Passphrases do not match. Please re-enter.", "error")
        return render_template("login.html", active_tab="register", next_url=next_url)

    if db.get_user_by_username(username):
        flash(f"Username '{username}' is already registered. Please sign in or use another.", "error")
        return render_template("login.html", active_tab="register", next_url=next_url)

    try:
        user_id = db.create_user(username=username, password=password, email=email, role=role)
        session.clear()
        session["user_id"] = user_id
        session["username"] = username
        session["role"] = role
        flash(f"Account created successfully! Welcome to CryptoGuard AI, {username}.", "success")
        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("index"))
    except Exception as exc:
        flash(f"Registration error: {exc}", "error")
        return render_template("login.html", active_tab="register", next_url=next_url)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out safely.", "success")
    return redirect(url_for("login"))


# ------------------------------------------------------------------ pages
@app.route("/")
def index():
    return render_template("index.html", stats=db.get_stats(), recent=db.list_scans(limit=5))


@app.route("/upload")
@login_required
def upload():
    return render_template("upload.html")


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():

    try:
        if request.form.get("sample"):                      # "Scan Sample" button
            with open(config.SAMPLE_FILE, "r", encoding="utf-8") as fh:
                source, filename = fh.read(), "sample_protocol.py"
        else:
            upload_file = request.files.get("code_file")
            pasted = request.form.get("code_text", "")
            if upload_file and upload_file.filename:
                filename = secure_filename(upload_file.filename)
                if os.path.splitext(filename)[1].lower() not in config.ALLOWED_EXTENSIONS:
                    raise ValueError("Unsupported file type. Please upload a .py or .txt file.")
                raw = upload_file.read()
                if not raw.strip():
                    raise ValueError("The uploaded file is empty.")
                source = raw.decode("utf-8", errors="replace")
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S_")   # keep a copy; never executed
                with open(os.path.join(config.UPLOAD_DIR, stamp + filename), "wb") as out:
                    out.write(raw)
            elif pasted.strip():
                source, filename = pasted, "pasted_code.py"
            else:
                raise ValueError("Source code is empty. Upload a file or paste some code.")
        scan_id = run_pipeline(filename, source)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("upload"))
    except sqlite3.Error:
        flash("Database error while saving the scan. Please try again.", "error")
        return redirect(url_for("upload"))
    return redirect(url_for("results", scan_id=scan_id))


@app.route("/results/<int:scan_id>")
def results(scan_id):
    scan, findings = db.get_scan(scan_id)
    if scan is None:
        abort(404)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    static_level = level_for(scan["static_score"])
    return render_template("results.html", scan=scan, findings=findings, counts=counts,
                           static_level=static_level)


@app.route("/history")
def history():
    return render_template("history.html", scans=db.list_scans())


def build_text_report(scan, findings):
    lines = [config.PROJECT_TITLE, "=" * 70, f"Scan date     : {scan['scan_date']}", f"File          : {scan['filename']}",
             f"Risk score    : {scan['risk_score']}/100", f"Risk level    : {scan['risk_level']}",
             f"AI prediction : {scan['ai_prediction']} ({scan['ai_confidence']:.0%} confidence)",
             f"Score method  : {scan['explanation']}", f"Findings      : {scan['finding_count']}", "", "DETECTED ISSUES", "-" * 70]
    for f in findings:
        lines += [f"[{f['severity']}] {f['rule_id']} - {f['title']} (line {f['line_number']})",
                  f"  Why dangerous : {f['description']}", f"  Evidence      : {f['evidence']}",
                  f"  Recommendation: {f['recommendation']}", ""]
    if not findings:
        lines.append("No issues detected.\n")
    lines += ["SECURITY SUMMARY", "-" * 70,
              f"The file received a {scan['risk_level']} overall risk rating with {scan['finding_count']} finding(s). "
              "Address CRITICAL and HIGH items first. This tool is static analysis only and may miss issues."]
    return "\n".join(lines)


@app.route("/report/<int:scan_id>")
def report(scan_id):
    scan, findings = db.get_scan(scan_id)
    if scan is None:
        abort(404)
    fmt = request.args.get("download")
    if fmt == "txt":
        text = build_text_report(scan, findings)
        with open(os.path.join(config.REPORT_DIR, f"report_{scan_id}.txt"), "w", encoding="utf-8") as fh:
            fh.write(text)
        return Response(text, mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.txt"})
    html = render_template("report.html", scan=scan, findings=findings, title=config.PROJECT_TITLE,
                           printable=(fmt == "html"))
    with open(os.path.join(config.REPORT_DIR, f"report_{scan_id}.html"), "w", encoding="utf-8") as fh:
        fh.write(html)
    if fmt == "html":
        return Response(html, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.html"})
    return html


@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats())


# ------------------------------------------------------------------ errors
def _error(code, message):
    return render_template("error.html", code=code, message=message), code


@app.errorhandler(404)
def not_found(_e):
    return _error(404, "That scan or page does not exist.")


@app.errorhandler(413)
def too_large(_e):
    flash("File too large. The maximum size is 1 MB.", "error")
    return redirect(url_for("upload"))


@app.errorhandler(sqlite3.Error)
def db_error(_e):
    return _error(500, "A database error occurred. Delete database/scans.db and restart to reset it.")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
