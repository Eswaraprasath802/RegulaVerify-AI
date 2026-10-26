from __future__ import annotations

import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from flask import Flask, abort, flash, g, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from regulaverify.authority import verify_application
from regulaverify.database import close_db, get_db, init_db, utc_now
from regulaverify.documents import extract_document, sha256_bytes, validate_upload
from regulaverify.rules import RULE_VERSION, run_checks

app = Flask(__name__, instance_relative_config=True)
app.config.update(
    SECRET_KEY=os.environ.get("RV_SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("RV_DATABASE") or str(Path(app.instance_path) / "regulaverify.sqlite3"),
    UPLOAD_FOLDER=os.environ.get("RV_UPLOAD_FOLDER") or str(Path(app.instance_path) / "uploads"),
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    MAX_FILE_SIZE=15 * 1024 * 1024,
)
Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
app.teardown_appcontext(close_db)


@app.before_request
def prepare_request():
    g.user = None
    if session.get("username"):
        user = get_db().execute("SELECT username, role, display_name FROM users WHERE username = ?", (session["username"],)).fetchone()
        g.user = dict(user) if user else None
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        if not secrets.compare_digest(submitted, session.get("csrf_token", "")):
            abort(400, "Your session token expired. Reload the page and try again.")
    if request.endpoint not in {"login", "static"} and g.user is None:
        return redirect(url_for("login"))


@app.context_processor
def inject_template_globals():
    return {"csrf_token": session.get("csrf_token", ""), "rule_version": RULE_VERSION}


@app.template_filter("pretty_date")
def pretty_date(value):
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%d %b %Y")
    except (ValueError, AttributeError):
        return value


@app.template_filter("pretty_datetime")
def pretty_datetime(value):
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%d %b %Y · %H:%M")
    except (ValueError, AttributeError):
        return value


def can_write() -> bool:
    return bool(g.user and g.user["role"] in {"reviewer", "admin"})


def require_writer():
    if not can_write():
        flash("This action requires a reviewer or administrator role.", "error")
        return False
    return True


def get_case(application_id: str) -> dict:
    db = get_db()
    row = db.execute("SELECT * FROM applications WHERE application_id = ?", (application_id,)).fetchone()
    if not row:
        abort(404)
    case = dict(row)
    docs = db.execute("SELECT * FROM documents WHERE application_id = ? ORDER BY id", (case["id"],)).fetchall()
    case["documents"] = []
    for doc in docs:
        item = dict(doc)
        try:
            item["fields"] = json.loads(item["extracted_fields"])
            item["file_metadata"] = json.loads(item["metadata"])
        except json.JSONDecodeError:
            item["fields"], item["file_metadata"] = {}, {}
        case["documents"].append(item)
    findings = db.execute("SELECT * FROM findings WHERE application_id = ? ORDER BY id", (case["id"],)).fetchall()
    case["findings"] = []
    for finding in findings:
        item = dict(finding)
        item["evidence_items"] = json.loads(item["evidence"] or "[]")
        case["findings"].append(item)
    audit = db.execute("SELECT * FROM audit_events WHERE application_id = ? ORDER BY id DESC", (case["id"],)).fetchall()
    case["audit"] = []
    for event in audit:
        item = dict(event)
        item["evidence_refs_list"] = json.loads(item["evidence_refs"] or "[]")
        case["audit"].append(item)
    return case


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["username"] = username
            session["csrf_token"] = secrets.token_urlsafe(24)
            return redirect(url_for("dashboard"))
        flash("That username and password combination was not recognized.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def dashboard():
    db = get_db()
    stats = {
        "total": db.execute("SELECT COUNT(*) FROM applications").fetchone()[0],
        "review": db.execute("SELECT COUNT(*) FROM applications WHERE status = 'Requires review'").fetchone()[0],
        "pending": db.execute("SELECT COUNT(*) FROM applications WHERE verification_status = 'Pending'").fetchone()[0],
        "anomalies": db.execute("SELECT COUNT(DISTINCT application_id) FROM findings WHERE status = 'flagged'").fetchone()[0],
        "actions": db.execute("SELECT COUNT(*) FROM applications WHERE review_status = 'Pending review'").fetchone()[0],
    }
    rows = db.execute(
        """SELECT a.*, (SELECT COUNT(*) FROM findings f WHERE f.application_id=a.id AND f.status IN ('flagged','uncertain')) AS issue_count
        FROM applications a ORDER BY CASE a.review_status WHEN 'Pending review' THEN 0 ELSE 1 END, a.created_at DESC LIMIT 12"""
    ).fetchall()
    return render_template("dashboard.html", stats=stats, applications=rows)


@app.get("/applications/new")
def new_application():
    if not require_writer():
        return redirect(url_for("dashboard"))
    return render_template("new_application.html")


@app.post("/applications")
def create_application():
    if not require_writer():
        return redirect(url_for("dashboard"))
    institution = request.form.get("institution", "").strip()
    institution_id = request.form.get("institution_id", "").strip().upper()
    category = request.form.get("category", "").strip()
    allowed_categories = {"Extension of Approval (EoA)", "Programme change", "Institutional modification"}
    if not institution or len(institution) > 160 or not institution_id or len(institution_id) > 40 or category not in allowed_categories:
        flash("Enter a valid institution name, institution ID and application category.", "error")
        return render_template("new_application.html", form=request.form), 400

    uploads = request.files.getlist("files")
    doc_types = request.form.getlist("doc_types")
    prepared = []
    try:
        for index, uploaded in enumerate(uploads[:10]):
            if not uploaded or not uploaded.filename:
                continue
            original = secure_filename(uploaded.filename)[:180] or "uploaded-document"
            data = uploaded.read(app.config["MAX_FILE_SIZE"] + 1)
            if len(data) > app.config["MAX_FILE_SIZE"]:
                raise ValueError(f"{original}: each file must be 15 MB or smaller.")
            extension = validate_upload(original, data)
            doc_type = doc_types[index] if index < len(doc_types) else ""
            if doc_type not in {"Application form", "Accreditation certificate", "No Objection Certificate", "Infrastructure evidence", "Other"}:
                raise ValueError(f"Choose a document type for {original}.")
            extracted = extract_document(data, extension)
            prepared.append({"original": original, "data": data, "extension": extension, "doc_type": doc_type, "extracted": extracted, "digest": sha256_bytes(data)})
        if len(uploads) > 10:
            raise ValueError("Add no more than 10 files to one application.")
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template("new_application.html", form=request.form), 400

    db = get_db()
    application_id = f"RV-26-{uuid4().hex[:6].upper()}"
    cursor = db.execute(
        "INSERT INTO applications (application_id, institution, institution_id, category, created_at) VALUES (?, ?, ?, ?, ?)",
        (application_id, institution, institution_id, category, utc_now()),
    )
    numeric_id = cursor.lastrowid
    for item in prepared:
        stored_name = f"{uuid4().hex}.{item['extension']}"
        Path(app.config["UPLOAD_FOLDER"], stored_name).write_bytes(item["data"])
        extracted = item["extracted"]
        db.execute(
            """INSERT INTO documents
            (application_id, doc_type, original_name, stored_name, sha256, extracted_text,
             extracted_fields, page_count, metadata, extraction_method, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (numeric_id, item["doc_type"], item["original"], stored_name, item["digest"], extracted["text"], json.dumps(extracted["fields"]), extracted["page_count"], json.dumps(extracted["metadata"]), extracted["method"], utc_now()),
        )
    db.execute(
        "INSERT INTO audit_events (application_id, actor, action, detail, evidence_refs, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (numeric_id, g.user["username"], "Application created", f"{len(prepared)} document(s) uploaded. Rule set {RULE_VERSION} will be applied.", "[]", utc_now()),
    )
    db.commit()
    case = get_case(application_id)
    run_checks(case, case["documents"], g.user["username"])
    flash("Application received. Findings are ready for review.", "success")
    return redirect(url_for("application_detail", application_id=application_id))


@app.get("/applications/<application_id>")
def application_detail(application_id: str):
    return render_template("application_detail.html", case=get_case(application_id), can_write=can_write())


@app.post("/applications/<application_id>/checks")
def rerun_checks(application_id: str):
    if not require_writer():
        return redirect(url_for("application_detail", application_id=application_id))
    case = get_case(application_id)
    run_checks(case, case["documents"], g.user["username"])
    flash("Validation checks completed.", "success")
    return redirect(url_for("application_detail", application_id=application_id))


@app.post("/applications/<application_id>/verify")
def simulate_verification(application_id: str):
    if not require_writer():
        return redirect(url_for("application_detail", application_id=application_id))
    case = get_case(application_id)
    status, _detail = verify_application(case, case["documents"], g.user["username"])
    updated = get_case(application_id)
    run_checks(updated, updated["documents"], g.user["username"])
    flash(f"Demo source result: {status}. This is a synthetic authority response.", "success" if status == "Verified" else "error")
    return redirect(url_for("application_detail", application_id=application_id))


@app.post("/applications/<application_id>/review")
def submit_review(application_id: str):
    if not require_writer():
        return redirect(url_for("application_detail", application_id=application_id))
    case = get_case(application_id)
    outcome = request.form.get("outcome", "")
    note = request.form.get("note", "").strip()
    allowed_outcomes = {"Reviewed", "Needs clarification", "Escalated"}
    if outcome not in allowed_outcomes or len(note) > 1200:
        flash("Select a review outcome and keep the observation under 1,200 characters.", "error")
        return redirect(url_for("application_detail", application_id=application_id))
    db = get_db()
    db.execute(
        "UPDATE applications SET review_status = ?, reviewer = ?, reviewed_at = ?, review_note = ? WHERE id = ?",
        (outcome, g.user["display_name"], utc_now(), note, case["id"]),
    )
    db.execute(
        "INSERT INTO audit_events (application_id, actor, action, detail, evidence_refs, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (case["id"], g.user["username"], f"Reviewer outcome: {outcome}", note or "No observation entered.", json.dumps([item["rule_id"] for item in case["findings"]]), utc_now()),
    )
    db.commit()
    flash("Review outcome and observation added to the audit history.", "success")
    return redirect(url_for("application_detail", application_id=application_id))


@app.get("/documents/<int:document_id>/file")
def document_file(document_id: int):
    row = get_db().execute("SELECT stored_name, original_name FROM documents WHERE id = ?", (document_id,)).fetchone()
    if not row or not row["stored_name"]:
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], row["stored_name"], as_attachment=False, download_name=row["original_name"])


@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413, message="The upload is too large. The total request limit is 20 MB."), 413


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="We couldn’t find that application or document."), 404


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "The request could not be processed.")), 400


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
