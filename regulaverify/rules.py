from __future__ import annotations

import json
import re
from datetime import date, timedelta

from .database import get_db, utc_now

RULE_VERSION = "SIH-DEMO-1.0"
REQUIRED_DOCUMENTS = {
    "Extension of Approval (EoA)": ("Application form", "Accreditation certificate"),
    "Programme change": ("Application form", "Accreditation certificate", "No Objection Certificate"),
    "Institutional modification": ("Application form", "Accreditation certificate"),
}


def required_documents(category: str) -> tuple[str, ...]:
    return REQUIRED_DOCUMENTS.get(category, REQUIRED_DOCUMENTS["Extension of Approval (EoA)"])


def run_checks(application: dict, documents: list[dict], actor: str = "system") -> list[dict]:
    present_types = {doc["doc_type"] for doc in documents}
    required = required_documents(application["category"])
    missing = [name for name in required if name not in present_types]
    doc_status = "flagged" if missing else "pass"
    result = [
        _finding(
            "DOC-001",
            doc_status,
            "action" if missing else "clear",
            "Required document check",
            ("Required documents missing: " + ", ".join(missing)) if missing else f"All {len(required)} required document types are present.",
            [{"document_type": name, "value": "Missing"} for name in missing]
            or [{"document_type": name, "value": "Present"} for name in required],
        )
    ]

    cert_docs = [doc for doc in documents if doc["doc_type"] == "Accreditation certificate"]
    expiry_rows = []
    for doc in cert_docs:
        fields = _fields(doc)
        expiry = fields.get("expiry_date")
        if expiry:
            try:
                expiry_day = date.fromisoformat(expiry)
                expiry_rows.append((doc, expiry_day, fields))
            except (TypeError, ValueError):
                pass
    readable_ids = {doc["id"] for doc, _expiry, _fields in expiry_rows}
    unreadable_certs = [doc for doc in cert_docs if doc.get("id") not in readable_ids]
    expired_rows = [row for row in expiry_rows if row[1] < date.today()]
    if not cert_docs or not expiry_rows:
        result.append(_finding("DATE-001", "uncertain", "review", "Certificate validity", "A readable expiry date was not extracted. Confirm the certificate dates manually.", [{"document_type": "Accreditation certificate", "value": "Expiry date unavailable"}]))
    elif expired_rows:
        evidence = [_evidence(doc, expiry_day.isoformat(), "expiry_date") for doc, expiry_day, _fields in expired_rows]
        evidence.extend({"document_type": doc["doc_type"], "filename": doc["original_name"], "value": "Expiry date unavailable", "field": "expiry_date"} for doc in unreadable_certs)
        summary = "At least one extracted expiry date is earlier than today."
        if unreadable_certs:
            summary += " Other certificates need manual date review."
        result.append(_finding("DATE-001", "flagged", "action", "Certificate validity", summary, evidence))
    elif unreadable_certs:
        evidence = [_evidence(doc, expiry_day.isoformat(), "expiry_date") for doc, expiry_day, _fields in expiry_rows]
        evidence.extend({"document_type": doc["doc_type"], "filename": doc["original_name"], "value": "Expiry date unavailable", "field": "expiry_date"} for doc in unreadable_certs)
        result.append(_finding("DATE-001", "uncertain", "review", "Certificate validity", "No expiry date has passed, but one or more submitted certificates need manual date review.", evidence))
    else:
        result.append(
            _finding(
                "DATE-001",
                "pass",
                "clear",
                "Certificate validity",
                f"All {len(expiry_rows)} readable certificate expiry dates have not passed.",
                [_evidence(doc, expiry_day.isoformat(), "expiry_date") for doc, expiry_day, _fields in expiry_rows],
            )
        )

    identifier_values = []
    for doc in documents:
        fields = _fields(doc)
        value = fields.get("institution_id")
        if value:
            identifier_values.append((doc, value, fields))
    conflicts = [(doc, value, fields) for doc, value, fields in identifier_values if value.casefold() != application["institution_id"].casefold()]
    if not identifier_values:
        result.append(_finding("ID-001", "uncertain", "review", "Institution identifier", "No institution identifier could be read from the submitted documents.", []))
    elif conflicts:
        refs = [_evidence(doc, value, "institution_id") for doc, value, _ in identifier_values]
        refs.insert(0, {"document_type": "Application record", "value": application["institution_id"], "field": "institution_id"})
        result.append(_finding("ID-001", "flagged", "action", "Institution identifier mismatch", "One or more documents contain an institution ID that differs from the application record.", refs))
    else:
        result.append(_finding("ID-001", "pass", "clear", "Institution identifier", "All extracted institution IDs match the application record.", [{"document_type": doc["doc_type"], "value": value, "field": "institution_id"} for doc, value, _ in identifier_values]))

    digest_groups: dict[str, list[dict]] = {}
    for doc in documents:
        digest_groups.setdefault(doc["sha256"], []).append(doc)
    duplicates = [items for items in digest_groups.values() if len(items) > 1]
    duplicate_evidence = [[{"document_type": doc["doc_type"], "filename": doc["original_name"], "value": doc["sha256"][:12]} for doc in group] for group in duplicates]
    result.append(
        _finding(
            "DUP-001",
            "flagged" if duplicates else "pass",
            "review" if duplicates else "clear",
            "Exact duplicate check",
            "Identical file content was submitted more than once." if duplicates else "No exact duplicate files were found in this application.",
            [item for group in duplicate_evidence for item in group],
        )
    )

    metadata_docs = [doc for doc in documents if doc["original_name"].lower().endswith(".pdf")]
    metadata_evidence = []
    metadata_available = False
    metadata_flags = []
    for doc in metadata_docs:
        metadata = json.loads(doc.get("metadata", "{}")) if isinstance(doc.get("metadata", "{}"), str) else doc.get("metadata", {})
        created = _pdf_date(metadata.get("creationDate", ""))
        modified = _pdf_date(metadata.get("modDate", ""))
        if created or modified:
            metadata_available = True
            metadata_evidence.append({"document_type": doc["doc_type"], "filename": doc["original_name"], "created": created.isoformat() if created else "Unavailable", "modified": modified.isoformat() if modified else "Unavailable"})
        if created and modified and created > modified:
            metadata_flags.append(doc["original_name"])
        if created and created > date.today() + timedelta(days=1):
            metadata_flags.append(doc["original_name"])
    if metadata_flags:
        metadata_status, metadata_severity = "flagged", "review"
        metadata_summary = "PDF timestamp metadata has an unexpected order or future creation date. This indicator needs human review and does not establish tampering."
    elif metadata_available:
        metadata_status, metadata_severity = "pass", "clear"
        metadata_summary = "No preliminary timestamp anomaly was detected in the available PDF metadata. Metadata can be changed and is not proof of authenticity."
    elif metadata_docs:
        metadata_status, metadata_severity = "pending", "review"
        metadata_summary = "No usable PDF timestamp metadata was found, so this limited check is inconclusive."
    else:
        metadata_status, metadata_severity = "pending", "review"
        metadata_summary = "No PDF files were submitted for timestamp metadata review."
    result.append(_finding("META-001", metadata_status, metadata_severity, "PDF metadata indicators", metadata_summary, metadata_evidence))

    verification = application.get("verification_status", "Pending")
    if not cert_docs:
        auth_status, auth_severity = "uncertain", "review"
        auth_summary = "No accreditation certificate is available for source verification."
    elif verification == "Verified":
        auth_status, auth_severity, auth_summary = "pass", "clear", "The synthetic authority record matched the submitted certificate details."
    elif verification == "Mismatch detected":
        auth_status, auth_severity, auth_summary = "flagged", "action", "The synthetic authority record returned conflicting certificate details."
    elif verification == "Source unavailable":
        auth_status, auth_severity, auth_summary = "uncertain", "review", "The simulated authority source was unavailable."
    else:
        auth_status, auth_severity, auth_summary = "pending", "review", "The certificate has not been checked against an authority source."
    result.append(_finding("AUTH-001", auth_status, auth_severity, "Issuing-authority verification", auth_summary, [{"source": "Simulated demonstration authority", "value": verification}]))

    db = get_db()
    db.execute("DELETE FROM findings WHERE application_id = ?", (application["id"],))
    for item in result:
        db.execute(
            """INSERT INTO findings
            (application_id, rule_id, rule_version, status, severity, title, summary, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (application["id"], item["rule_id"], RULE_VERSION, item["status"], item["severity"], item["title"], item["summary"], json.dumps(item["evidence"]), utc_now()),
        )
    has_flags = any(item["status"] in {"flagged", "uncertain"} for item in result)
    db.execute("UPDATE applications SET status = ? WHERE id = ?", ("Requires review" if has_flags else "Checks complete", application["id"]))
    db.commit()
    _audit(application["id"], actor, "Validation run", f"Applied rule set {RULE_VERSION}.", [item["rule_id"] for item in result])
    return result


def _finding(rule_id: str, status: str, severity: str, title: str, summary: str, evidence: list[dict]) -> dict:
    return {"rule_id": rule_id, "rule_version": RULE_VERSION, "status": status, "severity": severity, "title": title, "summary": summary, "evidence": evidence}


def _fields(document: dict) -> dict:
    raw = document.get("extracted_fields", "{}")
    return json.loads(raw) if isinstance(raw, str) else raw


def _evidence(document: dict, value: str, field: str) -> dict:
    fields = _fields(document)
    field_pages = fields.get("source_pages", {})
    return {"document_type": document["doc_type"], "filename": document["original_name"], "value": value, "field": field, "page": field_pages.get(field, fields.get("source_page"))}


def _pdf_date(value: str) -> date | None:
    if not value:
        return None
    match = re.match(r"^D:(\d{4})(\d{2})(\d{2})", value)
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def _audit(application_id: int, actor: str, action: str, detail: str, evidence_refs: list) -> None:
    get_db().execute(
        "INSERT INTO audit_events (application_id, actor, action, detail, evidence_refs, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (application_id, actor, action, detail, json.dumps(evidence_refs), utc_now()),
    )
    get_db().commit()
