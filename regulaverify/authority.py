from __future__ import annotations

from .database import get_db, utc_now

# Fictional records for the SIH demonstration. They do not connect to AICTE or a live authority.
SYNTHETIC_RECORDS = {
    "ACC-2024-018": {"institution_id": "INST-1024", "status": "Verified"},
    "ACC-2026-018": {"institution_id": "INST-1024", "status": "Verified"},
    "ACC-FAKE-999": {"institution_id": "INST-9999", "status": "Mismatch detected"},
}


def verify_application(application: dict, documents: list[dict], actor: str) -> tuple[str, str]:
    certificate = next((doc for doc in documents if doc["doc_type"] == "Accreditation certificate"), None)
    if not certificate:
        status, detail = "Source unavailable", "No accreditation certificate was submitted."
    else:
        import json

        fields = json.loads(certificate["extracted_fields"])
        reference = fields.get("certificate_number", "")
        record = SYNTHETIC_RECORDS.get(reference)
        if not record:
            status, detail = "Source unavailable", f"The fictional authority has no record for {reference or 'the extracted certificate number'}."
        elif record["institution_id"] != application["institution_id"]:
            status, detail = "Mismatch detected", f"Synthetic record institution ID {record['institution_id']} differs from the application record."
        else:
            status, detail = record["status"], f"Synthetic record {reference} matched institution {record['institution_id']}."

    db = get_db()
    db.execute("UPDATE applications SET verification_status = ? WHERE id = ?", (status, application["id"]))
    db.execute(
        "INSERT INTO audit_events (application_id, actor, action, detail, evidence_refs, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (application["id"], actor, "Simulated authority verification", detail, '["AUTH-001"]', utc_now()),
    )
    db.commit()
    return status, detail
