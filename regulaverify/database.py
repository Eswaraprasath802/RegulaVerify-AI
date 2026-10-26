from __future__ import annotations

import json
import hashlib
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g
from werkzeug.security import generate_password_hash


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(current_app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect_db()
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db() -> None:
    database_path = Path(current_app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    db = connect_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            display_name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id TEXT NOT NULL UNIQUE,
            institution TEXT NOT NULL,
            institution_id TEXT NOT NULL,
            category TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Processing complete',
            verification_status TEXT NOT NULL DEFAULT 'Pending',
            review_status TEXT NOT NULL DEFAULT 'Pending review',
            reviewer TEXT,
            reviewed_at TEXT,
            review_note TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
            doc_type TEXT NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT,
            sha256 TEXT NOT NULL,
            extracted_text TEXT NOT NULL DEFAULT '',
            extracted_fields TEXT NOT NULL DEFAULT '{}',
            page_count INTEGER NOT NULL DEFAULT 0,
            metadata TEXT NOT NULL DEFAULT '{}',
            extraction_method TEXT NOT NULL DEFAULT 'text parsing',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
            rule_id TEXT NOT NULL,
            rule_version TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            evidence_refs TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_documents_application ON documents(application_id);
        CREATE INDEX IF NOT EXISTS idx_findings_application ON findings(application_id);
        CREATE INDEX IF NOT EXISTS idx_audit_application ON audit_events(application_id);
        """
    )

    demo_passwords = {
        "reviewer": ("demo1234", "reviewer", "Asha Menon"),
        "admin": ("admin1234", "admin", "Platform administrator"),
        "auditor": ("audit1234", "auditor", "Read-only auditor"),
    }
    for username, (password, role, name) in demo_passwords.items():
        db.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, display_name) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(os.environ.get(f"RV_{username.upper()}_PASSWORD", password)), role, name),
        )

    if db.execute("SELECT COUNT(*) FROM applications").fetchone()[0] == 0:
        _seed_demo_application(db)
    db.commit()
    db.close()


def _seed_demo_application(db: sqlite3.Connection) -> None:
    db.execute(
        """INSERT INTO applications
        (application_id, institution, institution_id, category, created_at, status, verification_status, review_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "APP-2026-001",
            "North Valley Institute of Technology",
            "INST-1024",
            "Programme change",
            "2026-04-18T09:15:00+05:30",
            "Requires review",
            "Pending",
            "Pending review",
        ),
    )
    app_id = db.execute("SELECT id FROM applications WHERE application_id = ?", ("APP-2026-001",)).fetchone()[0]
    demo_documents = [
        (
            "Application form",
            "application-form-demo.pdf",
            "demo-app-form",
            "Synthetic demonstration record. Institution ID: INST-1024. Application category: Programme change.",
            {"institution_id": "INST-1024", "category": "Programme change", "source_page": 1, "confidence": 0.98},
            2,
        ),
        (
            "Accreditation certificate",
            "accreditation-certificate-demo.pdf",
            "demo-accreditation",
            "Synthetic demonstration record. Institution ID: INST-1024. Certificate number: ACC-2024-018. Issue date: 01 July 2023. Expiry date: 30 June 2025.",
            {
                "institution_id": "INST-1024",
                "certificate_number": "ACC-2024-018",
                "issue_date": "2023-07-01",
                "expiry_date": "2025-06-30",
                "source_page": 1,
                "confidence": 0.97,
            },
            1,
        ),
        (
            "No Objection Certificate",
            "noc-demo.pdf",
            "demo-noc",
            "Synthetic demonstration record. Institution ID: INST-2048. NOC number: NOC-2026-051.",
            {"institution_id": "INST-2048", "certificate_number": "NOC-2026-051", "source_page": 1, "confidence": 0.96},
            1,
        ),
    ]
    for doc_type, filename, digest, body, fields, pages in demo_documents:
        db.execute(
            """INSERT INTO documents
            (application_id, doc_type, original_name, stored_name, sha256, extracted_text,
             extracted_fields, page_count, metadata, extraction_method, created_at)
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, 'synthetic demo data', ?)""",
            (app_id, doc_type, filename, hashlib.sha256(digest.encode()).hexdigest(), body, json.dumps(fields), pages, "{}", utc_now()),
        )
    seeded_findings = [
        (
            "DOC-001", "pass", "clear", "Required document check",
            "All 3 required document types are present.",
            [{"document_type": "Application form", "value": "Present"}, {"document_type": "Accreditation certificate", "value": "Present"}, {"document_type": "No Objection Certificate", "value": "Present"}],
        ),
        (
            "DATE-001", "flagged", "action", "Certificate validity",
            "Expiry date 2025-06-30 is earlier than the current review date.",
            [{"document_type": "Accreditation certificate", "filename": "accreditation-certificate-demo.pdf", "value": "2025-06-30", "field": "expiry_date", "page": 1}],
        ),
        (
            "ID-001", "flagged", "action", "Institution identifier mismatch",
            "One or more documents contain an institution ID that differs from the application record.",
            [{"document_type": "Application record", "value": "INST-1024", "field": "institution_id"}, {"document_type": "Application form", "value": "INST-1024", "field": "institution_id", "page": 1}, {"document_type": "Accreditation certificate", "value": "INST-1024", "field": "institution_id", "page": 1}, {"document_type": "No Objection Certificate", "filename": "noc-demo.pdf", "value": "INST-2048", "field": "institution_id", "page": 1}],
        ),
        (
            "DUP-001", "pass", "clear", "Exact duplicate check",
            "No exact duplicate files were found in this application.", [],
        ),
        (
            "META-001", "pending", "review", "PDF metadata indicators",
            "No usable PDF timestamp metadata was found, so this limited check is inconclusive.", [],
        ),
        (
            "AUTH-001", "pending", "review", "Issuing-authority verification",
            "The certificate has not been checked against an authority source.",
            [{"source": "Simulated demonstration authority", "value": "Pending"}],
        ),
    ]
    for rule_id, status, severity, title, summary, evidence in seeded_findings:
        db.execute(
            """INSERT INTO findings (application_id, rule_id, rule_version, status, severity, title, summary, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (app_id, rule_id, "SIH-DEMO-1.0", status, severity, title, summary, json.dumps(evidence), utc_now()),
        )
    db.execute(
        "INSERT INTO audit_events (application_id, actor, action, detail, evidence_refs, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (app_id, "system", "Demo case created", "Synthetic training example. All institution and document details are fictional.", "[]", utc_now()),
    )
