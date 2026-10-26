# RegulaVerify AI

SIH 2026 · AICTE Problem Statement 26261 · Flask prototype

RegulaVerify AI is a decision-support prototype for preliminary application scrutiny. It brings document upload, field extraction, configurable checklist rules, cross-document checks, simulated source verification and human review into one evidence-linked workflow. It does not approve or reject applications.

## Run locally

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. The first launch creates a local SQLite database and seeds a fictional example case.

### Demo accounts

| Role | Username | Password | Access |
|---|---|---|---|
| Reviewer | `reviewer` | `demo1234` | View cases, submit applications, run checks and record review outcomes |
| Administrator | `admin` | `admin1234` | Same prototype access as reviewer |
| Read-only auditor | `auditor` | `audit1234` | View cases and audit history |

Set `RV_REVIEWER_PASSWORD`, `RV_ADMIN_PASSWORD` or `RV_AUDITOR_PASSWORD` before the database is first created to change the seeded passwords. `RV_SECRET_KEY` should be set to a persistent random secret when running beyond a local demo. Optional paths can be changed with `RV_DATABASE` and `RV_UPLOAD_FOLDER`.

## What is implemented

- Local reviewer login with reviewer, administrator and read-only auditor roles.
- PDF, PNG and JPG upload with extension and file-signature checks, a 15 MB per-file limit, and random storage names.
- Embedded PDF text extraction with PyMuPDF. OCR fallback uses Tesseract when the binary and the Python packages are installed; extraction still works without OCR for readable PDFs.
- Deterministic extraction for institution IDs, certificate numbers and issue/expiry dates. Each document retains its hash, extracted values, source page, metadata and extraction method.
- Versioned sample rules for required document types, certificate validity, institutional ID consistency, exact duplicate hashes, limited PDF timestamp indicators and source-verification status.
- A fictional issuing-authority adapter with verified, mismatch and unavailable results. It never contacts AICTE or another live service.
- Reviewer observations, outcomes and a timestamped audit history.
- Synthetic dashboard case `APP-2026-001` demonstrating an expired certificate and conflicting institution ID.

## Prototype boundaries

The sample rule set is illustrative, not an official AICTE checklist. Configure rules from current authorized guidance before any operational use. The extraction layer uses text patterns and optional OCR; it does not call an LLM. Extraction confidence is a heuristic indicator, not a calibrated accuracy score. PDF metadata and duplicate checks do not establish document authenticity or fraud. The seeded records are fictional, and the example case has no original files attached.

The prototype stores records in SQLite and uploaded files in the local `instance/uploads` directory so it runs without a database service. This is a local demonstration setup, not a production deployment configuration. Production use would need an approved identity provider, managed database and protected object storage, encryption and retention controls, operational monitoring, and authorized integrations.
