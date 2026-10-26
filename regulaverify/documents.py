from __future__ import annotations

import hashlib
import io
import re
import shutil
from datetime import datetime

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
MONTH = r"January|February|March|April|May|June|July|August|September|October|November|December"
DATE = rf"(?:\d{{1,2}}\s+(?:{MONTH})\s+\d{{4}}|\d{{1,2}}[/-]\d{{1,2}}[/-]\d{{4}}|(?:{MONTH})\s+\d{{1,2}},?\s+\d{{4}})"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_upload(filename: str, data: bytes) -> str:
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Use a PDF, PNG, JPG or JPEG file.")
    signatures = {
        "pdf": data.startswith(b"%PDF-"),
        "png": data.startswith(b"\x89PNG\r\n\x1a\n"),
        "jpg": data.startswith(b"\xff\xd8\xff"),
        "jpeg": data.startswith(b"\xff\xd8\xff"),
    }
    if not data or not signatures[extension]:
        raise ValueError(f"{filename}: the file contents do not match its extension.")
    return extension


def extract_document(data: bytes, extension: str) -> dict:
    text_parts: list[str] = []
    page_count = 0
    metadata: dict = {}
    method = "embedded PDF text"
    if extension == "pdf":
        try:
            import fitz

            with fitz.open(stream=data, filetype="pdf") as pdf:
                page_count = len(pdf)
                if page_count > 40:
                    raise ValueError("PDFs must contain 40 pages or fewer for this prototype.")
                metadata = {str(k): str(v) for k, v in (pdf.metadata or {}).items() if v}
                for page_index, page in enumerate(pdf):
                    page_text = page.get_text("text").strip()
                    if page_text:
                        text_parts.append(f"[Page {page_index + 1}]\n{page_text}")
                    elif _can_ocr():
                        pixmap = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False)
                        ocr_text = _ocr_image(pixmap.tobytes("png"))
                        if ocr_text:
                            text_parts.append(f"[Page {page_index + 1}]\n{ocr_text}")
                            method = "PDF text + OCR fallback"
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("The PDF could not be read. Check that it is a valid, unlocked PDF.") from exc
    else:
        page_count = 1
        if _can_ocr():
            text = _ocr_image(data)
            if text:
                text_parts.append(f"[Page 1]\n{text}")
                method = "OCR"

    text = "\n\n".join(text_parts)
    return {
        "text": text,
        "page_count": page_count,
        "metadata": metadata,
        "method": method if text else "no readable text (manual review required)",
        "fields": extract_fields(text),
    }


def _can_ocr() -> bool:
    return shutil.which("tesseract") is not None


def _ocr_image(data: bytes) -> str:
    if not _can_ocr():
        return ""
    try:
        from PIL import Image
        import pytesseract

        with Image.open(io.BytesIO(data)) as image:
            return pytesseract.image_to_string(image).strip()
    except Exception:
        return ""


def _parse_date(value: str) -> str | None:
    formats = (
        "%d %B %Y",
        "%d %b %Y",
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%m/%d/%Y",
        "%B %d, %Y",
        "%B %d %Y",
    )
    for date_format in formats:
        try:
            return datetime.strptime(value.strip(), date_format).date().isoformat()
        except ValueError:
            continue
    return None


def extract_fields(text: str) -> dict:
    institution = re.search(r"\b(INST[- ]?\d{3,})\b", text, re.IGNORECASE)
    cert = re.search(
        r"(?:certificate|registration|accreditation|noc)\s*(?:no\.?|number|#)\s*[:#-]?\s*([A-Z0-9][A-Z0-9/-]{2,})",
        text,
        re.IGNORECASE,
    )
    expiry = re.search(rf"(?:expiry|expires|valid until|valid through|expiration)(?:\s+date)?\s*[:\-]?\s*({DATE})", text, re.IGNORECASE)
    issue = re.search(rf"(?:issue|issued)(?:\s+date)?\s*[:\-]?\s*({DATE})", text, re.IGNORECASE)
    fields: dict = {}
    source_pages: dict = {}
    if institution:
        fields["institution_id"] = re.sub(r"\s+", "-", institution.group(1)).upper()
        source_pages["institution_id"] = _page_for_value(text, institution.group(1))
    if cert:
        fields["certificate_number"] = cert.group(1).rstrip(".,;:")
        source_pages["certificate_number"] = _page_for_value(text, cert.group(1))
    if issue:
        fields["issue_date"] = _parse_date(issue.group(1)) or issue.group(1)
        source_pages["issue_date"] = _page_for_value(text, issue.group(1))
    if expiry:
        fields["expiry_date"] = _parse_date(expiry.group(1)) or expiry.group(1)
        source_pages["expiry_date"] = _page_for_value(text, expiry.group(1))
    fields["source_pages"] = source_pages
    fields["source_page"] = source_pages.get("institution_id") or next(iter(source_pages.values()), None) or _page_for_value(text, None)
    fields["confidence"] = round(min(0.98, 0.55 + 0.11 * sum(key in fields for key in ("institution_id", "certificate_number", "issue_date", "expiry_date"))), 2) if text.strip() else 0.0
    return fields


def _page_for_value(text: str, value: str | None) -> int | None:
    if not text.strip():
        return None
    marker = re.search(r"\[Page (\d+)\]", text)
    if not marker:
        return 1
    if value:
        for part in re.split(r"(?=\[Page \d+\])", text):
            if value.casefold() in part.casefold():
                page_marker = re.search(r"\[Page (\d+)\]", part)
                if page_marker:
                    return int(page_marker.group(1))
    return int(marker.group(1))
