"""File-upload hardening: real content sniffing (not just extension trust),
size/count limits, and safe random filenames / path-traversal guards.
"""
import re
import secrets
from pathlib import Path
from typing import Optional, Tuple

MAX_TEXT_LEN = 20_000
MAX_QUERY_LEN = 500
MAX_PDF_SIZE_BYTES = 15 * 1024 * 1024
MAX_DOCX_SIZE_BYTES = 15 * 1024 * 1024
MAX_IMAGE_SIZE_BYTES = 8 * 1024 * 1024
MAX_IMAGES_PER_REQUEST = 5

ALLOWED_PDF_MIME = {"application/pdf"}
ALLOWED_DOCX_MIME = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf", ".docx"}
ALLOWED_IMAGE_MIME = {"image/png", "image/jpeg"}

_PDF_MAGIC = b"%PDF-"
_DOCX_MAGIC = b"PK\x03\x04"  # .docx is a zip archive (Office Open XML)
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sniff_pdf(data: bytes) -> bool:
    return data[:5] == _PDF_MAGIC


def sniff_docx(data: bytes) -> bool:
    return data[:4] == _DOCX_MAGIC


def sniff_image_mime(data: bytes) -> Optional[str]:
    if data[:8] == _PNG_MAGIC:
        return "image/png"
    if data[:3] == _JPEG_MAGIC:
        return "image/jpeg"
    return None


def validate_pdf_upload(file_bytes: bytes, declared_mime: str) -> Tuple[bool, str]:
    if not file_bytes:
        return False, "الملف فارغ."
    if len(file_bytes) > MAX_PDF_SIZE_BYTES:
        return False, f"حجم الملف يتجاوز الحد المسموح ({MAX_PDF_SIZE_BYTES // (1024 * 1024)} ميجابايت)."
    if not sniff_pdf(file_bytes):
        return False, "محتوى الملف لا يطابق تنسيق PDF الحقيقي رغم امتداده — تم رفض الرفع."
    if declared_mime and declared_mime not in ALLOWED_PDF_MIME:
        return False, "نوع الملف (MIME) المصرَّح به غير مسموح."
    return True, "ok"


def validate_docx_upload(file_bytes: bytes, declared_mime: str) -> Tuple[bool, str]:
    if not file_bytes:
        return False, "الملف فارغ."
    if len(file_bytes) > MAX_DOCX_SIZE_BYTES:
        return False, f"حجم الملف يتجاوز الحد المسموح ({MAX_DOCX_SIZE_BYTES // (1024 * 1024)} ميجابايت)."
    if not sniff_docx(file_bytes):
        return False, "محتوى الملف لا يطابق تنسيق Word (docx) الحقيقي رغم امتداده — تم رفض الرفع."
    if declared_mime and declared_mime not in ALLOWED_DOCX_MIME:
        return False, "نوع الملف (MIME) المصرَّح به غير مسموح."
    return True, "ok"


def validate_document_upload(file_bytes: bytes, declared_mime: str, filename: str) -> Tuple[bool, str]:
    """Dispatch to the right validator based on the file's extension, still
    backed by real magic-byte sniffing (never the extension alone)."""
    ext = Path(filename or "").suffix.lower()
    if ext not in ALLOWED_DOCUMENT_EXTENSIONS:
        return False, "امتداد الملف غير مسموح. الأنواع المدعومة: PDF أو Word (.docx) فقط."
    if ext == ".docx":
        return validate_docx_upload(file_bytes, declared_mime)
    return validate_pdf_upload(file_bytes, declared_mime)


def validate_image_upload(file_bytes: bytes, declared_mime: str) -> Tuple[bool, str]:
    if not file_bytes:
        return False, "الملف فارغ."
    if len(file_bytes) > MAX_IMAGE_SIZE_BYTES:
        return False, f"حجم الصورة يتجاوز الحد المسموح ({MAX_IMAGE_SIZE_BYTES // (1024 * 1024)} ميجابايت)."
    sniffed = sniff_image_mime(file_bytes)
    if sniffed is None:
        return False, "محتوى الملف لا يطابق تنسيق صورة PNG/JPEG حقيقي رغم امتداده — تم رفض الرفع."
    if declared_mime and declared_mime not in ALLOWED_IMAGE_MIME:
        return False, "نوع الصورة (MIME) المصرَّح به غير مسموح."
    return True, "ok"


def safe_random_filename(original_name: str) -> str:
    """Generate a random, non-guessable filename, preserving only a short
    alphanumeric extension extracted from the original name."""
    ext = ""
    if original_name and "." in original_name:
        raw_ext = original_name.rsplit(".", 1)[-1]
        ext = "." + re.sub(r"[^a-zA-Z0-9]", "", raw_ext)[:5]
    return f"{secrets.token_hex(16)}{ext}"


def safe_join(base_dir: Path, filename: str) -> Path:
    """Resolve `filename` under `base_dir`, raising ValueError on any
    path-traversal attempt (e.g. '../../etc/passwd', absolute paths)."""
    base_dir = base_dir.resolve()
    candidate = (base_dir / filename).resolve()
    if base_dir not in candidate.parents and candidate != base_dir:
        raise ValueError("مسار ملف غير آمن (محاولة اجتياز مسارات).")
    return candidate


def sanitize_plain_text(text: str, max_len: int = MAX_TEXT_LEN) -> str:
    if not text:
        return ""
    cleaned = _CONTROL_CHARS_RE.sub("", text)
    return cleaned[:max_len]
