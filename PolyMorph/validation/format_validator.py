from __future__ import annotations
import io, zipfile
from dataclasses import dataclass

@dataclass
class ValidationResult:
    fmt: str
    valid: bool
    detail: str

class FormatValidator:
    @classmethod
    def validate(cls, data: bytes, fmt: str) -> ValidationResult:
        method = cls._VALIDATORS.get(fmt)
        if method is None:
            return ValidationResult(fmt=fmt, valid=True,
                detail="No validator registered for this format — skipped.")
        valid, detail = method(data)
        return ValidationResult(fmt=fmt, valid=valid, detail=detail)

    @classmethod
    def validate_both(cls, data, fmt_a, fmt_b):
        return cls.validate(data, fmt_a), cls.validate(data, fmt_b)

    @staticmethod
    def _validate_pdf(data):
        try:
            import pypdf
            r = pypdf.PdfReader(io.BytesIO(data), strict=False)
            return True, f"pypdf: {len(r.pages)} page(s) read successfully."
        except ImportError:
            if data[:4] == b"%PDF" and b"%%EOF" in data:
                return True, "pypdf not installed — magic byte check passed."
            return False, "pypdf not installed and magic byte check failed."
        except Exception as exc:
            return False, f"pypdf: {exc}"

    @staticmethod
    def _validate_zip(data):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                bad = zf.testzip()
                if bad:
                    return False, f"CRC error in: {bad}"
                return True, f"zipfile: {len(names)} entr(ies) — {names[:5]}"
        except zipfile.BadZipFile as exc:
            return False, f"zipfile: {exc}"
        except Exception as exc:
            return False, f"zipfile: {exc}"

    @staticmethod
    def _validate_pillow(data):
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            img.verify()
            return True, f"Pillow: {img.format} verified."
        except ImportError:
            return True, "Pillow not installed — skipped."
        except Exception as exc:
            return False, f"Pillow: {exc}"

    @staticmethod
    def _validate_html(data):
        text = data[:4096].decode("utf-8", errors="ignore").lower()
        if any(tag in text for tag in ("<html", "<!doctype", "<script", "<svg", "<body", "<head")):
            return True, "HTML: script or HTML tag structure detected."
        return False, "HTML: no HTML or script tags found in first 4 KB."

    @staticmethod
    def _validate_php(data):
        if b"<?php" in data or b"<?=" in data:
            return True, "PHP: opening script tag (<?php or <?=) detected."
        return False, "PHP: no opening <?php or <?= tag found."

FormatValidator._VALIDATORS = {
    "pypdf":   FormatValidator._validate_pdf,
    "zipfile": FormatValidator._validate_zip,
    "pillow":  FormatValidator._validate_pillow,
    "html":    FormatValidator._validate_html,
    "php":     FormatValidator._validate_php,
    "docx":    FormatValidator._validate_zip,
    "jar":     FormatValidator._validate_zip,
}
