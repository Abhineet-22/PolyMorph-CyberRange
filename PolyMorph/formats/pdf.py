"""
PDF format helpers
==================
Low-level byte manipulation for PDF construction and normalization.
"""

from __future__ import annotations


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

EOF_MARKER = b"%%EOF"


# ─────────────────────────────────────────────────────────────────────────────
# Public helpers
# ─────────────────────────────────────────────────────────────────────────────

def find_eof_position(pdf_bytes: bytes) -> int:
    """
    Return the byte offset immediately after the last %%EOF marker
    (including any trailing CR/LF).

    Raises ValueError if no %%EOF is found.
    """
    pos = pdf_bytes.rfind(EOF_MARKER)
    if pos == -1:
        raise ValueError(
            "Cannot locate %%EOF marker — is this a valid PDF?"
        )

    end = pos + len(EOF_MARKER)

    # PDF spec allows %%EOF to be followed by a single EOL sequence.
    if end < len(pdf_bytes) and pdf_bytes[end] == 0x0D:   # CR
        end += 1
    if end < len(pdf_bytes) and pdf_bytes[end] == 0x0A:   # LF
        end += 1

    return end


def normalize(pdf_bytes: bytes) -> bytes:
    """
    Trim any bytes that follow the last %%EOF marker and ensure
    the file ends with exactly one LF after the marker.

    This prevents pre-existing trailer junk from breaking the
    polyglot when the second format's bytes are appended.
    """
    end = find_eof_position(pdf_bytes)
    trimmed = pdf_bytes[:end]

    # Guarantee a clean newline termination.
    if not trimmed.endswith(b"\n"):
        trimmed += b"\n"

    return trimmed

def find_header_offset(pdf_bytes: bytes) -> int:
    """
    Return the byte offset of the %PDF- marker within the first 1024 bytes.
    Returns -1 if not found.
    """
    PDF_MARKER   = b"%PDF-"
    SEARCH_LIMIT = 1024

    # Extend the window by len(PDF_MARKER) - 1 so a marker whose first byte
    # falls at offset 1023 is still found in full, not truncated.
    window = pdf_bytes[: SEARCH_LIMIT + len(PDF_MARKER) - 1]
    return window.find(PDF_MARKER)


def has_valid_header(pdf_bytes: bytes) -> bool:
    """
    Return True if a %PDF- marker is present within the first 1024 bytes.
    Does NOT require the marker to be at offset 0.
    """
    return find_header_offset(pdf_bytes) != -1


# ── Job B helpers (Injection) ─────────────────────────────────────────────────

def inject_payload(pdf_bytes: bytes, payload: bytes) -> tuple[bytes, int]:
    """
    Inject payload into a PDF comment line prior to the startxref marker.

    Parameters
    ----------
    pdf_bytes : Raw host PDF bytes.
    payload   : Foreign payload bytes.

    Returns
    -------
    (new_pdf_bytes, payload_offset)
    """
    if not has_valid_header(pdf_bytes):
        raise ValueError("Cannot inject into invalid PDF: missing %PDF- header.")

    # Locate startxref marker
    sxref_pos = pdf_bytes.rfind(b"startxref")
    if sxref_pos == -1:
        # Fallback to %%EOF
        sxref_pos = pdf_bytes.rfind(EOF_MARKER)
        if sxref_pos == -1:
            raise ValueError("Cannot locate startxref or %%EOF marker in PDF.")

    comment_line = b"% " + payload.replace(b"\n", b"\n% ") + b"\n"
    polyglot = pdf_bytes[:sxref_pos] + comment_line + pdf_bytes[sxref_pos:]
    payload_offset = sxref_pos + 2
    return polyglot, payload_offset
