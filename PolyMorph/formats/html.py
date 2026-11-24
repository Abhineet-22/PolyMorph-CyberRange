"""
HTML Format Helper — Job A (Normalization)
==========================================
HTML structure relevant to polyglot construction:

  HTML has no strict binary framing. A browser's HTML parser is defined
  by the WHATWG HTML Living Standard, which specifies error-recovery
  behaviour for virtually every malformed input. Practically:

    append_tolerant  : True  — bytes after </html> are ignored
    prepend_tolerant : True  — bytes before <!DOCTYPE> or <html> are tolerated
                               (browsers enter "quirks mode" but still render)
    max_prepend_bytes: -1    — no upper bound; browsers handle arbitrary prefixes
    scans_from_end   : False — HTML parsers read forward, not backward

The combination of both tolerances makes HTML one of the most flexible
formats for polyglot construction:
  - As host (format A): any payload appended after </html> is invisible
    to the HTML renderer.
  - As payload (format B): an HTML file can follow any append-tolerant
    format (e.g. a JPEG) because the browser's MIME sniffing may interpret
    the combined file as HTML when served without a strict Content-Type.

No logical EOF marker:
  HTML has no binary EOF equivalent. normalize() is therefore a no-op for
  APPEND purposes — the bytes are returned as-is. This is intentional.
  An HTML parser stops when its input is exhausted, not at a marker byte.

Normalization goal:
  Return the HTML bytes unchanged. Optionally strip trailing whitespace
  for cleanliness, but do not remove content — there is no marker to
  locate and no binary to corrupt by adding bytes.
"""

from __future__ import annotations

# ── Constants ─────────────────────────────────────────────────────────────────

# Byte sequences that identify HTML content near the start of the file.
# Checked case-insensitively and after stripping leading whitespace.
_HEADER_CANDIDATES = (
    b"<!doctype html",
    b"<!doctype",
    b"<html",
)

# Bytes we consider harmless trailing whitespace.
_TRAILING_WHITESPACE = b" \t\r\n"


# ── Job A helpers ─────────────────────────────────────────────────────────────

def normalize(html_bytes: bytes) -> bytes:
    """
    Return HTML bytes ready for use as the host in an APPEND polyglot.

    HTML has no binary EOF marker, so this function does not locate or
    truncate at any specific byte position. We strip trailing ASCII
    whitespace only — this keeps the output clean without risking
    removal of meaningful content.

    The append payload (e.g. ZIP bytes) will follow directly after the
    returned bytes. HTML parsers stop when input is exhausted and do not
    look for trailing content, so no separator is needed.
    """
    return html_bytes.rstrip(_TRAILING_WHITESPACE)


def has_valid_header(html_bytes: bytes) -> bool:
    """
    Return True if the bytes look like HTML content.

    We check the first 1024 bytes, case-insensitively, after stripping
    leading whitespace. HTML's prepend tolerance means the magic sequence
    does not have to be at offset 0 — but for format identification
    purposes, we check within a reasonable window.
    """
    window = html_bytes[:1024].lstrip(_TRAILING_WHITESPACE).lower()
    return any(window.startswith(cand) for cand in _HEADER_CANDIDATES)


def detect_version(html_bytes: bytes) -> str:
    """
    Return a rough HTML version hint based on the DOCTYPE declaration.

    Used by Job B (InjectStrategy) to determine comment injection strategy:
      - HTML5 (<!DOCTYPE html>) — standard <!-- --> comments
      - XHTML                   — comments must be well-formed XML
      - HTML4 / unknown         — standard <!-- --> comments

    Returns one of: "html5", "xhtml", "html4", "unknown"
    """
    window = html_bytes[:256].lstrip(_TRAILING_WHITESPACE).lower()
    if b"<!doctype html>" in window or b"<!doctype html " in window:
        if b"xhtml" in window:
            return "xhtml"
        return "html5"
    if b"html 4" in window or b"html4" in window:
        return "html4"
    if window.startswith(b"<html") or window.startswith(b"<!doctype"):
        return "unknown"
    return "unknown"


# ── Job B helpers (Injection) ─────────────────────────────────────────────────

def find_injection_offset(html_bytes: bytes) -> int:
    """
    Find safe offset to insert HTML comment payload.
    Ideally right after <!DOCTYPE ...> tag or opening <html> tag.
    """
    lower = html_bytes.lower()
    doctype_idx = lower.find(b"<!doctype")
    if doctype_idx != -1:
        end_doctype = lower.find(b">", doctype_idx)
        if end_doctype != -1:
            pos = end_doctype + 1
            if pos < len(html_bytes) and html_bytes[pos:pos+1] in (b"\r", b"\n"):
                pos += 1
                if pos < len(html_bytes) and html_bytes[pos:pos+1] == b"\n":
                    pos += 1
            return pos

    html_idx = lower.find(b"<html")
    if html_idx != -1:
        end_html = lower.find(b">", html_idx)
        if end_html != -1:
            return end_html + 1

    return 0


def inject_payload(html_bytes: bytes, payload: bytes) -> tuple[bytes, int]:
    """
    Inject foreign payload inside an HTML comment (<!-- payload -->).

    Parameters
    ----------
    html_bytes : Raw host HTML bytes.
    payload    : Foreign bytes to embed.

    Returns
    -------
    (new_html_bytes, payload_offset)
    """
    insert_pos = find_injection_offset(html_bytes)
    prefix = b"<!-- "
    suffix = b" -->\n"
    comment = prefix + payload + suffix

    polyglot = html_bytes[:insert_pos] + comment + html_bytes[insert_pos:]
    payload_offset = insert_pos + len(prefix)
    return polyglot, payload_offset


def extract_comments(html_bytes: bytes) -> list[bytes]:
    """Extract contents of all HTML comments (<!-- ... -->)."""
    comments: list[bytes] = []
    start = 0
    while True:
        idx = html_bytes.find(b"<!--", start)
        if idx == -1:
            break
        end = html_bytes.find(b"-->", idx + 4)
        if end == -1:
            break
        comments.append(html_bytes[idx + 4 : end].strip())
        start = end + 3
    return comments
