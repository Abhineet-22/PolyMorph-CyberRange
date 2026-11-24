"""
JPEG Format Helper — Job A (Normalization)
==========================================
JPEG structure relevant to polyglot construction:

  SOI  FF D8          — Start of Image (magic bytes, must be at offset 0)
  ...  marker segments (FF XX LL LL data)
  EOI  FF D9          — End of Image (logical EOF)

append_tolerant: True
  JPEG parsers stop at EOI and discard everything after it.
  Any bytes appended after FF D9 are invisible to the JPEG decoder.

Normalization goal:
  Locate the LAST FF D9 in the file, return bytes up to and including
  that marker. Trailing garbage (from a previous construction attempt,
  test artifact, or unknown origin) is stripped.

Why rfind, not find?
  Some JPEG files embed thumbnail images in EXIF APP1 segments that
  themselves contain a complete SOI/EOI pair. rfind ensures we stop at
  the outermost EOI, not an inner thumbnail's EOI.
"""

from __future__ import annotations

# ── Constants ─────────────────────────────────────────────────────────────────

SOI_MARKER = b"\xff\xd8"        # Start of Image — must be at offset 0
EOI_MARKER = b"\xff\xd9"        # End of Image   — logical EOF
JPEG_MAGIC  = b"\xff\xd8\xff"   # First 3 bytes of every valid JPEG


# ── Job A helpers ─────────────────────────────────────────────────────────────

def find_eoi_position(jpeg_bytes: bytes) -> int:
    """
    Return the byte offset immediately AFTER the last FF D9 EOI marker.

    We use rfind (last occurrence) rather than find (first occurrence)
    because embedded EXIF thumbnails contain their own SOI/EOI pair earlier
    in the stream. Using the last FF D9 ensures we capture the outermost image.

    Raises ValueError if no FF D9 is found.
    """
    pos = jpeg_bytes.rfind(EOI_MARKER)
    if pos == -1:
        raise ValueError(
            "Cannot locate EOI marker (FF D9) — is this a valid JPEG?"
        )
    return pos + len(EOI_MARKER)


def normalize(jpeg_bytes: bytes) -> bytes:
    """
    Trim any bytes that follow the last FF D9 EOI marker.

    Returns the JPEG bytes up to and including the EOI.
    No trailing newline is added (unlike PDF) because JPEG is a binary
    format and inserting text bytes after the EOI would be detectable.
    """
    return jpeg_bytes[: find_eoi_position(jpeg_bytes)]


def has_valid_header(jpeg_bytes: bytes) -> bool:
    """
    Return True if the bytes begin with the JPEG SOI magic sequence FF D8 FF.

    JPEG has zero prepend tolerance — the magic bytes must be at offset 0.
    """
    return jpeg_bytes[:3] == JPEG_MAGIC


# ── Job B helpers (Injection) ─────────────────────────────────────────────────

COM_MARKER = b"\xff\xfe"        # JPEG Comment marker
MAX_COM_PAYLOAD = 65533         # 65535 - 2 bytes length field


def find_injection_offset(jpeg_bytes: bytes) -> int:
    """
    Find the optimal byte offset to insert metadata/comment markers.

    Standard convention:
      - Start immediately after SOI (offset 2).
      - If APP0 (JFIF) or APP1 (Exif) marker exists at offset 2, place
        the comment immediately after the initial APP segment(s).
        This preserves JFIF/Exif identification in strict header parsers.
      - If no APP markers exist, returns offset 2 (right after SOI).
    """
    if not has_valid_header(jpeg_bytes):
        raise ValueError("Invalid JPEG header — cannot determine injection offset.")

    pos = 2
    # Check for consecutive APP markers (0xFFE0 .. 0xFFEF) starting at offset 2
    while pos + 4 <= len(jpeg_bytes) and jpeg_bytes[pos] == 0xFF and 0xE0 <= jpeg_bytes[pos + 1] <= 0xEF:
        marker_len = int.from_bytes(jpeg_bytes[pos + 2 : pos + 4], "big")
        if marker_len < 2 or pos + 2 + marker_len > len(jpeg_bytes):
            break
        pos += 2 + marker_len

    return pos


def inject_payload(jpeg_bytes: bytes, payload: bytes) -> tuple[bytes, int]:
    """
    Inject arbitrary payload bytes into JPEG COM (Comment) segment(s).

    Parameters
    ----------
    jpeg_bytes : Raw host JPEG bytes.
    payload    : Foreign bytes to embed inside COM marker(s).

    Returns
    -------
    (new_jpeg_bytes, payload_offset)
      where payload_offset is the byte offset of the payload inside the
      resulting JPEG file (useful for offset patching).
    """
    import struct

    if not has_valid_header(jpeg_bytes):
        raise ValueError("Cannot inject into invalid JPEG: missing SOI marker.")

    insert_pos = find_injection_offset(jpeg_bytes)

    if len(payload) <= MAX_COM_PAYLOAD:
        # Single COM marker
        com_data = COM_MARKER + struct.pack(">H", len(payload) + 2) + payload
        polyglot = jpeg_bytes[:insert_pos] + com_data + jpeg_bytes[insert_pos:]
        payload_offset = insert_pos + 4
        return polyglot, payload_offset

    # Multi-segment chaining for large payloads
    segments = bytearray()
    first_payload_offset = insert_pos + 4
    for i in range(0, len(payload), MAX_COM_PAYLOAD):
        chunk = payload[i : i + MAX_COM_PAYLOAD]
        segments.extend(COM_MARKER + struct.pack(">H", len(chunk) + 2) + chunk)

    polyglot = jpeg_bytes[:insert_pos] + bytes(segments) + jpeg_bytes[insert_pos:]
    return polyglot, first_payload_offset


def extract_comments(jpeg_bytes: bytes) -> list[bytes]:
    """Extract all payloads stored inside COM (FF FE) segments."""
    comments: list[bytes] = []
    if not has_valid_header(jpeg_bytes):
        return comments

    pos = 2
    while pos + 4 <= len(jpeg_bytes):
        if jpeg_bytes[pos] != 0xFF:
            pos += 1
            continue

        marker = jpeg_bytes[pos + 1]
        if marker in (0xD8, 0xD9, 0x00):   # SOI, EOI, or escaped FF 00
            pos += 2
            continue
        if marker == 0xDA:                 # SOS (Start of Scan) - scan data begins
            break

        marker_len = int.from_bytes(jpeg_bytes[pos + 2 : pos + 4], "big")
        if marker_len < 2:
            break

        if marker == 0xFE:                 # COM segment
            data_start = pos + 4
            data_end = pos + 2 + marker_len
            comments.append(jpeg_bytes[data_start:data_end])

        pos += 2 + marker_len

    return comments
