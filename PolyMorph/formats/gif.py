"""
GIF Format Helper — Job A (Normalization)
==========================================
GIF structure relevant to polyglot construction:

  Header block         GIF87a or GIF89a  (6 bytes, offset 0)
  Logical Screen Descriptor              (7 bytes)
  [Global Colour Table if present]
  ... image frames, extension blocks ...
  Trailer              0x3B              (1 byte — logical EOF)

Two versions:
  GIF87a  — original spec; extension blocks not supported
  GIF89a  — extended spec; supports Application Extension blocks,
             Plain Text Extension, Comment Extension, Graphic Control

append_tolerant: True
  GIF parsers stop at the Trailer byte (0x3B) and discard trailing data.
  All major browsers, Pillow, and giflib honour this.

has_comment_field: True (GIF89a only)
  GIF89a Comment Extension blocks (0x21 0xFE) carry arbitrary text via
  chained sub-blocks of up to 255 bytes each. Total capacity is
  effectively unlimited through sub-block chaining.
  GIF87a has no extension blocks — the comment field is unavailable.
  Job B (InjectStrategy) will handle this distinction.

Normalization goal:
  Locate the LAST 0x3B Trailer byte in the file, return bytes up to
  and including it. Trailing garbage is stripped.

Why rfind?
  In theory a GIF has exactly one Trailer, but corrupt or hand-crafted
  files may have data after the Trailer. rfind + verification is safer
  than find, and consistent with our approach across other formats.
"""

from __future__ import annotations

# ── Constants ─────────────────────────────────────────────────────────────────

GIF87A_MAGIC = b"GIF87a"
GIF89A_MAGIC = b"GIF89a"
TRAILER      = b"\x3b"


# ── Job A helpers ─────────────────────────────────────────────────────────────

def find_trailer_position(gif_bytes: bytes) -> int:
    """
    Return the byte offset immediately AFTER the GIF Trailer byte (0x3B).

    We use rfind so that the last 0x3B in the file is used. This handles
    the (rare but real) case where raw 0x3B bytes appear inside image data
    or extension blocks.

    Raises ValueError if no Trailer byte is found.
    """
    pos = gif_bytes.rfind(TRAILER)
    if pos == -1:
        raise ValueError(
            "Cannot locate GIF Trailer byte (0x3B) — is this a valid GIF?"
        )
    return pos + len(TRAILER)


def normalize(gif_bytes: bytes) -> bytes:
    """
    Trim any bytes that follow the GIF Trailer byte.

    Returns the GIF bytes up to and including 0x3B.
    No trailing newline is added — GIF is a binary format.
    """
    return gif_bytes[: find_trailer_position(gif_bytes)]


def has_valid_header(gif_bytes: bytes) -> bool:
    """
    Return True if the bytes begin with GIF87a or GIF89a magic.

    GIF has zero prepend tolerance — magic bytes must be at offset 0.
    """
    return gif_bytes[:6] in (GIF87A_MAGIC, GIF89A_MAGIC)


def is_gif89a(gif_bytes: bytes) -> bool:
    """
    Return True if this is a GIF89a file (supports extension blocks).

    Used by Job B (InjectStrategy) to determine whether Comment Extension
    blocks are available for payload injection.
    """
    return gif_bytes[:6] == GIF89A_MAGIC


# ── Job B helpers (Injection) ─────────────────────────────────────────────────

COMMENT_EXTENSION_INTRO = b"\x21\xfe"  # Introducer (0x21) + Label (0xFE)


def find_injection_offset(gif_bytes: bytes) -> int:
    """
    Find safe offset to insert GIF89a Extension Blocks.

    Structure:
      Header (6 bytes) + Logical Screen Descriptor (7 bytes) = 13 bytes.
      Followed by Global Color Table if present (size = 3 * 2^(N+1)).
      Extension blocks are safely placed after the GCT and before the
      first Image Descriptor (0x2C).
    """
    if not has_valid_header(gif_bytes):
        raise ValueError("Invalid GIF header — cannot determine injection offset.")

    if len(gif_bytes) < 13:
        raise ValueError("GIF truncated before Logical Screen Descriptor.")

    # Packed field at byte 10: bit 7 is GCT flag, bits 0-2 are GCT size index
    packed = gif_bytes[10]
    has_gct = bool(packed & 0x80)
    gct_size = 3 * (2 ** ((packed & 0x07) + 1)) if has_gct else 0

    return 13 + gct_size


def inject_payload(gif_bytes: bytes, payload: bytes) -> tuple[bytes, int]:
    """
    Inject arbitrary payload into a GIF89a Comment Extension block.

    If the host file has a GIF87a header, it is automatically upgraded to
    GIF89a so that extension blocks are fully spec-compliant.

    Parameters
    ----------
    gif_bytes : Raw host GIF bytes.
    payload   : Foreign payload bytes.

    Returns
    -------
    (new_gif_bytes, payload_offset)
    """
    if not has_valid_header(gif_bytes):
        raise ValueError("Cannot inject into invalid GIF: missing magic bytes.")

    # Upgrade to GIF89a if necessary
    host = gif_bytes
    if host[:6] == GIF87A_MAGIC:
        host = GIF89A_MAGIC + host[6:]

    insert_pos = find_injection_offset(host)

    # Sub-block chaining (max 255 bytes per sub-block)
    sub_blocks = bytearray()
    for i in range(0, len(payload), 255):
        chunk = payload[i : i + 255]
        sub_blocks.append(len(chunk))
        sub_blocks.extend(chunk)
    # Block terminator (0-length sub-block)
    sub_blocks.append(0)

    ext_block = COMMENT_EXTENSION_INTRO + bytes(sub_blocks)
    polyglot = host[:insert_pos] + ext_block + host[insert_pos:]

    # Payload begins after 2-byte introducer + 1-byte first sub-block length
    payload_offset = insert_pos + 2 + 1
    return polyglot, payload_offset


def extract_comments(gif_bytes: bytes) -> list[bytes]:
    """Extract all payloads stored in GIF89a Comment Extension blocks."""
    comments: list[bytes] = []
    if not has_valid_header(gif_bytes):
        return comments

    pos = find_injection_offset(gif_bytes)
    while pos + 2 < len(gif_bytes):
        if gif_bytes[pos] == 0x3B:   # Trailer byte
            break
        if gif_bytes[pos] == 0x21:   # Extension block introducer
            label = gif_bytes[pos + 1]
            pos += 2
            block_data = bytearray()
            while pos < len(gif_bytes):
                block_len = gif_bytes[pos]
                pos += 1
                if block_len == 0:
                    break
                block_data.extend(gif_bytes[pos : pos + block_len])
                pos += block_len
            if label == 0xFE:
                comments.append(bytes(block_data))
        else:
            pos += 1

    return comments
