"""
ZIP format helpers
==================
Low-level byte manipulation for ZIP construction, EOCD parsing,
and offset patching — the critical step for prepend polyglots.

ZIP structure overview (single-disk archive):
  [Local file entry 0]   PK\x03\x04 + header + data
  [Local file entry 1]   PK\x03\x04 + header + data
  ...
  [Central directory]    PK\x01\x02 entries (one per file)
  [EOCD]                 PK\x05\x06 — found by scanning backward

When N bytes are prepended (e.g. a PDF), every absolute offset
stored in the central directory and EOCD must increase by N.
"""

from __future__ import annotations

import struct
import zipfile
import io


# ─────────────────────────────────────────────────────────────────────────────
# Signatures
# ─────────────────────────────────────────────────────────────────────────────

LOCAL_SIG   = b"PK\x03\x04"
CD_SIG      = b"PK\x01\x02"
EOCD_SIG    = b"PK\x05\x06"
EOCD64_SIG  = b"PK\x06\x06"   # ZIP64 EOCD (future support)

# Minimum EOCD size (no comment): 22 bytes
EOCD_MIN_SIZE  = 22
# Maximum EOCD comment length: 65535 bytes
EOCD_MAX_COMMENT = 65535


# ─────────────────────────────────────────────────────────────────────────────
# EOCD helpers
# ─────────────────────────────────────────────────────────────────────────────

def find_eocd_offset(data: bytes | bytearray) -> int:
    """
    Return the byte offset of the EOCD signature by scanning backward
    from the physical end of the file.

    Raises ValueError if no valid EOCD is found.
    """
    search_start = max(0, len(data) - EOCD_MIN_SIZE - EOCD_MAX_COMMENT)
    pos = len(data) - EOCD_MIN_SIZE

    while pos >= search_start:
        if data[pos : pos + 4] == EOCD_SIG:
            # Verify the comment length field matches remaining bytes.
            comment_len = struct.unpack_from("<H", data, pos + 20)[0]
            if pos + EOCD_MIN_SIZE + comment_len == len(data):
                return pos
        pos -= 1

    raise ValueError(
        "Cannot locate EOCD signature — is this a valid ZIP?"
    )


def read_eocd(data: bytes | bytearray, eocd_offset: int) -> dict:
    """Parse the EOCD record at eocd_offset into a dict."""
    (
        _sig,
        disk_num,
        disk_start,
        records_on_disk,
        total_records,
        cd_size,
        cd_offset,
        comment_len,
    ) = struct.unpack_from("<4sHHHHIIH", data, eocd_offset)

    comment = data[
        eocd_offset + EOCD_MIN_SIZE :
        eocd_offset + EOCD_MIN_SIZE + comment_len
    ]

    return {
        "offset":         eocd_offset,
        "disk_num":       disk_num,
        "disk_start":     disk_start,
        "records_on_disk": records_on_disk,
        "total_records":  total_records,
        "cd_size":        cd_size,
        "cd_offset":      cd_offset,
        "comment_len":    comment_len,
        "comment":        bytes(comment),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Offset patching — the core of prepend polyglot support
# ─────────────────────────────────────────────────────────────────────────────

def patch_offsets(zip_bytes: bytes, prepend_size: int) -> bytes:
    """
    Return a copy of zip_bytes with all absolute offsets incremented
    by prepend_size.

    Two offset fields need patching:
      1. Each central-directory entry's "relative offset of local header"
         (CD entry offset + 42, little-endian uint32).
      2. The EOCD's "offset of start of central directory"
         (EOCD offset + 16, little-endian uint32).

    After patching, prepending exactly prepend_size bytes to the result
    produces a file whose ZIP parser can locate all structures correctly.
    """
    if prepend_size == 0:
        return zip_bytes

    data = bytearray(zip_bytes)
    eocd_off = find_eocd_offset(data)
    eocd = read_eocd(data, eocd_off)

    cd_offset  = eocd["cd_offset"]
    cd_size    = eocd["cd_size"]

    # ── 1. Patch every central directory entry ────────────────────────
    pos = cd_offset
    cd_end = cd_offset + cd_size

    while pos < cd_end:
        if data[pos : pos + 4] != CD_SIG:
            break   # Unexpected — stop rather than corrupt the file

        filename_len = struct.unpack_from("<H", data, pos + 28)[0]
        extra_len    = struct.unpack_from("<H", data, pos + 30)[0]
        comment_len  = struct.unpack_from("<H", data, pos + 32)[0]

        # Relative offset of local file header is at CD entry byte 42.
        old_local_off = struct.unpack_from("<I", data, pos + 42)[0]
        struct.pack_into("<I", data, pos + 42, old_local_off + prepend_size)

        pos += 46 + filename_len + extra_len + comment_len

    # ── 2. Patch the EOCD central directory offset ────────────────────
    struct.pack_into("<I", data, eocd_off + 16, cd_offset + prepend_size)

    return bytes(data)


def patch_offsets_and_tail(zip_bytes: bytes, prepend_size: int, tail_size: int = 0) -> bytes:
    """
    Patch central directory offsets by prepend_size, and optionally patch
    the EOCD comment length to account for trailing bytes (e.g. when the ZIP
    is embedded inside a host format before image scan data).
    """
    patched = patch_offsets(zip_bytes, prepend_size)
    if 0 < tail_size <= EOCD_MAX_COMMENT:
        data = bytearray(patched)
        eocd_off = find_eocd_offset(data)
        struct.pack_into("<H", data, eocd_off + 20, tail_size)
        return bytes(data)
    return patched


# ─────────────────────────────────────────────────────────────────────────────
# Validation helper
# ─────────────────────────────────────────────────────────────────────────────

def is_valid_zip(data: bytes) -> tuple[bool, str]:
    """
    Return (True, "") if data parses as a valid ZIP, else (False, reason).
    Uses Python's stdlib zipfile for authoritative validation.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            bad = zf.testzip()
            if bad:
                return False, f"CRC/size error in entry: {bad}"
        return True, ""
    except zipfile.BadZipFile as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"Unexpected error: {exc}"
