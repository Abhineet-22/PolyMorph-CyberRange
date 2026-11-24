"""
Format Registry
===============
The knowledge base of every format PolyMorph understands.

Each FormatSpec captures the *parsing contract* of a format — where its
parser starts reading, what it tolerates, where it stops, what injection
points it exposes, and metadata the evasion and probe engines need.

The CombinationEngine consults this registry to derive viable construction
strategies for any requested format pair.
"""

from __future__ import annotations

import json
import dataclasses
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# Strategy enum
# ─────────────────────────────────────────────────────────────────────────────

class PolyStrategy(Enum):
    """
    APPEND  — Format B appended after Format A's logical EOF marker.
              A's parser stops at its EOF; B's parser finds its structure
              by scanning from the physical end of the file.

    PREPEND — Format A's header/content prepended before Format B.
              B's parser tolerates leading bytes it doesn't recognise.

    INJECT  — Format B's payload embedded inside Format A's comment or
              metadata field. A's parser reads past it as opaque data.

    NEST    — Format B placed as a named entry inside Format A's
              container structure (ZIP-based: DOCX, JAR, APK …).
    """
    APPEND  = "append"
    PREPEND = "prepend"
    INJECT  = "inject"
    NEST    = "nest"


# ─────────────────────────────────────────────────────────────────────────────
# FormatSpec
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FormatSpec:
    """
    Immutable descriptor of a file format's parsing contract.

    Fields are grouped into seven concerns:
      1. Identity          — what the format is
      2. Parsing contract  — how parsers locate and read the format
      3. Integrity         — whether the format has internal checksums
      4. Injection points  — where foreign data can be hidden
      5. Role capability   — whether this format can be a host or payload
      6. Evasion profile   — expected entropy range for anomaly scoring
      7. Empirical state   — whether properties are asserted or probe-verified
    """

    # ── 1. Identity ───────────────────────────────────────────────────
    name: str
    # Canonical short name used throughout PolyMorph ("pdf", "zip", …)

    extensions: tuple[str, ...]
    # File extensions associated with this format, including the dot.

    mime_types: tuple[str, ...]
    # Official IANA MIME type(s) for this format.

    magic_bytes: tuple[bytes, ...]
    # One or more valid magic byte sequences that identify the format.

    magic_offset: int = 0
    # Byte offset at which magic_bytes must appear.

    category: str = ""
    # Broad format category: "document" | "image" | "archive" |
    # "executable" | "audio" | "video" | "other"

    # ── 2. Parsing contract ───────────────────────────────────────────
    append_tolerant: bool = False
    # True → parser ignores bytes after its logical EOF marker.
    # Examples: PDF (after %%EOF), JPEG (after FF D9), PNG (after IEND).

    prepend_tolerant: bool = False
    # True → parser works when arbitrary bytes precede its own content.
    # Example: ZIP (EOCD found by scanning backward from physical EOF).

    max_prepend_bytes: int = 0
    # Maximum leading bytes most parsers tolerate before failing.
    # 0 = either zero tolerance or not yet empirically measured.
    # -1 = unlimited (parser imposes no upper bound, e.g. ZIP).

    eof_markers: tuple[bytes, ...] = ()
    # Byte sequences that mark the logical end of the format's content.

    scans_from_end: bool = False
    # True → primary structure locator scans *backward* from the
    # physical end of the file (ZIP's EOCD search is canonical).

    requires_offset_patch: bool = False
    # True → prepending N bytes requires patching internal absolute-
    # offset fields by +N (e.g. ZIP central directory offsets).

    # ── 3. Integrity ──────────────────────────────────────────────────
    has_internal_checksum: bool = False
    # True → format stores CRC/hash values over part of its content.

    checksum_covers_append: bool = False
    # True → appending bytes after the EOF marker invalidates the
    # checksum, making APPEND polyglots detectable by strict validators.
    # Example: gzip CRC32 covers the entire compressed stream.
    # Counter-example: ZIP CRC32 is per-entry and does not cover the
    # EOCD or any appended bytes.

    # ── 4. Injection points ───────────────────────────────────────────
    has_comment_field: bool = False
    # True → format defines a structured comment/metadata field that
    # accepts arbitrary bytes without breaking the parser.

    comment_max_bytes: int = 0
    # Capacity of the comment field in bytes. 0 = unlimited.

    has_metadata_block: bool = False
    # True → format has a dedicated metadata section (EXIF, APP markers,
    # XMP, ID3 tags …) that can carry foreign payloads.

    injection_offsets: tuple[int, ...] = ()
    # Fixed byte offsets in the format structure where a foreign payload
    # can be inserted without moving subsequent structures.
    # Empty tuple = no known fixed injection points.

    is_container: bool = False
    # True → format is a container that stores named sub-files
    # (ZIP-based: DOCX, JAR, APK, EPUB …).

    # ── 5. Role capability ────────────────────────────────────────────
    viable_as_host: bool = True
    # True → format can act as Format A (the outer wrapper) in a
    # polyglot construction. Typically requires append_tolerant=True,
    # has_comment_field=True, or is_container=True.

    viable_as_payload: bool = True
    # True → format can act as Format B (the embedded payload).
    # Typically requires scans_from_end=True or prepend_tolerant=True.

    # ── 6. Evasion profile ────────────────────────────────────────────
    typical_entropy_range: tuple[float, float] = (0.0, 8.0)
    # Expected Shannon entropy range (bits per byte) for legitimate
    # files of this format. Used by the evasion scorer to flag anomalous
    # entropy in polyglot output. Range: 0.0 (uniform) to 8.0 (random).

    # ── 7. Empirical state ────────────────────────────────────────────
    probe_verified: bool = False
    # False → parsing contract values are asserted from format
    #         specification knowledge (the current state of all builtins).
    # True  → values have been empirically confirmed by the probe engine
    #         against real parser binaries on the current platform.

    parser_notes: dict[str, str] | None = None
    # Per-parser behaviour notes keyed by parser/tool name.
    # None = not yet characterised.
    # Example: {"adobe_reader": "tolerant", "pdfium": "strict after v90"}

    known_polyglot_uses: tuple[str, ...] = ()
    # Documented real-world or research uses of this format in polyglots.
    # Example: ("GIFAR attack", "PDF+ZIP upload bypass")

    # ── Validation backend key ─────────────────────────────────────────
    validator: str = ""
    # Key used by FormatValidator to select the right parsing library.

    notes: str = ""
    # Free-text notes for human readers.


# ─────────────────────────────────────────────────────────────────────────────
# FormatRegistry
# ─────────────────────────────────────────────────────────────────────────────

class FormatRegistry:
    """
    Central registry mapping format names to FormatSpec instances.

    All built-in formats are registered at module-load time via
    _register_builtins(). External callers can add formats at runtime
    with register(), which the probe engine will use to write back
    empirically verified specs.
    """

    _formats: dict[str, FormatSpec] = {}
    _builtins: set[str] = set()
    CUSTOM_FORMATS_FILE = Path(__file__).resolve().parent.parent / "custom_formats.json"

    # ── CRUD ──────────────────────────────────────────────────────────

    @classmethod
    def register(cls, spec: FormatSpec) -> None:
        """Register or replace a FormatSpec."""
        cls._formats[spec.name] = spec
        cls._save_custom_formats()

    @classmethod
    def register_builtin(cls, spec: FormatSpec) -> None:
        """Register a built-in format."""
        cls._formats[spec.name] = spec
        cls._builtins.add(spec.name)

    @classmethod
    def _save_custom_formats(cls) -> None:
        data = {}
        for name, spec in cls._formats.items():
            if name in cls._builtins:
                continue
            spec_dict = dataclasses.asdict(spec)
            # Encode bytes to hex
            spec_dict["magic_bytes"] = [b.hex() for b in spec.magic_bytes]
            spec_dict["eof_markers"] = [b.hex() for b in spec.eof_markers]
            data[name] = spec_dict
        
        if data:
            cls.CUSTOM_FORMATS_FILE.parent.mkdir(parents=True, exist_ok=True)
            cls.CUSTOM_FORMATS_FILE.write_text(json.dumps(data, indent=2))

    @classmethod
    def _load_custom_formats(cls) -> None:
        if not cls.CUSTOM_FORMATS_FILE.exists():
            return
        
        try:
            data = json.loads(cls.CUSTOM_FORMATS_FILE.read_text())
            for name, spec_dict in data.items():
                # Decode hex back to bytes
                spec_dict["magic_bytes"] = tuple(bytes.fromhex(h) for h in spec_dict.get("magic_bytes", []))
                spec_dict["eof_markers"] = tuple(bytes.fromhex(h) for h in spec_dict.get("eof_markers", []))
                
                # Convert list to tuple for sequences
                for key, val in spec_dict.items():
                    if isinstance(val, list):
                        spec_dict[key] = tuple(val)

                spec = FormatSpec(**spec_dict)
                cls._formats[spec.name] = spec
        except Exception as e:
            print(f"Warning: Failed to load custom formats from {cls.CUSTOM_FORMATS_FILE}: {e}")

    @classmethod
    def get(cls, name: str) -> FormatSpec:
        if name not in cls._formats:
            raise KeyError(
                f"Format '{name}' is not registered. "
                f"Available: {cls.all_names()}"
            )
        return cls._formats[name]

    @classmethod
    def all_names(cls) -> list[str]:
        return sorted(cls._formats.keys())

    @classmethod
    def by_category(cls, category: str) -> list[FormatSpec]:
        return [
            s for s in cls._formats.values()
            if s.category == category
        ]

    # ── Strategy derivation ───────────────────────────────────────────

    @classmethod
    def viable_strategies(cls, fmt_a: str, fmt_b: str) -> list[PolyStrategy]:
        """
        Return a ranked list of viable construction strategies for (A, B).

        Checks role capability first: if A is not viable as a host or B is
        not viable as a payload, no strategy is possible and an empty list
        is returned immediately.

        Ranking: APPEND (most reliable, structural) → PREPEND → INJECT
        (field-size constrained) → NEST (requires container).
        """
        a = cls.get(fmt_a)
        b = cls.get(fmt_b)

        # Role pre-check — fail fast before structural analysis.
        if not a.viable_as_host:
            return []
        if not b.viable_as_payload:
            return []

        strategies: list[PolyStrategy] = []

        # APPEND: A stops at its EOF; B finds its structure from end
        # or tolerates being preceded by A's bytes.
        if a.append_tolerant and (b.scans_from_end or b.prepend_tolerant):
            strategies.append(PolyStrategy.APPEND)

        # PREPEND: B is prepend-tolerant and APPEND doesn't already cover it.
        if b.prepend_tolerant and PolyStrategy.APPEND not in strategies:
            strategies.append(PolyStrategy.PREPEND)

        # INJECT: A exposes a comment or metadata injection point.
        if a.has_comment_field or a.has_metadata_block:
            strategies.append(PolyStrategy.INJECT)

        # NEST: A is a container format.
        if a.is_container:
            strategies.append(PolyStrategy.NEST)

        return strategies

    # ── Descriptions ──────────────────────────────────────────────────

    @classmethod
    def describe_pair(cls, fmt_a: str, fmt_b: str) -> str:
        """Human-readable strategy viability report for a format pair."""
        strategies = cls.viable_strategies(fmt_a, fmt_b)
        a = cls.get(fmt_a)
        b = cls.get(fmt_b)

        lines = [
            f"Pair       : {a.name.upper()} + {b.name.upper()}",
            f"Strategies : {[s.value for s in strategies] or ['none — unsupported pair']}",
        ]

        if not a.viable_as_host:
            lines.append(f"⚠  {a.name} is not viable as a host format.")
        if not b.viable_as_payload:
            lines.append(f"⚠  {b.name} is not viable as a payload format.")

        if PolyStrategy.APPEND in strategies:
            lines.append(
                f"APPEND  : {a.name} ignores bytes after its EOF marker; "
                f"{b.name} locates its structure from the physical end of the file."
            )
        if PolyStrategy.INJECT in strategies:
            cap = f"{a.comment_max_bytes} bytes" if a.comment_max_bytes else "unlimited"
            lines.append(
                f"INJECT  : {a.name} comment/metadata field capacity = {cap}"
            )
        if PolyStrategy.NEST in strategies:
            lines.append(
                f"NEST    : {a.name} is a container — {b.name} can be embedded as an entry."
            )

        return "\n".join(lines)

    @classmethod
    def describe_format(cls, fmt: str) -> str:
        """Human-readable full profile of a single registered format."""
        s = cls.get(fmt)

        verified = (
            "[probe-verified]" if s.probe_verified else "[asserted — not yet probe-verified]"
        )

        checksum_note = ""
        if s.has_internal_checksum:
            checksum_note = (
                f"yes (covers append: {s.checksum_covers_append})"
            )

        injection = []
        if s.has_comment_field:
            cap = f"{s.comment_max_bytes} bytes" if s.comment_max_bytes else "unlimited"
            injection.append(f"comment field ({cap})")
        if s.has_metadata_block:
            injection.append("metadata block")
        if s.injection_offsets:
            injection.append(f"fixed offsets {s.injection_offsets}")
        if s.is_container:
            injection.append("container entries")

        parser_notes_str = ""
        if s.parser_notes:
            parser_notes_str = "\n  ".join(
                f"{k}: {v}" for k, v in s.parser_notes.items()
            )

        polyglot_uses = (
            "\n  - ".join(s.known_polyglot_uses)
            if s.known_polyglot_uses
            else "none documented"
        )

        lines = [
            f"Format         : {s.name.upper()}  {verified}",
            f"Extensions     : {' '.join(s.extensions)}",
            f"MIME types     : {' '.join(s.mime_types)}",
            f"Category       : {s.category}",
            f"Magic bytes    : {[m.hex() for m in s.magic_bytes]} @ offset {s.magic_offset}",
            f"",
            f"Parsing contract",
            f"  append_tolerant   : {s.append_tolerant}",
            f"  prepend_tolerant  : {s.prepend_tolerant}",
            f"  max_prepend_bytes : {s.max_prepend_bytes if s.max_prepend_bytes >= 0 else 'unlimited'}",
            f"  scans_from_end    : {s.scans_from_end}",
            f"  requires_offset_patch: {s.requires_offset_patch}",
            f"  eof_markers       : {[m.hex() for m in s.eof_markers] or 'none'}",
            f"",
            f"Integrity",
            f"  internal_checksum : {checksum_note or 'none'}",
            f"",
            f"Injection points   : {', '.join(injection) or 'none'}",
            f"",
            f"Role capability",
            f"  viable_as_host    : {s.viable_as_host}",
            f"  viable_as_payload : {s.viable_as_payload}",
            f"",
            f"Evasion profile",
            f"  typical_entropy   : {s.typical_entropy_range[0]:.1f} – {s.typical_entropy_range[1]:.1f} bits/byte",
            f"",
            f"Known polyglot uses",
            f"  - {polyglot_uses}",
        ]

        if parser_notes_str:
            lines += [f"", f"Parser notes", f"  {parser_notes_str}"]

        if s.notes:
            lines += [f"", f"Notes", f"  {s.notes}"]

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Built-in format definitions
# ─────────────────────────────────────────────────────────────────────────────

def _register_builtins() -> None:

    # ── PDF ───────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="pdf",
        extensions=(".pdf",),
        mime_types=("application/pdf",),
        magic_bytes=(b"%PDF",),
        magic_offset=0,
        category="document",

        append_tolerant=True,
        prepend_tolerant=False,
        max_prepend_bytes=1024,
        eof_markers=(b"%%EOF",),
        scans_from_end=False,
        requires_offset_patch=False,

        has_internal_checksum=False,
        checksum_covers_append=False,

        has_comment_field=True,
        comment_max_bytes=0,
        has_metadata_block=True,
        injection_offsets=(),
        is_container=False,

        viable_as_host=True,
        viable_as_payload=True,

        typical_entropy_range=(4.0, 7.5),

        probe_verified=False,
        parser_notes={
            "adobe_reader": "tolerant — ignores bytes after %%EOF",
            "pypdf":        "searches for %PDF- in first 2048 bytes",
            "pdfium":       "strict after v90 — rejects files with garbage before %PDF-",
            "poppler":      "tolerant — ignores trailing bytes",
        },
        known_polyglot_uses=(
            "PDF+ZIP upload bypass",
            "PDF+HTML dual-parse content confusion",
            "PDF+JavaScript browser exploit delivery",
        ),

        validator="pypdf",
        notes=(
            "PDF parsers stop at the last %%EOF and discard trailing bytes. "
            "ISO 32000 permits %PDF- anywhere within the first 1024 bytes. "
            "Ideal host format for APPEND polyglots."
        ),
    ))

    # ── ZIP ───────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="zip",
        extensions=(".zip",),
        mime_types=("application/zip", "application/x-zip-compressed"),
        magic_bytes=(b"PK\x03\x04",),
        magic_offset=0,
        category="archive",

        append_tolerant=False,
        prepend_tolerant=True,
        max_prepend_bytes=-1,
        eof_markers=(),
        scans_from_end=True,
        requires_offset_patch=True,

        has_internal_checksum=True,
        checksum_covers_append=False,

        has_comment_field=True,
        comment_max_bytes=65535,
        has_metadata_block=False,
        injection_offsets=(),
        is_container=False,

        viable_as_host=False,
        viable_as_payload=True,

        typical_entropy_range=(7.5, 8.0),

        probe_verified=False,
        parser_notes={
            "python_zipfile": "handles prepended data automatically via EOCD scan",
            "7zip":           "warns about prepended data but extracts cleanly",
            "winrar":         "warns about prepended data but extracts cleanly",
            "windows_explorer": "silent — extracts without warning after offset patch",
            "unzip":          "prints 'extra bytes at beginning' warning, extracts cleanly",
        },
        known_polyglot_uses=(
            "PDF+ZIP — most common polyglot pair",
            "JPEG+ZIP image/archive dual parse",
            "GIFAR variant (GIF+ZIP)",
            "Content-type confusion in upload filters",
        ),

        validator="zipfile",
        notes=(
            "ZIP parsers locate the EOCD by scanning backward from physical EOF. "
            "Prepend-tolerant after central-directory offset patching. "
            "Per-entry CRC32 does not cover prepended data or the EOCD comment. "
            "EOCD comment field accepts up to 65535 bytes of arbitrary data."
        ),
    ))

    # ── JPEG ──────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="jpeg",
        extensions=(".jpg", ".jpeg"),
        mime_types=("image/jpeg",),
        magic_bytes=(b"\xff\xd8\xff",),
        magic_offset=0,
        category="image",

        append_tolerant=True,
        prepend_tolerant=False,
        max_prepend_bytes=0,
        eof_markers=(b"\xff\xd9",),
        scans_from_end=False,
        requires_offset_patch=False,

        has_internal_checksum=False,
        checksum_covers_append=False,

        has_comment_field=True,
        comment_max_bytes=65533,
        has_metadata_block=True,
        injection_offsets=(2,),
        is_container=False,

        viable_as_host=True,
        viable_as_payload=False,

        typical_entropy_range=(7.0, 7.9),

        probe_verified=False,
        parser_notes={
            "pillow":   "strict — requires FF D8 FF at offset 0",
            "libjpeg":  "strict — requires FF D8 FF at offset 0",
            "exiftool": "reads APP markers; tolerant of trailing data after FF D9",
        },
        known_polyglot_uses=(
            "JPEG+ZIP dual-format file",
            "JPEG+PHP upload filter bypass",
            "GIFAR variant using JPEG as host",
        ),

        validator="pillow",
        notes=(
            "JPEG parsers stop at EOI marker (FF D9) and discard trailing bytes. "
            "APP0–APPF and COM segments accept up to 65533 bytes each; "
            "chain multiple segments for payloads larger than 65533 bytes."
        ),
    ))

    # ── GIF ───────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="gif",
        extensions=(".gif",),
        mime_types=("image/gif",),
        magic_bytes=(b"GIF87a", b"GIF89a"),
        magic_offset=0,
        category="image",

        append_tolerant=True,
        prepend_tolerant=False,
        max_prepend_bytes=0,
        eof_markers=(b"\x3b",),
        scans_from_end=False,
        requires_offset_patch=False,

        has_internal_checksum=False,
        checksum_covers_append=False,

        has_comment_field=True,
        comment_max_bytes=0,
        has_metadata_block=False,
        injection_offsets=(6,),
        is_container=False,

        viable_as_host=True,
        viable_as_payload=False,

        typical_entropy_range=(4.5, 7.5),

        probe_verified=False,
        parser_notes={
            "pillow":  "tolerant of trailing bytes after 0x3B trailer",
            "giflib":  "stops at trailer byte; ignores trailing data",
            "browsers": "extremely tolerant of malformed GIF structure",
        },
        known_polyglot_uses=(
            "GIFAR — GIF+JAR attack exploiting Java applet sandbox (CVE context)",
            "GIF+ZIP dual-parse upload bypass",
            "GIF magic bytes pass naive content-type filters while carrying script payload",
        ),

        validator="pillow",
        notes=(
            "GIF parsers stop at the trailer byte (0x3B) and ignore trailing data. "
            "GIF89a Application Extension blocks carry arbitrary binary data via "
            "chained 255-byte sub-blocks — effectively unlimited total capacity. "
            "GIF87a does not support extension blocks."
        ),
    ))

    # ── PNG ───────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="png",
        extensions=(".png",),
        mime_types=("image/png",),
        magic_bytes=(b"\x89PNG\r\n\x1a\n",),
        magic_offset=0,
        category="image",

        append_tolerant=True,
        prepend_tolerant=False,
        max_prepend_bytes=0,
        eof_markers=(b"IEND",),
        scans_from_end=False,
        requires_offset_patch=False,

        has_internal_checksum=True,
        checksum_covers_append=False,

        has_comment_field=True,
        comment_max_bytes=0,
        has_metadata_block=True,
        injection_offsets=(8,),
        is_container=False,

        viable_as_host=True,
        viable_as_payload=False,

        typical_entropy_range=(6.5, 7.8),

        probe_verified=False,
        parser_notes={
            "pillow":  "validates chunk CRCs in verify() mode; tolerates post-IEND bytes",
            "libpng":  "strict chunk CRC validation; ignores bytes after IEND",
            "browsers": "tolerant of post-IEND data; render without error",
        },
        known_polyglot_uses=(
            "PNG+ZIP dual-format upload bypass",
            "PNG tEXt chunk used for data exfiltration in CTF challenges",
        ),

        validator="pillow",
        notes=(
            "PNG parsers stop at the IEND chunk; bytes after it are ignored. "
            "Per-chunk CRC32 fields cover individual chunk data only — not the "
            "file as a whole — so appending after IEND does not break checksums. "
            "tEXt, zTXt, and iTXt ancillary chunks accept unlimited payloads."
        ),
    ))

    # ── HTML ──────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="html",
        extensions=(".html", ".htm"),
        mime_types=("text/html",),
        magic_bytes=(b"<!DOCTYPE", b"<html", b"<HTML"),
        magic_offset=0,
        category="document",

        append_tolerant=True,
        prepend_tolerant=True,
        max_prepend_bytes=-1,
        eof_markers=(),
        scans_from_end=False,
        requires_offset_patch=False,

        has_internal_checksum=False,
        checksum_covers_append=False,

        has_comment_field=True,
        comment_max_bytes=0,
        has_metadata_block=True,
        injection_offsets=(),
        is_container=False,

        viable_as_host=True,
        viable_as_payload=True,

        typical_entropy_range=(3.5, 6.0),

        probe_verified=False,
        parser_notes={
            "chrome":  "extremely tolerant — renders despite arbitrary leading/trailing content",
            "firefox": "extremely tolerant — same as Chrome",
            "curl":    "no parsing — returns raw bytes",
        },
        known_polyglot_uses=(
            "HTML+ZIP content-type confusion in web upload filters",
            "mXSS via polyglot HTML/XML dual-parse",
            "HTML+JavaScript payload delivery past naive scanners",
        ),

        validator="html",
        notes=(
            "HTML has no strict binary structure. Browsers apply error-recovery "
            "heuristics and are tolerant of virtually any leading or trailing "
            "content. HTML comments (<!-- -->) can carry arbitrary binary data "
            "of unlimited size without breaking rendering."
        ),
    ))

    # ── DOCX ──────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="docx",
        extensions=(".docx",),
        mime_types=(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        magic_bytes=(b"PK\x03\x04",),
        magic_offset=0,
        category="document",

        append_tolerant=False,
        prepend_tolerant=True,
        max_prepend_bytes=-1,
        eof_markers=(),
        scans_from_end=True,
        requires_offset_patch=True,

        has_internal_checksum=True,
        checksum_covers_append=False,

        has_comment_field=False,
        comment_max_bytes=0,
        has_metadata_block=True,
        injection_offsets=(),
        is_container=True,

        viable_as_host=True,
        viable_as_payload=True,

        typical_entropy_range=(7.0, 8.0),

        probe_verified=False,
        parser_notes={
            "microsoft_word": "ignores extra ZIP entries not listed in [Content_Types].xml",
            "libreoffice":    "more strict — may warn on unexpected ZIP entries",
        },
        known_polyglot_uses=(
            "DOCX+JAR dual-format file (ZIP container shared)",
            "DOCX container used to smuggle arbitrary file entries past scanners",
        ),

        validator="zipfile",
        notes=(
            "DOCX is an OOXML ZIP container. At the ZIP level it is fully "
            "prepend-tolerant after offset patching. Word's application-layer "
            "parser only validates entries referenced in [Content_Types].xml; "
            "additional ZIP entries are silently ignored."
        ),
    ))

    # ── JAR ───────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="jar",
        extensions=(".jar",),
        mime_types=("application/java-archive",),
        magic_bytes=(b"PK\x03\x04",),
        magic_offset=0,
        category="executable",

        append_tolerant=False,
        prepend_tolerant=True,
        max_prepend_bytes=-1,
        eof_markers=(),
        scans_from_end=True,
        requires_offset_patch=True,

        has_internal_checksum=True,
        checksum_covers_append=False,

        has_comment_field=False,
        comment_max_bytes=0,
        has_metadata_block=True,
        injection_offsets=(),
        is_container=True,

        viable_as_host=True,
        viable_as_payload=True,

        typical_entropy_range=(6.5, 8.0),

        probe_verified=False,
        parser_notes={
            "jvm_hotspot": "locates manifest by entry name; prepended data tolerated after offset patch",
            "7zip":        "extracts all entries regardless of prepended data",
        },
        known_polyglot_uses=(
            "GIFAR — GIF+JAR; Java applet loaded as image URL (historical, pre-SOP enforcement)",
            "JAR+ZIP dual-container file",
        ),

        validator="zipfile",
        notes=(
            "JAR is a ZIP container. The JVM locates META-INF/MANIFEST.MF and "
            "class files by entry name within the ZIP structure; prepended data "
            "and extra entries are tolerated after central-directory offset patching."
        ),
    ))

    # ── SVG ───────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="svg",
        extensions=(".svg",),
        mime_types=("image/svg+xml",),
        magic_bytes=(b"<svg", b"<?xml", b"<!DOCTYPE svg"),
        magic_offset=0,
        category="image",

        append_tolerant=True,
        prepend_tolerant=True,
        max_prepend_bytes=-1,
        eof_markers=(b"</svg>",),
        scans_from_end=False,
        requires_offset_patch=False,

        has_internal_checksum=False,
        checksum_covers_append=False,

        has_comment_field=True,       # <!-- XML comments -->
        comment_max_bytes=0,          # unlimited
        has_metadata_block=True,      # <metadata>, <title>, <desc> elements
        injection_offsets=(),
        is_container=False,

        viable_as_host=True,
        viable_as_payload=True,

        typical_entropy_range=(3.5, 5.5),

        probe_verified=False,
        parser_notes={
            "chrome_blink":  "Full DOM execution in <object>/<embed>/<iframe>/direct navigation; scripts suppressed in <img> context",
            "firefox_gecko": "Same as Chrome — full DOM in browsing contexts, suppressed in <img>",
            "xml_parser":    "Strict XML — CDATA section required for '<', '>', '&' inside <script>",
            "dompurify":     "Strips <script> and event-handler attributes by default — standard SVG sanitizer",
            "svg_sanitize":  "Library-level sanitization required for user-uploaded SVGs serving in origin context",
        },
        known_polyglot_uses=(
            "SVG avatar upload → Stored XSS (HackerOne high-bounty category)",
            "SVG <script> in <object> tag without nosniff/CSP → DOM MIME origin execution",
            "SVG + XML polyglot — valid SVG and valid XHTML simultaneously",
            "SVG onload= event handler XSS in user-generated content platforms",
            "SVG <foreignObject> XHTML embedding for CSP bypass",
        ),

        validator="html",
        notes=(
            "SVG is an XML-based vector image format. Unlike PNG/JPEG/GIF which are "
            "binary raster formats decoded by image pixel pipelines, SVG is parsed as an "
            "XML DOM and supports native <script> elements and event-handler attributes "
            "(onload, onerror, onclick) per the W3C SVG specification. "
            "Scripts execute in the full origin when SVG is loaded in any browsing context "
            "(<object>, <embed>, <iframe>, or direct URL navigation). "
            "Scripts are suppressed ONLY when loaded via <img src=...> (image loading context). "
            "No binary magic bytes — SVG starts with XML text, bypassing binary magic-byte "
            "upload filters trivially. CDATA wrapping required for JS inside XML-parsed <script>."
        ),
    ))

    # ── PHP ───────────────────────────────────────────────────────────
    FormatRegistry.register_builtin(FormatSpec(
        name="php",
        extensions=(".php", ".phtml", ".php5"),
        mime_types=("application/x-httpd-php", "text/x-php", "application/x-php"),
        magic_bytes=(b"<?php", b"<?="),
        magic_offset=0,
        category="script",

        append_tolerant=True,
        prepend_tolerant=True,
        max_prepend_bytes=-1,
        eof_markers=(),
        scans_from_end=False,
        requires_offset_patch=False,

        has_internal_checksum=False,
        checksum_covers_append=False,

        has_comment_field=True,
        comment_max_bytes=0,
        has_metadata_block=False,
        injection_offsets=(),
        is_container=False,

        viable_as_host=True,
        viable_as_payload=True,

        typical_entropy_range=(4.0, 6.0),

        probe_verified=False,
        parser_notes={
            "php_zend": "executes only code inside <?php tags; treats all leading/trailing binary data as raw output",
        },
        known_polyglot_uses=(
            "JPEG+PHP upload filter bypass (LFI to RCE)",
            "GIF+PHP web shell injection",
            "PNG+PHP avatar payload",
        ),

        validator="php",
        notes=(
            "PHP interpreters scan streams for opening script tags (<?php or <?=). "
            "All bytes prior to the opening tag and after the closing tag (?>) are "
            "treated as inert passthrough text, making PHP universally prepend- and "
            "append-tolerant when paired with LFI or CGI sinks."
        ),
    ))


_register_builtins()
FormatRegistry._load_custom_formats()