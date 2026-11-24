"""
Base Probe
==========
Abstract base class shared by all probes.

Key design decision — validator injection
-----------------------------------------
The validator is a plain callable  (bytes) -> (bool, str)  injected at
construction time. This decouples probes entirely from the FormatRegistry:
any callable that accepts raw bytes and returns a (passed, detail) tuple
can be used, whether it is a registered FormatValidator backend, a
subprocess call to an external tool, or a simple magic-byte check.

This is what enables Discovery mode — probing formats that have no
registered FormatSpec at all.

Provides
--------
  _validate()         — calls the injected validator
  _make_garbage()     — builds recognisable probe garbage of N bytes
  _is_checksum_error() — detects CRC/integrity failure in error strings
  PROBE_MARKER        — shared constant for garbage identification
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable


# ─────────────────────────────────────────────────────────────────────────────
# Type alias
# ─────────────────────────────────────────────────────────────────────────────

# A validator is any callable that takes raw bytes and returns
# (passed: bool, detail: str). No registry dependency.
Validator = Callable[[bytes], tuple[bool, str]]


# ─────────────────────────────────────────────────────────────────────────────
# Shared constants
# ─────────────────────────────────────────────────────────────────────────────

# Recognisable marker that starts every probe garbage payload.
# Chosen to be:
#   - ASCII-printable (visible in hex dumps and strings output)
#   - Not a valid magic sequence for any registered format
#   - Identifiable at a glance during forensic analysis
PROBE_MARKER = b"[PMPROBE]"

# Keywords that indicate a checksum / integrity failure in parser output.
_CHECKSUM_KEYWORDS = (
    "crc",
    "checksum",
    "integrity",
    "hash",
    "corrupt",
    "invalid data",
)


# ─────────────────────────────────────────────────────────────────────────────
# BaseProbe
# ─────────────────────────────────────────────────────────────────────────────

class BaseProbe(ABC):
    """
    Abstract base class for all format property probes.

    Parameters
    ----------
    fmt       : Format name being probed (e.g. "pdf", "elf").
    validator : Callable (bytes) -> (bool, str) used to test whether a
                modified file is still accepted by the format's parser.
                Injected externally — no registry dependency here.
    """

    def __init__(self, fmt: str, validator: Validator) -> None:
        self.fmt        = fmt
        self._validator = validator

    # ── Shared helpers ────────────────────────────────────────────────

    def _validate(self, data: bytes) -> tuple[bool, str]:
        """
        Validate data using the injected validator.
        Returns (passed: bool, detail: str).
        """
        return self._validator(data)

    def _make_garbage(self, size: int) -> bytes:
        """
        Build a garbage payload of exactly `size` bytes.
        Always starts with PROBE_MARKER so probe bytes are identifiable
        in hex dumps. Remainder uses a repeating non-null pattern to
        avoid looking like innocuous zero-padding to entropy scanners.
        """
        if size <= 0:
            return b""
        if size <= len(PROBE_MARKER):
            return PROBE_MARKER[:size]
        remainder = size - len(PROBE_MARKER)
        filler = (b"\xAA\xBB\xCC\xDD" * ((remainder // 4) + 1))[:remainder]
        return PROBE_MARKER + filler

    @staticmethod
    def _is_checksum_error(detail: str) -> bool:
        """
        Return True if the parser's response string indicates a checksum
        or integrity failure rather than a structural format error.
        """
        lower = detail.lower()
        return any(kw in lower for kw in _CHECKSUM_KEYWORDS)

    @abstractmethod
    def run(self, sample: bytes) -> object:
        """
        Execute the probe against `sample` (the unmodified file bytes).
        Returns a probe-specific result dataclass.
        """
        ...
