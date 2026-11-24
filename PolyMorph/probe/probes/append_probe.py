"""
Append Probe
============
Empirically determines two FormatSpec fields:

  append_tolerant       — does the format's parser accept bytes appended
                          after the logical EOF marker?

  checksum_covers_append — when it rejects appended bytes, is the failure
                           a checksum/CRC error (vs a structural error)?

How it works
------------
1. Locate the logical EOF marker in the sample (if known).
2. Append garbage bytes of increasing sizes AFTER the EOF marker.
3. Attempt to validate the modified file with the real parser.
4. Classify the result:
     pass  → append_tolerant = True
     fail (checksum error) → append_tolerant = False,
                              checksum_covers_append = True
     fail (other error)    → append_tolerant = False,
                              checksum_covers_append = False

Probe sizes
-----------
We test multiple sizes because some parsers have a tolerance window
(e.g. accept up to 512 appended bytes but reject more).
If ALL sizes pass → HIGH confidence. If sizes disagree → MEDIUM.
"""

from __future__ import annotations

from ..probe_result import (
    AppendProbeResult,
    Confidence,
    SingleProbeResult,
)
from .base_probe import BaseProbe


# Probe sizes in bytes — chosen to cover: tiny, small, medium, large.
_APPEND_SIZES = (16, 128, 512, 4096)

# Checksum error keywords (case-insensitive).
_CHECKSUM_KEYWORDS = ("crc", "checksum", "integrity", "corrupt", "hash")


class AppendProbe(BaseProbe):
    """Tests append_tolerant and checksum_covers_append."""

    def run(self, sample: bytes) -> AppendProbeResult:
        tests: list[SingleProbeResult] = []
        checksum_failures: list[bool] = []

        for size in _APPEND_SIZES:
            garbage  = self._make_garbage(size)
            modified = sample + garbage
            passed, detail = self._validate(modified)

            tests.append(SingleProbeResult(
                name="append",
                probe_size=size,
                passed=passed,
                detail=detail,
            ))

            if not passed:
                checksum_failures.append(self._is_checksum_error(detail))

        # ── Aggregate ─────────────────────────────────────────────────
        pass_count = sum(1 for t in tests if t.passed)
        fail_count = len(tests) - pass_count

        # append_tolerant: True if every probe size passed.
        if pass_count == len(tests):
            append_tolerant = True
            checksum_covers_append = False
            confidence = Confidence.HIGH
            notes = f"Parser accepted appended bytes at all {len(tests)} probe sizes."

        elif fail_count == len(tests):
            append_tolerant = False
            # checksum_covers_append: True if ALL failures were checksum errors.
            checksum_covers_append = all(checksum_failures)
            confidence = Confidence.HIGH
            failure_type = (
                "checksum/CRC failures"
                if checksum_covers_append
                else "structural format errors"
            )
            notes = (
                f"Parser rejected appended bytes at all {len(tests)} probe sizes "
                f"with {failure_type}."
            )

        else:
            # Mixed results — some sizes passed, some failed.
            # This suggests a size-dependent tolerance window.
            append_tolerant = None   # inconclusive: partially tolerant
            checksum_covers_append = (
                all(checksum_failures) if checksum_failures else None
            )
            confidence = Confidence.MEDIUM
            notes = (
                f"Mixed results: {pass_count} sizes passed, {fail_count} failed. "
                f"Parser may have a tolerance window. "
                f"Passing sizes: "
                f"{[t.probe_size for t in tests if t.passed]} bytes."
            )

        return AppendProbeResult(
            append_tolerant=append_tolerant,
            checksum_covers_append=checksum_covers_append,
            confidence=confidence,
            tests=tests,
            notes=notes,
        )
