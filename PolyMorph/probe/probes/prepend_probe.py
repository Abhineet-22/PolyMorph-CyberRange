"""
Prepend Probe
=============
Empirically determines two FormatSpec fields:

  prepend_tolerant  — does the format's parser accept arbitrary bytes
                      inserted before its own content?

  max_prepend_bytes — the maximum number of leading bytes the parser
                      tolerates before failing. -1 means unlimited.

How it works
------------
1. Prepend garbage bytes of increasing sizes BEFORE the sample.
2. Validate at each size using the real parser.
3. Find the boundary between passing and failing:
     - Pass at all sizes up to MAX_PROBE → max_prepend_bytes = -1
     - Fail at 1 byte → max_prepend_bytes = 0, prepend_tolerant = False
     - Pass up to N, fail at N+1 → max_prepend_bytes = N

Probe strategy
--------------
We use a two-pass approach:

Pass 1 — threshold scan at meaningful fixed sizes:
    1, 8, 64, 128, 256, 512, 1024, 4096, 16384, 65536

This quickly identifies:
  - Formats with zero tolerance (fail at 1)
  - Formats with spec-defined limits (PDF: ~1024)
  - Formats with unlimited tolerance (ZIP: pass at 65536)

Pass 2 — boundary refinement (linear scan in [last_pass, first_fail]):
Runs only when Pass 1 finds a finite boundary. Finds the exact
maximum tolerated prepend size byte-by-byte within a 128-byte window
around the boundary.

Confidence
----------
HIGH        — clear pass/fail boundary found
MEDIUM      — boundary found but within a mixed zone
LOW         — single-test result (e.g. fails at 1 byte, no further info)
INCONCLUSIVE — all tests failed (sample may be invalid itself)
"""

from __future__ import annotations

from ..probe_result import (
    Confidence,
    PrependProbeResult,
    SingleProbeResult,
)
from .base_probe import BaseProbe


# Pass 1: fixed threshold sizes (bytes).
_THRESHOLDS = (1, 8, 64, 128, 256, 512, 1024, 4096, 16384, 65536)

# Maximum size we consider "unlimited" — if tolerant at this, report -1.
_UNLIMITED_THRESHOLD = 65536

# Pass 2: max window for boundary refinement (bytes).
_REFINE_WINDOW = 128


class PrependProbe(BaseProbe):
    """Tests prepend_tolerant and max_prepend_bytes."""

    def run(self, sample: bytes) -> PrependProbeResult:

        # ── Pass 1: threshold scan ────────────────────────────────────
        tests: list[SingleProbeResult] = []
        last_pass: int | None = None
        first_fail: int | None = None

        for size in _THRESHOLDS:
            garbage  = self._make_garbage(size)
            modified = garbage + sample
            passed, detail = self._validate(modified)

            tests.append(SingleProbeResult(
                name="prepend",
                probe_size=size,
                passed=passed,
                detail=detail,
            ))

            if passed:
                last_pass = size
            elif first_fail is None:
                first_fail = size

            # Stop scanning once we've confirmed failure — no point
            # testing larger sizes if smaller ones already fail.
            if first_fail is not None and last_pass is not None:
                # We've bracketed the boundary. Stop threshold scan.
                break
            if first_fail is not None and last_pass is None:
                # Failed at the very first probe. Zero tolerance.
                break

        # ── Classify Pass 1 result ────────────────────────────────────

        # Case A: tolerant at every threshold up to and including 65536.
        if last_pass == _UNLIMITED_THRESHOLD and first_fail is None:
            return PrependProbeResult(
                prepend_tolerant=True,
                max_prepend_bytes=-1,
                confidence=Confidence.HIGH,
                tests=tests,
                notes=(
                    f"Parser accepted up to {_UNLIMITED_THRESHOLD} prepended bytes. "
                    "Reporting as unlimited (-1). Likely scans from end of file."
                ),
            )

        # Case B: failed at 1 byte — zero tolerance.
        if first_fail == _THRESHOLDS[0] and last_pass is None:
            return PrependProbeResult(
                prepend_tolerant=False,
                max_prepend_bytes=0,
                confidence=Confidence.HIGH,
                tests=tests,
                notes=(
                    "Parser rejected 1 prepended byte. "
                    "Format requires magic bytes at exact offset."
                ),
            )

        # Case C: all tests failed (sample may be invalid).
        if last_pass is None and first_fail is not None:
            return PrependProbeResult(
                prepend_tolerant=None,
                max_prepend_bytes=None,
                confidence=Confidence.INCONCLUSIVE,
                tests=tests,
                notes=(
                    "All prepend probe sizes failed. "
                    "Verify that the sample file itself is valid before probing."
                ),
            )

        # Case D: finite boundary found. Refine it.
        if last_pass is not None and first_fail is not None:
            exact_max, refine_tests = self._refine_boundary(
                sample, last_pass, first_fail
            )
            tests.extend(refine_tests)
            return PrependProbeResult(
                prepend_tolerant=True,
                max_prepend_bytes=exact_max,
                confidence=Confidence.HIGH,
                tests=tests,
                notes=(
                    f"Parser tolerates up to {exact_max} prepended bytes. "
                    f"Fails at {exact_max + 1} bytes. "
                    f"Boundary refined between {last_pass}–{first_fail} bytes."
                ),
            )

        # Fallback — should not normally be reached.
        return PrependProbeResult(
            prepend_tolerant=None,
            max_prepend_bytes=None,
            confidence=Confidence.INCONCLUSIVE,
            tests=tests,
            notes="Probe produced ambiguous results.",
        )

    # ── Pass 2: boundary refinement ───────────────────────────────────

    def _refine_boundary(
        self,
        sample: bytes,
        last_pass: int,
        first_fail: int,
    ) -> tuple[int, list[SingleProbeResult]]:
        """
        Linear scan between [last_pass, first_fail] to find the exact
        maximum tolerated prepend size.

        Caps refinement at _REFINE_WINDOW bytes of scan range to avoid
        spending excessive time on very wide boundaries.
        """
        tests: list[SingleProbeResult] = []
        scan_range = first_fail - last_pass

        if scan_range > _REFINE_WINDOW:
            # Range too wide for full linear scan.
            # Do a mini binary search instead.
            lo, hi = last_pass, first_fail
            while hi - lo > 1:
                mid = (lo + hi) // 2
                garbage  = self._make_garbage(mid)
                modified = garbage + sample
                passed, detail = self._validate(modified)
                tests.append(SingleProbeResult(
                    name="prepend_refine",
                    probe_size=mid,
                    passed=passed,
                    detail=detail,
                ))
                if passed:
                    lo = mid
                else:
                    hi = mid
            return lo, tests

        # Full linear scan within the window.
        current_max = last_pass
        for size in range(last_pass + 1, first_fail):
            garbage  = self._make_garbage(size)
            modified = garbage + sample
            passed, detail = self._validate(modified)
            tests.append(SingleProbeResult(
                name="prepend_refine",
                probe_size=size,
                passed=passed,
                detail=detail,
            ))
            if passed:
                current_max = size
            else:
                break

        return current_max, tests
