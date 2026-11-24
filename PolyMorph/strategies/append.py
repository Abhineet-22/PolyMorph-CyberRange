"""
Append Strategy
===============
Appends Format B after Format A's logical EOF marker.

Supports any format pair where:
  - Format A is append_tolerant (parser ignores bytes after its EOF)
  - Format B scans_from_end OR is prepend_tolerant

Normalizers registered for format A:
  pdf   — trims after %%EOF
  jpeg  — trims after FF D9 (EOI)
  png   — trims after IEND chunk
  gif   — trims after 0x3B trailer
  html  — strips trailing whitespace (no binary EOF)

Offset patchers registered for format B:
  zip   — patches EOCD and CD entry offsets by +len(host)
  docx  — same (ZIP-based container)
  jar   — same (ZIP-based container)
"""

from __future__ import annotations

from collections.abc import Callable

from ..core.format_registry import FormatSpec
from ..formats import pdf  as pdf_fmt
from ..formats import jpeg as jpeg_fmt
from ..formats import png  as png_fmt
from ..formats import gif  as gif_fmt
from ..formats import html as html_fmt
from ..formats import zip_fmt
from .base import BaseStrategy, StrategyResult


class AppendStrategy(BaseStrategy):
    name = "append"

    # Job A normalizers — one per append-tolerant host format.
    # Each callable: (bytes) -> bytes
    _NORMALISE: dict[str, Callable[[bytes], bytes]] = {
        "pdf":  pdf_fmt.normalize,
        "jpeg": jpeg_fmt.normalize,
        "png":  png_fmt.normalize,
        "gif":  gif_fmt.normalize,
        "html": html_fmt.normalize,
    }

    # Offset patchers — for payload formats that store absolute offsets.
    # Each callable: (bytes, int) -> bytes
    _PATCH_OFFSETS: dict[str, Callable[[bytes, int], bytes]] = {
        "zip":  zip_fmt.patch_offsets,
        "docx": zip_fmt.patch_offsets,
        "jar":  zip_fmt.patch_offsets,
    }

    def execute(
        self,
        data_a: bytes,
        data_b: bytes,
        spec_a: FormatSpec,
        spec_b: FormatSpec,
    ) -> StrategyResult:

        fmt_a, fmt_b = spec_a.name, spec_b.name

        # ── Pre-flight checks ─────────────────────────────────────────
        if not spec_a.append_tolerant:
            return StrategyResult(
                False, b"", fmt_a, fmt_b, self.name,
                error=f"{fmt_a} is not append-tolerant — its parser does "
                      f"not ignore bytes after its EOF marker.",
            )
        if not (spec_b.scans_from_end or spec_b.prepend_tolerant):
            return StrategyResult(
                False, b"", fmt_a, fmt_b, self.name,
                error=f"{fmt_b} is neither scan-from-end nor prepend-tolerant "
                      f"— it cannot serve as format B in an APPEND polyglot.",
            )

        # ── Step 1: Normalize host (format A) ─────────────────────────
        normalise_fn = self._NORMALISE.get(fmt_a)
        try:
            host = normalise_fn(data_a) if normalise_fn else data_a
        except ValueError as exc:
            return StrategyResult(
                False, b"", fmt_a, fmt_b, self.name,
                error=f"Normalization of {fmt_a} failed: {exc}",
            )

        # ── Step 2: Patch payload offsets (format B) ──────────────────
        patch_fn = self._PATCH_OFFSETS.get(fmt_b)
        try:
            payload = (
                patch_fn(data_b, len(host))
                if patch_fn and spec_b.requires_offset_patch
                else data_b
            )
        except ValueError as exc:
            return StrategyResult(
                False, b"", fmt_a, fmt_b, self.name,
                error=f"Offset patching of {fmt_b} failed: {exc}",
            )

        # ── Step 3: Concatenate ───────────────────────────────────────
        polyglot = host + payload
        return StrategyResult(
            True, polyglot, fmt_a, fmt_b, self.name,
            notes=(
                f"Host ({fmt_a}): {len(host):,} B  |  "
                f"Payload ({fmt_b}): {len(payload):,} B  |  "
                f"Total: {len(polyglot):,} B"
            ),
        )
