"""
Inject Strategy
===============
Embeds Format B's payload inside Format A's internal comment, metadata,
or ancillary chunk structures.

Unlike AppendStrategy, the payload does NOT sit after Format A's logical
EOF marker. Instead, it is housed within Format A's internal byte stream,
allowing it to survive trailing-byte stripping or truncation filters.

Supported Host Formats (Format A):
  - jpeg : Injected into COM (FF FE) marker segment(s)
  - png  : Injected into tEXt ancillary chunk with automated CRC32
  - gif  : Injected into GIF89a Comment Extension (21 FE) sub-blocks
  - html : Injected into HTML comments (<!-- ... -->)
  - pdf  : Injected into PDF comments prior to startxref

Supported Payload Formats (Format B):
  - zip / docx / jar : Automatically patches local/central directory offsets
                       and EOCD comment length to handle trailing host bytes.
  - html / scripts / raw payloads: Embedded directly.
"""

from __future__ import annotations

from collections.abc import Callable

from ..core.format_registry import FormatSpec
from ..formats import pdf as pdf_fmt
from ..formats import jpeg as jpeg_fmt
from ..formats import png as png_fmt
from ..formats import gif as gif_fmt
from ..formats import html as html_fmt
from ..formats import zip_fmt
from .base import BaseStrategy, StrategyResult


class InjectStrategy(BaseStrategy):
    name = "inject"

    # Host normalizers (optional pre-cleaning to strip trailing garbage)
    _NORMALISE: dict[str, Callable[[bytes], bytes]] = {
        "pdf":  pdf_fmt.normalize,
        "jpeg": jpeg_fmt.normalize,
        "png":  png_fmt.normalize,
        "gif":  gif_fmt.normalize,
        "html": html_fmt.normalize,
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
        if not (spec_a.has_comment_field or spec_a.has_metadata_block):
            return StrategyResult(
                False, b"", fmt_a, fmt_b, self.name,
                error=f"{fmt_a} does not expose a comment field or metadata block "
                      f"for payload injection.",
            )

        if not spec_b.viable_as_payload:
            return StrategyResult(
                False, b"", fmt_a, fmt_b, self.name,
                error=f"{fmt_b} is marked as not viable as a payload.",
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

        # ── Step 2: Prepare payload (including offset patching if needed)
        payload = data_b
        requires_patch = spec_b.requires_offset_patch

        try:
            if fmt_a == "jpeg":
                if requires_patch and len(payload) > jpeg_fmt.MAX_COM_PAYLOAD:
                    return StrategyResult(
                        False, b"", fmt_a, fmt_b, self.name,
                        error=f"Payload size ({len(payload):,} B) exceeds single JPEG COM "
                              f"segment limit ({jpeg_fmt.MAX_COM_PAYLOAD:,} B). "
                              f"Use 'append' strategy for multi-segment archives.",
                    )

                insert_pos = jpeg_fmt.find_injection_offset(host)
                prefix_len = insert_pos + 4   # 2 bytes FF FE + 2 bytes length
                tail_len = len(host) - insert_pos

                if requires_patch:
                    payload = zip_fmt.patch_offsets_and_tail(payload, prefix_len, tail_len)

                polyglot, offset = jpeg_fmt.inject_payload(host, payload)
                loc_desc = f"JPEG COM segment @ offset {insert_pos}"

            elif fmt_a == "png":
                insert_pos = png_fmt.find_injection_offset(host)
                keyword = b"Comment"
                # Chunk layout: 4B len + 4B type + len(kw) + 1B null + payload + 4B CRC
                prefix_len = insert_pos + 4 + 4 + len(keyword) + 1
                tail_len = 4 + (len(host) - insert_pos)  # CRC (4B) + rest of PNG chunks

                if requires_patch:
                    payload = zip_fmt.patch_offsets_and_tail(payload, prefix_len, tail_len)

                polyglot, offset = png_fmt.inject_payload(host, payload, keyword=keyword)
                loc_desc = f"PNG tEXt chunk @ offset {insert_pos}"

            elif fmt_a == "gif":
                if requires_patch and len(payload) > 255:
                    return StrategyResult(
                        False, b"", fmt_a, fmt_b, self.name,
                        error=f"ZIP payload size ({len(payload):,} B) exceeds single GIF "
                              f"sub-block limit (255 B). GIF sub-block boundaries disrupt "
                              f"archive structure. Use 'append' strategy.",
                    )

                insert_pos = gif_fmt.find_injection_offset(host)
                prefix_len = insert_pos + 2 + 1   # 2B intro (21 FE) + 1B len
                tail_len = 1 + (len(host) - insert_pos)  # 1B terminator (00) + rest of GIF

                if requires_patch:
                    payload = zip_fmt.patch_offsets_and_tail(payload, prefix_len, tail_len)

                polyglot, offset = gif_fmt.inject_payload(host, payload)
                loc_desc = f"GIF89a Comment Extension @ offset {insert_pos}"

            elif fmt_a == "html":
                insert_pos = html_fmt.find_injection_offset(host)
                prefix_str = b"<!-- "
                suffix_str = b" -->\n"
                prefix_len = insert_pos + len(prefix_str)
                tail_len = len(suffix_str) + (len(host) - insert_pos)

                if requires_patch:
                    payload = zip_fmt.patch_offsets_and_tail(payload, prefix_len, tail_len)

                polyglot, offset = html_fmt.inject_payload(host, payload)
                loc_desc = f"HTML comment block @ offset {insert_pos}"

            elif fmt_a == "pdf":
                if requires_patch:
                    return StrategyResult(
                        False, b"", fmt_a, fmt_b, self.name,
                        error=f"Embedding offset-sensitive format '{fmt_b}' inside PDF comments "
                              f"is not supported. Use 'append' strategy.",
                    )

                polyglot, offset = pdf_fmt.inject_payload(host, payload)
                loc_desc = f"PDF comment stream"

            else:
                return StrategyResult(
                    False, b"", fmt_a, fmt_b, self.name,
                    error=f"Injection handler for host format '{fmt_a}' is not implemented.",
                )

        except Exception as exc:
            return StrategyResult(
                False, b"", fmt_a, fmt_b, self.name,
                error=f"Injection failed: {exc}",
            )

        return StrategyResult(
            True, polyglot, fmt_a, fmt_b, self.name,
            notes=(
                f"Payload ({fmt_b}, {len(payload):,} B) injected into {loc_desc}  |  "
                f"Host ({fmt_a}): {len(host):,} B  |  "
                f"Total: {len(polyglot):,} B"
            ),
        )
