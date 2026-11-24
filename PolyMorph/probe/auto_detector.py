"""
Auto Detector
=============
Identifies an unknown file format and resolves the best available
validator for it — without requiring any user input.

Detection flow
--------------
Step 1  python-magic
        Authoritative format identification. Returns MIME type and a
        human-readable description backed by 5000+ signatures.
        If python-magic is not installed → fall back to Tier 3.

Step 2  FormatRegistry match
        Does the detected MIME / description match a registered format?
        If yes → use its structural validator (Tier 1, HIGH confidence).

Step 3  ParserIndex match
        Is the format in the curated index?
          Available    → structural validator (Tier 1, HIGH confidence).
          Not installed → note install hint, fall back to Tier 2.
          Not in index → needs_suggestion = True, fall back to Tier 2.

Step 4  Tier fallback
        Tier 2: python-magic validator (AppendProbe=LOW, PrependProbe=MEDIUM)
        Tier 3: magic-byte check      (both LOW — only when python-magic
                                       is unavailable)

Confidence semantics
--------------------
append_confidence:
  Tier 1 → HIGH   (structural parser exercises the full file)
  Tier 2 → LOW    (libmagic reads from start; appended bytes invisible)
  Tier 3 → LOW    (magic-byte check at offset 0 only)

prepend_confidence:
  Tier 1 → HIGH
  Tier 2 → MEDIUM (libmagic detects displaced magic correctly)
  Tier 3 → MEDIUM (magic-byte check at offset 0 detects displacement)
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.format_registry import FormatRegistry
from ..validation.format_validator import FormatValidator
from .parser_index import ParserIndex, ParserEntry
from .probe_result import Confidence, DetectionResult
from .probes.base_probe import Validator


class AutoDetector:
    """
    Identifies a file format from raw bytes and returns the best
    available Validator along with confidence metadata.
    """

    @classmethod
    def detect(
        cls,
        sample: bytes,
        fmt_hint: str,
    ) -> DetectionResult:
        """
        Parameters
        ----------
        sample   : Raw bytes of the file to identify.
        fmt_hint : Format name provided by the user (e.g. "elf").
                   Used as an additional matching signal alongside
                   python-magic identification.

        Returns
        -------
        DetectionResult with the best available validator and
        confidence metadata.
        """

        # ── Step 1: python-magic identification ───────────────────────
        mime_type, description = cls._run_magic(sample)
        magic_available = mime_type != ""

        # ── Step 2: FormatRegistry match ──────────────────────────────
        registry_validator = cls._check_registry(
            fmt_hint, mime_type, description, sample
        )
        if registry_validator is not None:
            return DetectionResult(
                format_hint=fmt_hint,
                mime_type=mime_type,
                description=description,
                validator=registry_validator,
                validator_tier=1,
                validator_source="FormatRegistry",
                append_confidence=Confidence.HIGH,
                prepend_confidence=Confidence.HIGH,
                parser_known=True,
                parser_available=True,
                install_hint=None,
                needs_suggestion=False,
            )

        # ── Step 3: ParserIndex match ─────────────────────────────────
        entry = ParserIndex.find(fmt_hint, mime_type, description)

        if entry is not None:
            if entry.is_available():
                return DetectionResult(
                    format_hint=fmt_hint,
                    mime_type=mime_type,
                    description=description,
                    validator=entry.make_validator(),
                    validator_tier=1,
                    validator_source=f"ParserIndex:{entry.python_lib or entry.cli_tool}",
                    append_confidence=Confidence.HIGH,
                    prepend_confidence=Confidence.HIGH,
                    parser_known=True,
                    parser_available=True,
                    install_hint=None,
                    needs_suggestion=False,
                )
            else:
                # Known format, parser just not installed.
                # Fall through to Tier 2 but note what to install.
                return DetectionResult(
                    format_hint=fmt_hint,
                    mime_type=mime_type,
                    description=description,
                    validator=cls._tier2_validator(mime_type)
                    if magic_available
                    else cls._tier3_validator(sample),
                    validator_tier=2 if magic_available else 3,
                    validator_source=(
                        "python-magic (fallback — parser not installed)"
                        if magic_available
                        else "magic-byte check (fallback)"
                    ),
                    append_confidence=Confidence.LOW,
                    prepend_confidence=Confidence.MEDIUM,
                    parser_known=True,
                    parser_available=False,
                    install_hint=entry.install_hint(),
                    needs_suggestion=False,
                )

        # ── Step 4: Completely unknown ────────────────────────────────
        return DetectionResult(
            format_hint=fmt_hint,
            mime_type=mime_type,
            description=description,
            validator=cls._tier2_validator(mime_type)
            if magic_available
            else cls._tier3_validator(sample),
            validator_tier=2 if magic_available else 3,
            validator_source=(
                "python-magic (no structural parser available)"
                if magic_available
                else "magic-byte check (python-magic not installed)"
            ),
            append_confidence=Confidence.LOW,
            prepend_confidence=Confidence.MEDIUM,
            parser_known=False,
            parser_available=False,
            install_hint=(
                "pip install python-magic"
                if not magic_available
                else None
            ),
            needs_suggestion=True,
        )

    # ── Internal helpers ──────────────────────────────────────────────

    @staticmethod
    def _run_magic(sample: bytes) -> tuple[str, str]:
        """
        Run python-magic and return (mime_type, description).
        Returns ("", "") if python-magic is not installed.
        """
        try:
            import magic
            mime        = magic.from_buffer(sample, mime=True) or ""
            description = magic.from_buffer(sample) or ""
            return mime, description
        except ImportError:
            return "", ""
        except Exception:
            return "", ""

    @staticmethod
    def _check_registry(
        fmt_hint: str,
        mime_type: str,
        description: str,
        sample: bytes,
    ) -> Validator | None:
        """
        Check if any registered FormatSpec matches the detected format.
        Returns a validator if a match is found, else None.
        """
        for name in FormatRegistry.all_names():
            spec = FormatRegistry.get(name)

            # Match by format name hint
            if name == fmt_hint.lower():
                val_key = spec.validator or name
                def make_val(k=val_key):
                    def v(data: bytes) -> tuple[bool, str]:
                        r = FormatValidator.validate(data, k)
                        return r.valid, r.detail
                    return v
                return make_val()

            # Match by MIME type
            if mime_type and any(
                mime_type in m for m in spec.mime_types
            ):
                val_key = spec.validator or name
                def make_val(k=val_key):
                    def v(data: bytes) -> tuple[bool, str]:
                        r = FormatValidator.validate(data, k)
                        return r.valid, r.detail
                    return v
                return make_val()

            # Match by magic bytes
            for magic_seq in spec.magic_bytes:
                offset = spec.magic_offset
                if sample[offset: offset + len(magic_seq)] == magic_seq:
                    val_key = spec.validator or name
                    def make_val(k=val_key):
                        def v(data: bytes) -> tuple[bool, str]:
                            r = FormatValidator.validate(data, k)
                            return r.valid, r.detail
                        return v
                    return make_val()

        return None

    @staticmethod
    def _tier2_validator(expected_mime: str) -> Validator:
        """
        Build a python-magic validator.
        Reliable for PrependProbe (magic displaced → detected).
        Unreliable for AppendProbe (magic unchanged → false positive).
        """
        def validate(data: bytes) -> tuple[bool, str]:
            try:
                import magic as libmagic
                actual_mime = libmagic.from_buffer(data, mime=True)
                desc        = libmagic.from_buffer(data)
                # Consider valid if the base MIME type family matches.
                # e.g. "application/x-elf" matches "application/x-elf"
                base_expected = expected_mime.split("/")[0]
                base_actual   = (actual_mime or "").split("/")[0]
                passed = base_actual == base_expected
                return passed, f"python-magic: {desc} [{actual_mime}]"
            except Exception as exc:
                return False, f"python-magic error: {exc}"
        return validate

    @staticmethod
    def _tier3_validator(sample: bytes) -> Validator:
        """
        Build a magic-byte presence validator from the first 16 bytes
        of the sample. Used only when python-magic is unavailable.
        """
        magic_bytes = sample[:16]
        magic_len   = len(magic_bytes)

        def validate(data: bytes) -> tuple[bool, str]:
            if data[:magic_len] == magic_bytes:
                return True, f"magic-byte check: {magic_bytes.hex()} at offset 0"
            found = data[:magic_len].hex()
            return False, (
                f"magic-byte mismatch: expected {magic_bytes.hex()}, "
                f"found {found}"
            )
        return validate
