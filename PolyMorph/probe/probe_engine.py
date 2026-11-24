"""
Probe Engine
============
Orchestrates all probes for a given format + sample file.

Updated workflow
----------------
1. If explicit validator= is given → use it, skip auto-detection.
2. Otherwise → AutoDetector.detect() resolves the best validator
   (Tier 1 structural, Tier 2 python-magic, or Tier 3 magic-byte).
3. Validate unmodified sample. Abort if invalid.
4. Run AppendProbe and PrependProbe. Confidence is capped at the
   detector's tier confidence (cannot exceed what the validator supports).
5. Post-probe:
   Verification mode → compare against registered FormatSpec.
   Discovery mode    → generate FormatSpec template.
6. If detection.needs_suggestion AND suggest=True →
   SuggestionEngine fires (web + LLM).
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Callable

from ..core.format_registry import FormatRegistry, FormatSpec
from .auto_detector import AutoDetector
from .probe_result import (
    Confidence,
    DetectionResult,
    Divergence,
    ProbeReport,
    SuggestionResult,
)
from .probes.append_probe import AppendProbe
from .probes.prepend_probe import PrependProbe
from .probes.base_probe import Validator


class ProbeEngine:
    """Coordinates auto-detection, probing, and result assembly."""

    _UPDATE_THRESHOLD = Confidence.MEDIUM

    @classmethod
    def run(
        cls,
        fmt: str,
        sample_path: Path,
        validator: Validator | None = None,
        magic_bytes: bytes | None = None,
        suggest: bool = False,
        preferred_llm: str | None = None,
    ) -> ProbeReport:
        """
        Parameters
        ----------
        fmt           : Format name (registered or new).
        sample_path   : Path to a sample file of this format.
        validator     : Explicit validator callable — skips auto-detection.
        magic_bytes   : Hex bytes for Tier 3 override (rarely needed).
        suggest       : If True and format is unknown, run SuggestionEngine.
        preferred_llm : LLM provider preference for SuggestionEngine.
        """

        # ── Read sample ───────────────────────────────────────────────
        try:
            sample = sample_path.read_bytes()
        except OSError as exc:
            return ProbeReport(
                format_name=fmt,
                sample_path=str(sample_path),
                sample_size_bytes=0,
                sample_valid=False,
                error=f"Cannot read sample file: {exc}",
            )

        # ── Resolve mode and validator ────────────────────────────────
        if validator is not None:
            # Explicit validator supplied — skip auto-detection.
            # Check registry for mode, but don't require it.
            spec_exists = fmt in FormatRegistry.all_names()
            mode = "verification" if spec_exists else "discovery"
            resolved_validator = validator
            detection = None
        else:
            # Auto-detection path.
            detection = AutoDetector.detect(sample, fmt)
            spec_exists = fmt in FormatRegistry.all_names()
            mode = "verification" if spec_exists else "discovery"

            if magic_bytes is not None and detection.validator_tier < 2:
                # User supplied magic bytes as override — use Tier 3.
                from .auto_detector import AutoDetector as AD
                resolved_validator = AD._tier3_validator(
                    magic_bytes  # type: ignore[attr-defined]
                )
            else:
                resolved_validator = detection.validator

        # ── Validate unmodified sample ────────────────────────────────
        sample_valid, sample_detail = resolved_validator(sample)

        report = ProbeReport(
            format_name=fmt,
            sample_path=str(sample_path),
            sample_size_bytes=len(sample),
            sample_valid=sample_valid,
            mode=mode,
            detection=detection,
        )

        if not sample_valid:
            report.error = (
                f"Sample failed {fmt} validation before probing: "
                f"{sample_detail}\n"
                f"Provide a valid {fmt.upper()} file."
            )
            return report

        # ── Run probes ────────────────────────────────────────────────
        append_probe  = AppendProbe(fmt, resolved_validator)
        prepend_probe = PrependProbe(fmt, resolved_validator)

        report.append_result  = append_probe.run(sample)
        report.prepend_result = prepend_probe.run(sample)

        # Cap confidence at detector tier limits.
        if detection is not None:
            cls._apply_confidence_cap(report, detection)

        # ── Post-probe processing ─────────────────────────────────────
        if mode == "verification":
            spec = FormatRegistry.get(fmt)
            cls._compare(report, spec)
        else:
            cls._generate_spec_template(report, detection)

        # ── SuggestionEngine ──────────────────────────────────────────
        if suggest and detection is not None and detection.needs_suggestion:
            from .suggestion_engine.engine import SuggestionEngine
            report.suggestion = SuggestionEngine.run(
                format_description=detection.description or fmt,
                mime_type=detection.mime_type,
                preferred_llm=preferred_llm,
            )

        return report

    # ── Registry update ───────────────────────────────────────────────

    @classmethod
    def apply(cls, report: ProbeReport) -> FormatSpec | None:
        if not report.suggested_updates:
            return None

        if report.mode == "verification":
            spec = FormatRegistry.get(report.format_name)
            current = {
                f.name: getattr(spec, f.name)
                for f in dataclasses.fields(spec)
            }
            current.update(report.suggested_updates)
            current["probe_verified"] = True
            updated = FormatSpec(**current)

        else:
            kwargs: dict = {}
            for f in dataclasses.fields(FormatSpec):
                if f.default is not dataclasses.MISSING:
                    kwargs[f.name] = f.default
                elif f.default_factory is not dataclasses.MISSING:      # type: ignore[misc]
                    kwargs[f.name] = f.default_factory()                 # type: ignore[misc]

            kwargs.setdefault("name",        report.format_name)
            kwargs.setdefault("extensions",  ())
            kwargs.setdefault("mime_types",  ())
            kwargs.setdefault("magic_bytes", ())
            kwargs.update(report.suggested_updates)
            kwargs["probe_verified"] = True
            updated = FormatSpec(**kwargs)

        FormatRegistry.register(updated)
        return updated

    # ── Validator factory (kept for CLI backward compat) ──────────────

    @staticmethod
    def make_cmd_validator(cmd_template: str) -> Validator:
        """Build a validator from a shell command template with {file}."""
        import subprocess, tempfile, os
        def validate(data: bytes) -> tuple[bool, str]:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            cmd = cmd_template.replace("{file}", tmp_path)
            try:
                proc = subprocess.run(
                    cmd, shell=True, capture_output=True,
                    text=True, timeout=10,
                )
                passed = proc.returncode == 0
                detail = (proc.stdout or proc.stderr or "").strip()[:200]
                return passed, detail
            except subprocess.TimeoutExpired:
                return False, "Validator command timed out (10s)."
            except Exception as exc:
                return False, f"Validator command error: {exc}"
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        return validate

    # ── Confidence capping ────────────────────────────────────────────

    @staticmethod
    def _apply_confidence_cap(
        report: ProbeReport,
        detection: DetectionResult,
    ) -> None:
        """
        Cap probe confidence at the tier's maximum.
        A Tier 2 validator cannot produce HIGH confidence on AppendProbe.
        """
        if report.append_result and report.append_result.confidence == Confidence.HIGH:
            if detection.append_confidence != Confidence.HIGH:
                report.append_result.confidence = detection.append_confidence
                report.append_result.notes += (
                    f" [Confidence capped to {detection.append_confidence.value} "
                    f"— validator tier {detection.validator_tier}: "
                    f"{detection.validator_source}]"
                )

        if report.prepend_result and report.prepend_result.confidence == Confidence.HIGH:
            if detection.prepend_confidence != Confidence.HIGH:
                report.prepend_result.confidence = detection.prepend_confidence
                report.prepend_result.notes += (
                    f" [Confidence capped to {detection.prepend_confidence.value} "
                    f"— validator tier {detection.validator_tier}]"
                )

    # ── Verification mode ─────────────────────────────────────────────

    @classmethod
    def _compare(cls, report: ProbeReport, spec: FormatSpec) -> None:
        if report.append_result is not None:
            ar = report.append_result
            cls._check_field(report, spec, "append_tolerant",
                             ar.append_tolerant, ar.confidence)
            cls._check_field(report, spec, "checksum_covers_append",
                             ar.checksum_covers_append, ar.confidence)
        if report.prepend_result is not None:
            pr = report.prepend_result
            cls._check_field(report, spec, "prepend_tolerant",
                             pr.prepend_tolerant, pr.confidence)
            cls._check_field(report, spec, "max_prepend_bytes",
                             pr.max_prepend_bytes, pr.confidence)

    @classmethod
    def _check_field(
        cls,
        report: ProbeReport,
        spec: FormatSpec,
        field_name: str,
        measured: object,
        confidence: Confidence,
    ) -> None:
        if measured is None:
            return
        registered = getattr(spec, field_name)
        if measured != registered:
            report.divergences.append(Divergence(
                field_name=field_name,
                registered_value=registered,
                measured_value=measured,
                confidence=confidence,
            ))
        if confidence in (Confidence.HIGH, Confidence.MEDIUM):
            report.suggested_updates[field_name] = measured

    # ── Discovery mode ────────────────────────────────────────────────

    @classmethod
    def _generate_spec_template(
        cls,
        report: ProbeReport,
        detection: DetectionResult | None,
    ) -> None:
        ar = report.append_result
        pr = report.prepend_result

        template: dict[str, object] = {"name": report.format_name}

        if detection:
            if detection.mime_type:
                template["mime_types"] = (detection.mime_type,)
            if detection.validator_tier == 1:
                # Only include magic_bytes if we have a structural match.
                pass  # magic bytes come from the registry/index, not here

        if ar is not None and ar.confidence in (Confidence.HIGH, Confidence.MEDIUM):
            if ar.append_tolerant is not None:
                template["append_tolerant"] = ar.append_tolerant
            if ar.checksum_covers_append is not None:
                template["checksum_covers_append"] = ar.checksum_covers_append

        if pr is not None and pr.confidence in (Confidence.HIGH, Confidence.MEDIUM):
            if pr.prepend_tolerant is not None:
                template["prepend_tolerant"] = pr.prepend_tolerant
            if pr.max_prepend_bytes is not None:
                template["max_prepend_bytes"] = pr.max_prepend_bytes

        report.suggested_updates = template
