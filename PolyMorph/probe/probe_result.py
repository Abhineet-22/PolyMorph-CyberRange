"""
Probe Result
============
Dataclasses that carry the output of each individual probe and the
aggregated ProbeEngine report for a single format + sample pair.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Any


class Confidence(Enum):
    """
    How confident the probe engine is in a measured value.

    HIGH         — structural parser; multiple probe sizes agreed.
    MEDIUM       — python-magic prepend result, or limited probe sizes.
    LOW          — python-magic append result (unreliable by design) or
                   single magic-byte check.
    INCONCLUSIVE — probe could not determine a value.
    """
    HIGH         = "high"
    MEDIUM       = "medium"
    LOW          = "low"
    INCONCLUSIVE = "inconclusive"


@dataclass
class SingleProbeResult:
    """Result of one atomic probe test (one property, one probe size)."""
    name:       str
    probe_size: int
    passed:     bool
    detail:     str = ""


@dataclass
class AppendProbeResult:
    """Aggregated result of the append probe run."""
    append_tolerant:        bool | None = None
    checksum_covers_append: bool | None = None
    confidence: Confidence = Confidence.INCONCLUSIVE
    tests: list[SingleProbeResult] = field(default_factory=list)
    notes: str = ""


@dataclass
class PrependProbeResult:
    """Aggregated result of the prepend probe run."""
    prepend_tolerant:  bool | None = None
    max_prepend_bytes: int  | None = None
    confidence: Confidence = Confidence.INCONCLUSIVE
    tests: list[SingleProbeResult] = field(default_factory=list)
    notes: str = ""


@dataclass
class ChecksumProbeResult:
    """Result of the internal checksum detection probe."""
    has_internal_checksum: bool | None = None
    confidence: Confidence = Confidence.INCONCLUSIVE
    notes: str = ""


@dataclass
class Divergence:
    """Mismatch between a probe-measured value and the registered FormatSpec."""
    field_name:       str
    registered_value: object
    measured_value:   object
    confidence:       Confidence

    def __str__(self) -> str:
        return (
            f"{self.field_name}: "
            f"registered={self.registered_value!r} "
            f"measured={self.measured_value!r} "
            f"[{self.confidence.value} confidence]"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Detection result (produced by AutoDetector)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """
    Format identification result and resolved validator from AutoDetector.

    validator_tier semantics
    ------------------------
    1 — structural parser (FormatRegistry or ParserIndex, installed)
        AppendProbe=HIGH, PrependProbe=HIGH
    2 — python-magic (Tier 2 fallback)
        AppendProbe=LOW, PrependProbe=MEDIUM
    3 — magic-byte check (python-magic not installed)
        AppendProbe=LOW, PrependProbe=MEDIUM
    """
    format_hint:        str
    mime_type:          str
    description:        str
    validator:          Any           # Callable[[bytes], tuple[bool, str]]
    validator_tier:     int           # 1, 2, or 3
    validator_source:   str           # human-readable source description
    append_confidence:  Confidence
    prepend_confidence: Confidence
    parser_known:       bool          # format is in the parser index
    parser_available:   bool          # parser is installed and ready
    install_hint:       str | None    # what to install if not available
    needs_suggestion:   bool          # SuggestionEngine should fire


# ─────────────────────────────────────────────────────────────────────────────
# Suggestion result (produced by SuggestionEngine)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WebResult:
    title:   str
    url:     str
    snippet: str
    score:   int = 0


@dataclass
class LLMSuggestion:
    name:          str
    type:          str    # "python_lib" | "cli_tool" | "both"
    install:       str
    validator_cmd: str
    reliability:   str    # "high" | "medium" | "low"
    notes:         str


@dataclass
class SuggestionResult:
    """Combined output of web search + LLM query."""
    web_results:     list[WebResult]     = field(default_factory=list)
    llm_suggestions: list[LLMSuggestion] = field(default_factory=list)
    llm_provider:    str = ""
    error:           str = ""


# ─────────────────────────────────────────────────────────────────────────────
# ProbeReport (top-level report produced by ProbeEngine)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProbeReport:
    """
    Complete probe report for a single format + sample file.
    Produced by ProbeEngine.run() and consumed by the CLI renderer.
    """

    format_name:       str
    sample_path:       str
    sample_size_bytes: int
    sample_valid:      bool

    mode: str = "verification"
    # "verification" — format registered; values compared against spec.
    # "discovery"    — format unregistered; template generated instead.

    detection:      DetectionResult   | None = None
    append_result:  AppendProbeResult | None = None
    prepend_result: PrependProbeResult| None = None
    checksum_result:ChecksumProbeResult|None = None
    suggestion:     SuggestionResult  | None = None

    divergences:       list[Divergence]   = field(default_factory=list)
    suggested_updates: dict[str, object]  = field(default_factory=dict)

    error: str = ""
