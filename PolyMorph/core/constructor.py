"""
Constructor
===========
Top-level orchestrator. Accepts file paths + format names, delegates
to the CombinationEngine, runs the chosen strategy, and validates
the output against both constituent formats before returning.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .combination_engine import CombinationEngine
from .format_registry import PolyStrategy
from ..strategies.base import StrategyResult
from ..validation.format_validator import FormatValidator, ValidationResult


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolyglotResult:
    """
    Complete result of a polyglot construction attempt.
    Consumed by the CLI renderer and (later) the API layer.
    """
    success: bool
    fmt_a: str
    fmt_b: str
    strategy: str
    data: bytes = field(repr=False, default=b"")
    size_bytes: int = 0
    sha256: str = ""
    validation_a: ValidationResult | None = None
    validation_b: ValidationResult | None = None
    notes: str = ""
    error: str = ""
    both_valid: bool = False

    def __post_init__(self) -> None:
        if self.data:
            self.size_bytes = len(self.data)
            self.sha256 = hashlib.sha256(self.data).hexdigest()
        if self.validation_a and self.validation_b:
            self.both_valid = (
                self.validation_a.valid and self.validation_b.valid
            )


# ─────────────────────────────────────────────────────────────────────────────
# Constructor
# ─────────────────────────────────────────────────────────────────────────────

class Constructor:
    """
    Constructs a polyglot file from two input files.

    Usage
    -----
        result = Constructor.build(
            file_a=Path("document.pdf"),
            file_b=Path("archive.zip"),
            fmt_a="pdf",
            fmt_b="zip",
        )
        if result.both_valid:
            output_path.write_bytes(result.data)
    """

    @classmethod
    def build(
        cls,
        file_a: Path,
        file_b: Path,
        fmt_a: str,
        fmt_b: str,
        force_strategy: str | None = None,
        skip_validation: bool = False,
    ) -> PolyglotResult:
        """
        Build a polyglot and validate it.

        Parameters
        ----------
        file_a           : Path to the host file (format A).
        file_b           : Path to the payload file (format B).
        fmt_a            : Format name for file_a (e.g. "pdf").
        fmt_b            : Format name for file_b (e.g. "zip").
        force_strategy   : Override auto-strategy selection.
        skip_validation  : Skip post-construction validation (faster,
                           not recommended for final output).
        """

        # ── Read input files ──────────────────────────────────────────
        try:
            data_a = file_a.read_bytes()
        except OSError as exc:
            return cls._error(fmt_a, fmt_b, f"Cannot read {file_a}: {exc}")

        try:
            data_b = file_b.read_bytes()
        except OSError as exc:
            return cls._error(fmt_a, fmt_b, f"Cannot read {file_b}: {exc}")

        # ── Select strategy ───────────────────────────────────────────
        try:
            strategy, chosen_enum, spec_a, spec_b = CombinationEngine.select(
                fmt_a, fmt_b, force_strategy
            )
        except (ValueError, KeyError, NotImplementedError) as exc:
            return cls._error(fmt_a, fmt_b, str(exc))

        # ── Execute strategy ──────────────────────────────────────────
        result: StrategyResult = strategy.execute(data_a, data_b, spec_a, spec_b)

        if not result.success:
            return cls._error(fmt_a, fmt_b, result.error, chosen_enum.value)

        # ── Validate output ───────────────────────────────────────────
        val_a = val_b = None
        if not skip_validation:
            val_a, val_b = FormatValidator.validate_both(
                result.data,
                spec_a.validator or fmt_a,
                spec_b.validator or fmt_b,
            )

        return PolyglotResult(
            success=True,
            fmt_a=fmt_a,
            fmt_b=fmt_b,
            strategy=chosen_enum.value,
            data=result.data,
            validation_a=val_a,
            validation_b=val_b,
            notes=result.notes,
        )

    # ── Internal helpers ──────────────────────────────────────────────

    @staticmethod
    def _error(
        fmt_a: str,
        fmt_b: str,
        error: str,
        strategy: str = "unknown",
    ) -> PolyglotResult:
        return PolyglotResult(
            success=False,
            fmt_a=fmt_a,
            fmt_b=fmt_b,
            strategy=strategy,
            error=error,
        )
