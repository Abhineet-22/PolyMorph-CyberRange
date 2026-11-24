"""
Base strategy interface
=======================
Every construction strategy inherits from BaseStrategy and implements
execute(). The constructor calls execute() without knowing which
specific strategy is running.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..core.format_registry import FormatSpec


@dataclass
class StrategyResult:
    """Result returned by every strategy's execute() method."""
    success: bool
    data: bytes                  # The polyglot bytes (empty on failure)
    fmt_a: str
    fmt_b: str
    strategy: str
    size_bytes: int = 0
    notes: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        if self.success:
            self.size_bytes = len(self.data)


class BaseStrategy(ABC):
    """Abstract base class for all polyglot construction strategies."""

    name: str = "base"

    @abstractmethod
    def execute(
        self,
        data_a: bytes,
        data_b: bytes,
        spec_a: FormatSpec,
        spec_b: FormatSpec,
    ) -> StrategyResult:
        """
        Construct and return the polyglot bytes for the (A, B) pair.

        Parameters
        ----------
        data_a : bytes   Raw bytes of the first (host) file.
        data_b : bytes   Raw bytes of the second (payload) file.
        spec_a : FormatSpec  Registry entry for format A.
        spec_b : FormatSpec  Registry entry for format B.

        Returns
        -------
        StrategyResult with success=True and the polyglot in .data,
        or success=False with an error description.
        """
        ...
