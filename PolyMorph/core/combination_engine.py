"""
Combination Engine
==================
Given a (format_a, format_b) pair, the CombinationEngine:
  1. Consults the FormatRegistry for viable strategies.
  2. Selects the highest-priority strategy (or the one the user forced).
  3. Instantiates and returns the right Strategy object.

This is the reasoning layer that makes PolyMorph a framework rather
than a bag of format-specific scripts.
"""

from __future__ import annotations

from ..core.format_registry import FormatRegistry, FormatSpec, PolyStrategy
from ..strategies.base import BaseStrategy
from ..strategies.append import AppendStrategy
from ..strategies.inject import InjectStrategy


# ─────────────────────────────────────────────────────────────────────────────
# Strategy registry
# ─────────────────────────────────────────────────────────────────────────────

# Maps PolyStrategy enum values to concrete strategy classes.
# New strategies (PREPEND, NEST) are registered here as they land.

_STRATEGY_CLASSES: dict[PolyStrategy, type[BaseStrategy]] = {
    PolyStrategy.APPEND: AppendStrategy,
    PolyStrategy.INJECT: InjectStrategy,
}


# ─────────────────────────────────────────────────────────────────────────────
# CombinationEngine
# ─────────────────────────────────────────────────────────────────────────────

class CombinationEngine:
    """
    Selects the optimal construction strategy for a format pair and
    returns an instantiated, ready-to-call strategy object.
    """

    @classmethod
    def select(
        cls,
        fmt_a: str,
        fmt_b: str,
        force_strategy: str | None = None,
    ) -> tuple[BaseStrategy, PolyStrategy, FormatSpec, FormatSpec]:
        """
        Return (strategy_instance, chosen_strategy_enum, spec_a, spec_b).

        Parameters
        ----------
        fmt_a          : Name of the host format (e.g. "pdf").
        fmt_b          : Name of the payload format (e.g. "zip").
        force_strategy : If provided, override auto-selection with this
                         strategy name (e.g. "append").

        Raises
        ------
        ValueError  — No viable strategy exists for the pair, or the
                      forced strategy is not viable for this pair.
        KeyError    — One or both format names are not registered.
        """

        spec_a = FormatRegistry.get(fmt_a)
        spec_b = FormatRegistry.get(fmt_b)
        viable = FormatRegistry.viable_strategies(fmt_a, fmt_b)

        if not viable:
            raise ValueError(
                f"No viable polyglot construction strategy exists for "
                f"'{fmt_a}' + '{fmt_b}'.\n"
                f"  {fmt_a}: append_tolerant={spec_a.append_tolerant}, "
                f"has_comment={spec_a.has_comment_field}, "
                f"is_container={spec_a.is_container}\n"
                f"  {fmt_b}: prepend_tolerant={spec_b.prepend_tolerant}, "
                f"scans_from_end={spec_b.scans_from_end}"
            )

        if force_strategy:
            try:
                forced_enum = PolyStrategy(force_strategy.lower())
            except ValueError:
                valid = [s.value for s in PolyStrategy]
                raise ValueError(
                    f"Unknown strategy '{force_strategy}'. Valid: {valid}"
                )

            if forced_enum not in viable:
                raise ValueError(
                    f"Strategy '{force_strategy}' is not viable for "
                    f"'{fmt_a}' + '{fmt_b}'. "
                    f"Viable strategies: {[s.value for s in viable]}"
                )
            chosen = forced_enum

        else:
            # Auto-select: first in the viable list is highest priority.
            chosen = viable[0]

        strategy_class = _STRATEGY_CLASSES.get(chosen)
        if strategy_class is None:
            raise NotImplementedError(
                f"Strategy '{chosen.value}' is theoretically viable for this "
                f"pair but has not been implemented yet. "
                f"Implemented strategies: "
                f"{[s.value for s in _STRATEGY_CLASSES]}"
            )

        return strategy_class(), chosen, spec_a, spec_b

    @classmethod
    def list_viable(cls, fmt_a: str, fmt_b: str) -> str:
        """Return a human-readable viability report for a format pair."""
        return FormatRegistry.describe_pair(fmt_a, fmt_b)
