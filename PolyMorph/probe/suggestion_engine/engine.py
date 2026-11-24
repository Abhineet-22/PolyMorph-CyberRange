"""
Suggestion Engine
=================
Orchestrates web search and LLM query for completely unknown formats.
Only called when:
  1. No structural validator found in FormatRegistry or ParserIndex.
  2. User explicitly passed --suggest on the CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .web_search import search as web_search
from .llm_provider import LLMResult, query as llm_query
from ..probe_result import SuggestionResult, WebResult


class SuggestionEngine:
    """
    Combines web search and LLM results into a single SuggestionResult.
    """

    @classmethod
    def run(
        cls,
        format_description: str,
        mime_type: str,
        preferred_llm: str | None = None,
        max_web_results: int = 5,
    ) -> SuggestionResult:
        """
        Parameters
        ----------
        format_description : Human-readable description from libmagic.
        mime_type          : MIME type string.
        preferred_llm      : LLM provider preference (optional).
        max_web_results    : Maximum web results to include.
        """

        # Run both in sequence. Neither is allowed to crash the other.
        web_results: list[WebResult] = []
        try:
            web_results = web_search(
                format_description, mime_type, max_web_results
            )
        except Exception as exc:
            web_error = str(exc)
        else:
            web_error = "" if web_results else "No results found."

        llm_result: LLMResult | None = None
        try:
            llm_result = llm_query(
                format_description, mime_type, preferred_llm
            )
        except Exception as exc:
            llm_result = None
            llm_error = str(exc)
        else:
            llm_error = llm_result.error if llm_result else ""

        return SuggestionResult(
            web_results=web_results,
            llm_suggestions=llm_result.suggestions if llm_result else [],
            llm_provider=(
                f"{llm_result.provider} / {llm_result.model}"
                if llm_result and llm_result.provider
                else ""
            ),
            error=" | ".join(filter(None, [web_error, llm_error])),
        )
