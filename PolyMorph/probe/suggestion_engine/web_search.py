"""
Web Search
==========
Searches DuckDuckGo for parser/validator recommendations for an
unknown format. Uses three targeted queries to maximise signal quality.

Requires: pip install duckduckgo-search
Gracefully returns an empty list if the library is not installed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..probe_result import WebResult


# Keywords that improve a result's relevance score (case-insensitive).
_RELEVANCE_KEYWORDS = (
    ("python",      2),
    ("pip",         2),
    ("forensic",    2),
    ("parser",      1),
    ("parse",       1),
    ("validate",    1),
    ("validator",   1),
    ("library",     1),
    ("lib",         1),
    ("tool",        1),
    ("analysis",    1),
    ("github.com",  1),
    ("pypi.org",    1),
    ("readthedocs", 1),
)


def search(
    format_description: str,
    mime_type: str,
    max_results: int = 5,
) -> list[WebResult]:
    """
    Run three targeted DDG queries and return deduplicated, ranked results.

    Parameters
    ----------
    format_description : Human-readable description (from libmagic).
    mime_type          : MIME type string.
    max_results        : Maximum results to return.

    Returns
    -------
    List of WebResult sorted by relevance score, descending.
    Empty list if duckduckgo-search is not installed or search fails.
    """
    try:
        from ddgs import DDGS
    except ImportError:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            return []

    # Distil a short name from the description for query building.
    short_name = _short_name(format_description, mime_type)

    queries = [
        f"{short_name} file format python parser library",
        f"{short_name} file format validator forensics",
    ]
    if mime_type:
        queries.append(f"{mime_type} parser validate tool")

    seen_urls: set[str] = set()
    raw: list[WebResult] = []

    try:
        with DDGS() as ddgs:
            for query in queries:
                for r in ddgs.text(query, max_results=3):
                    url = r.get("href", "")
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    raw.append(WebResult(
                        title=r.get("title", ""),
                        url=url,
                        snippet=r.get("body", ""),
                    ))
    except Exception:
        return []

    # Score and sort.
    # Give a massive boost if the actual format name is mentioned
    for result in raw:
        combined = (result.title + " " + result.snippet + " " + result.url).lower()
        score = sum(
            weight
            for kw, weight in _RELEVANCE_KEYWORDS
            if kw in combined
        )
        if short_name.lower() in combined:
            score += 10
        result.score = score

    ranked = sorted(raw, key=lambda r: r.score, reverse=True)
    return ranked[:max_results]


def _short_name(description: str, mime_type: str) -> str:
    """
    Extract a short, query-friendly format name from the libmagic
    description or MIME type.

    e.g. "ELF 64-bit LSB executable, x86-64" → "ELF"
         "application/x-elf"                  → "elf"
    """
    # Take first word of description (usually the format name).
    first_word = description.split()[0] if description else ""
    if first_word and re.match(r"^[A-Za-z0-9_\-]+$", first_word):
        return first_word

    # Fall back to the subtype of the MIME type.
    if "/" in mime_type:
        subtype = mime_type.split("/", 1)[1]
        # Strip common prefixes: x-, vnd., etc.
        subtype = re.sub(r"^(x-|vnd\.|application/)", "", subtype)
        return subtype

    return description[:30] if description else "unknown"
