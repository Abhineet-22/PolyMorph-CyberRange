"""
LLM Provider
============
Discovers and calls an available LLM to generate structured parser
recommendations for an unknown file format.

Provider resolution order (first available wins)
------------------------------------------------
Tier A — Local (no API key, no data leaves the machine)
    1. Ollama      localhost:11434
    2. LM Studio   localhost:1234
    3. vLLM        localhost:8000

Tier B — Cloud (API key from environment variable)
    4. Anthropic   ANTHROPIC_API_KEY
    5. OpenAI      OPENAI_API_KEY
    6. Gemini      GEMINI_API_KEY

No SDK dependencies — all calls made via requests.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from ..probe_result import LLMSuggestion

# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LLMResult:
    suggestions:  list[LLMSuggestion]
    provider:     str   # which provider was used
    model:        str
    error:        str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Prompt template
# ─────────────────────────────────────────────────────────────────────────────

_PROMPT = """\
You are a digital forensics expert. A file has been identified as:

  Format description : {description}
  MIME type          : {mime_type}

Suggest the best tools or Python libraries to parse and validate files
of this format. Focus on tools useful in digital forensics pipelines.

Return ONLY a JSON array (no preamble, no markdown, no explanation).
Each object must have exactly these keys:
  "name"          : tool or library name (string)
  "type"          : "python_lib", "cli_tool", or "both" (string)
  "install"       : installation command (string)
  "validator_cmd" : how to use as a validator command with {{file}} as the
                    file path placeholder (string)
  "reliability"   : "high", "medium", or "low" (string)
  "notes"         : one sentence on what structural aspects it validates (string)

Return ONLY the JSON array.\
"""


# ─────────────────────────────────────────────────────────────────────────────
# Provider implementations
# ─────────────────────────────────────────────────────────────────────────────

def _call_openai_compat(
    base_url: str,
    model: str,
    prompt: str,
    api_key: str = "local",
) -> str:
    """Call any OpenAI-compatible /v1/chat/completions endpoint."""
    import urllib.request
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1000,
        "temperature": 0.2,
    }).encode()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    req = urllib.request.Request(
        f"{base_url}/v1/chat/completions",
        data=payload,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def _call_ollama(prompt: str) -> tuple[str, str] | None:
    """Try Ollama at localhost:11434. Returns (text, model) or None."""
    import urllib.request, urllib.error
    try:
        # List available models
        with urllib.request.urlopen(
            "http://localhost:11434/api/tags", timeout=3
        ) as r:
            models_data = json.loads(r.read())

        models = [m["name"] for m in models_data.get("models", [])]
        if not models:
            return None

        # Prefer larger models for better JSON output
        preferred = ["llama3.1:8b", "llama3:8b", "qwen2.5:7b",
                     "mistral:7b", "phi3:medium"]
        model = next((m for m in preferred if m in models), models[0])

        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        return data["response"], model

    except Exception:
        return None


def _call_lmstudio(prompt: str) -> tuple[str, str] | None:
    """Try LM Studio at localhost:1234."""
    import urllib.request, urllib.error
    try:
        with urllib.request.urlopen(
            "http://localhost:1234/v1/models", timeout=3
        ) as r:
            data = json.loads(r.read())
        models = data.get("data", [])
        if not models:
            return None
        model = models[0]["id"]
        text = _call_openai_compat(
            "http://localhost:1234", model, prompt
        )
        return text, model
    except Exception:
        return None


def _call_anthropic(prompt: str) -> tuple[str, str] | None:
    """Call Anthropic claude-sonnet-4-6 via API."""
    import urllib.request
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None
    try:
        model = "claude-sonnet-4-6"
        payload = json.dumps({
            "model": model,
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        text = data["content"][0]["text"]
        return text, model
    except Exception:
        return None


def _call_openai(prompt: str) -> tuple[str, str] | None:
    """Call OpenAI gpt-4o-mini via API."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        return None
    try:
        model = "gpt-4o-mini"
        text = _call_openai_compat(
            "https://api.openai.com", model, prompt, api_key
        )
        return text, model
    except Exception:
        return None


def _call_gemini(prompt: str) -> tuple[str, str] | None:
    """Call Google Gemini via API."""
    import urllib.request
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return None
    try:
        model = "gemini-1.5-flash"
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/"
            f"models/{model}:generateContent?key={api_key}"
        )
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2},
        }).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return text, model
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Provider resolution and JSON parsing
# ─────────────────────────────────────────────────────────────────────────────

_PROVIDERS = [
    ("Ollama",     _call_ollama),
    ("LM Studio",  _call_lmstudio),
    ("Anthropic",  _call_anthropic),
    ("OpenAI",     _call_openai),
    ("Gemini",     _call_gemini),
]


def query(
    format_description: str,
    mime_type: str,
    preferred_provider: str | None = None,
) -> LLMResult:
    """
    Query the first available LLM and parse its response.

    Parameters
    ----------
    format_description : Human-readable format description.
    mime_type          : MIME type string.
    preferred_provider : If provided, try this provider first.
                         Values: "ollama", "lmstudio", "anthropic",
                                 "openai", "gemini".
    """
    prompt = _PROMPT.format(
        description=format_description,
        mime_type=mime_type,
    )

    providers = list(_PROVIDERS)
    if preferred_provider:
        # Move preferred provider to front.
        pref = preferred_provider.lower().replace(" ", "")
        providers.sort(
            key=lambda p: 0 if p[0].lower().replace(" ", "") == pref else 1
        )

    for provider_name, call_fn in providers:
        result = call_fn(prompt)
        if result is None:
            continue
        raw_text, model = result
        suggestions, error = _parse_response(raw_text)
        return LLMResult(
            suggestions=suggestions,
            provider=provider_name,
            model=model,
            error=error,
        )

    return LLMResult(
        suggestions=[],
        provider="",
        model="",
        error=(
            "No LLM provider available. Set ANTHROPIC_API_KEY, "
            "OPENAI_API_KEY, or GEMINI_API_KEY, or run Ollama / LM Studio."
        ),
    )


def _parse_response(raw: str) -> tuple[list[LLMSuggestion], str]:
    """
    Parse the LLM's JSON response into a list of LLMSuggestion objects.
    Strips think blocks and markdown fences before parsing.
    """
    # Strip <think>...</think> blocks (Qwen3, DeepSeek etc.)
    cleaned = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    # Strip markdown code fences
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned,
                     flags=re.DOTALL).strip()

    try:
        data = json.loads(cleaned)
        if not isinstance(data, list):
            return [], "LLM returned non-array JSON."

        suggestions = []
        for item in data:
            if not isinstance(item, dict):
                continue
            suggestions.append(LLMSuggestion(
                name=str(item.get("name", "")),
                type=str(item.get("type", "python_lib")),
                install=str(item.get("install", "")),
                validator_cmd=str(item.get("validator_cmd", "")),
                reliability=str(item.get("reliability", "medium")),
                notes=str(item.get("notes", "")),
            ))
        return suggestions, ""

    except json.JSONDecodeError as exc:
        return [], f"JSON parse error: {exc}. Raw: {cleaned[:200]}"
