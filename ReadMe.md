# PolyMorph — Comprehensive Project Documentation

**Research Title:** Polyglot File Attacks: Automated Detection of Format-Ambiguous Payloads and Real-World Exploitation Demonstration  
**Author:** Abhineet Agrawal  
**Programme:** M.Sc. Cyber Security — National Forensic Sciences University (NFSU), Gandhinagar  
**Capstone Project — 2025–26**

---

## Table of Contents

1. [Project Genesis & Research Motivation](#1-project-genesis--research-motivation)
2. [What Is a Polyglot File?](#2-what-is-a-polyglot-file)
3. [Threat Model & Attack Surface Taxonomy](#3-threat-model--attack-surface-taxonomy)
4. [PolyMorph Architecture Overview](#4-polymorph-architecture-overview)
5. [Format Contracts (FormatRegistry)](#5-format-contracts-formatregistry)
6. [Synthesis Strategies](#6-synthesis-strategies)
7. [Three-Tier Testbed Design](#7-three-tier-testbed-design)
8. [Studio — Interactive Synthesis & Recon GUI](#8-studio--interactive-synthesis--recon-gui)
9. [Recon Module: Target Scanner](#9-recon-module-target-scanner)
10. [SVG Attack Vector — Live Demonstration](#10-svg-attack-vector--live-demonstration)
11. [PNG+HTML Polyglot — Why It Fails on CDNs](#11-pnghtml-polyglot--why-it-fails-on-cdns)
12. [Empirical Results](#12-empirical-results)
13. [Source-Sink Correlation Model](#13-source-sink-correlation-model)
14. [Limitations & Ethical Boundaries](#14-limitations--ethical-boundaries)
15. [CVE Context & Related Work](#15-cve-context--related-work)
16. [Research Journey Log](#16-research-journey-log)

---

## 1. Project Genesis & Research Motivation

### Background

Polyglot files are binary or text artefacts that simultaneously satisfy the syntax requirements of two or more distinct file format parsers. A single file can be valid as both a PNG image and a PHP script, as both a PDF and a ZIP archive, or as both an SVG graphic and an HTML document. This ambiguity is structurally inherent — not a bug in any single implementation — and arises from differences in how parsers identify, offset, and interpret file boundaries.

### The Problem

Modern web application security controls are systematically layered at different tiers:

| Tier | Control | Weakness |
|:--|:--|:--|
| Client-side | MIME type validation, file extension checks | Trivially bypassed by renaming or forging headers |
| Server-side | Content-Type inspection, magic-byte checks | Polyglots satisfy magic bytes of the "safe" format |
| CDN/Reverse proxy | MIME sniffing, Content-Disposition header | Relies on file extension or server headers, not content |
| Application parser | Library-specific format validation | Library only validates its expected slice of the file |

Polyglots weaponise this stack by presenting a file that passes each individual check while executing as a hostile format downstream.

### Research Questions

1. Can polyglot construction be automated in a format-agnostic, extensible framework?
2. Which synthesis strategies (append / inject / prepend) apply to which format pairs?
3. Where does WHATWG MIME Sniffing Standard and browser parsing actually prevent exploitation?
4. Can a live, remotely-accessible XSS demonstration be achieved using legitimate file format features?

---

## 2. What Is a Polyglot File?

### Formal Definition

A file `F` is a polyglot of formats `A` and `B` if:

```
parse_A(F) = valid_A_object  AND  parse_B(F) = valid_B_object
```

Both parsers succeed on `F` without modification. The file has a **single byte stream** but **two (or more) valid interpretations**.

### Construction Approaches

#### Append Strategy

Place one format's payload entirely after the EOF marker of the host format. The host parser stops at its EOF; the payload parser starts scanning from a known offset or searches backward from the file tail.

```
[ HOST FORMAT ][ HOST EOF ][ PAYLOAD FORMAT DATA ]
  ^── Parser A reads this ──^  ^── Parser B reads this ──^
```

**Use case:** ZIP polyglots — ZIP locates its Central Directory by scanning from the file end, so prepended arbitrary data is ignored. Enables: PNG+ZIP, PDF+ZIP.

#### Inject Strategy

Embed payload bytes into a "comment" or "metadata" field of the host format that the host parser tolerates but ignores. The embedded bytes are valid code/markup for the payload parser.

```
[ HOST HEADER ][ HOST COMMENT FIELD: PAYLOAD DATA ][ HOST BODY ]
                 ^── Parser A: opaque bytes ──^
                 ^── Parser B: executable code ──^
```

**Use case:** PNG `tEXt` chunks (arbitrary key-value data ignored by image renderers), SVG `<script>` injection (SVG's native XML DOM scripting), PDF comment fields.

#### Prepend Strategy

Prepend payload bytes before the host format's magic bytes, relying on the host parser's tolerance for leading garbage (or a specific "magic bytes at known offset" requirement).

```
[ PAYLOAD DATA ][ HOST MAGIC ][ HOST BODY ]
                  ^── Parser A: starts parsing here ──^
 ^── Parser B: consumes full stream ──^
```

**Use case:** PHP scripts prepended to images — PHP scans for `<?php` delimiter anywhere in the stream.

---

## 3. Threat Model & Attack Surface Taxonomy

### Content Surfaces

PolyMorph's recon module categorises attack surfaces into 9 distinct categories:

| Category | Description | Default Strategy | Severity |
|:--|:--|:--|:--|
| `media_serving` | Image/media served inline without `X-Content-Type-Options: nosniff` | inject | high |
| `doc_processing` | Server-side document parsing pipeline (pdfminer, PIL, ImageMagick) | append | high |
| `content_embed` | `<iframe>` or embed without `sandbox` attribute | inject | high |
| `api_ingestion` | Multipart/binary API endpoint accepting file streams | append | high |
| `cloud_storage` | Direct CDN / S3 / GCS references without ACL restrictions | append | medium |
| `download_serve` | File download route without `Content-Disposition: attachment` | inject | high |
| `param_reflection` | URLSearchParams → DOM sink (object.data, innerHTML) | inject | high |
| `svg_serving` | SVG asset endpoint or inline SVG without restrictive CSP | inject | high |
| `svg_upload` | File upload accepting images (SVG capable, no MIME verification) | inject | high |

### Exploitability Dimension

Each surface has an **exploitability** rating:

- **active** — An ingress mechanism exists that allows an attacker to introduce a hostile file. The delivery chain from attacker-controlled upload to victim browser execution is complete.
- **latent** — The serving mechanism exists but no direct upload path was detected. Exploitation requires supply-chain compromise (repository poisoning, CDN asset substitution).

---

## 4. PolyMorph Architecture Overview

```
PolyMorph/
├── core/
│   ├── format_registry.py      # FormatSpec definitions for each file format
│   └── constructor.py          # Synthesis engine: selects strategy, builds polyglot
├── formats/
│   ├── png.py                  # PNG-specific helpers (chunk reader/writer)
│   ├── jpeg.py                 # JPEG EXIF/APP comment field injection
│   ├── gif.py                  # GIF extension block helpers
│   ├── pdf.py                  # PDF comment and stream helpers
│   ├── html.py                 # HTML payload builder
│   ├── svg.py                  # SVG DOM polyglot helpers (NEW — v2.4.0)
│   └── zip_fmt.py              # ZIP Central Directory manipulation
├── strategies/
│   ├── base.py                 # Strategy abstract base class
│   ├── append.py               # AppendStrategy: tail polyglot construction
│   └── inject.py               # InjectStrategy: in-band comment/field injection
├── probe/
│   ├── target_scanner.py       # Recon engine: HTTP surface detection
│   ├── fingerprint_signatures.json  # Heuristic rules for tech fingerprinting
│   ├── probe_engine.py         # HTTP probe orchestration
│   └── auto_detector.py        # Format auto-detection from bytes
├── validation/
│   └── format_validator.py     # Post-build dual-format validation
├── tests/
│   ├── test_append.py          # Append strategy unit tests
│   ├── test_inject.py          # Inject strategy unit tests
│   └── test_content_surfaces.py  # Surface detection + recommendation tests
└── cli.py                      # CLI entrypoint

studio/
├── backend/
│   ├── main.py                 # FastAPI application
│   └── routes/
│       ├── crafter.py          # /api/crafter/* — polyglot synthesis API
│       ├── recon.py            # /api/recon/* — target scanning API
│       └── testbed.py          # /api/testbed/* — Docker testbed control API
└── frontend/
    └── index.html              # Single-page Studio GUI

testbed/
├── docker-compose.yml          # Orchestration for all three tiers
├── tier1_legacy/               # PHP 7.4 / Apache — legacy upload surface
├── tier2_mern/                 # MongoDB/Express/React/Node — modern API surface
├── tier3_cloud/                # Nginx + FastAPI — cloud-native microservice surface
└── harness/
    └── run_tests.py            # Automated end-to-end test harness
```

### Data Flow

```
[CLI / Studio UI]
       │
       ▼
  Constructor.build(file_a, file_b, fmt_a, fmt_b)
       │
       ├── FormatRegistry.get(fmt_a)  → FormatSpec_A
       ├── FormatRegistry.get(fmt_b)  → FormatSpec_B
       ├── _select_strategy()         → AppendStrategy | InjectStrategy
       │
       ▼
  strategy.execute(host_bytes, payload_bytes)
       │
       ▼
  format_validator.validate(result, fmt_a) + validate(result, fmt_b)
       │
       ▼
  ConstructorResult(data, success, strategy, notes, validation_a, validation_b)
```

---

## 5. Format Contracts (FormatRegistry)

Each registered format is described by a `FormatSpec` dataclass with the following key fields:

| Field | Type | Description |
|:--|:--|:--|
| `name` | str | Canonical format identifier (e.g., `"png"`, `"svg"`) |
| `extensions` | tuple[str] | File extensions (e.g., `(".png",)`) |
| `mime_types` | tuple[str] | MIME types (e.g., `("image/png",)`) |
| `magic_bytes` | tuple[bytes] | Leading byte signatures for format detection |
| `append_tolerant` | bool | Parser ignores trailing data after EOF |
| `prepend_tolerant` | bool | Parser ignores leading data before magic bytes |
| `max_prepend_bytes` | int | Maximum tolerated prepend size (0 = none) |
| `scans_from_end` | bool | Parser locates structures from EOF (ZIP Central Dir) |
| `has_comment_field` | bool | Format has an in-band opaque field for injection |
| `comment_max_bytes` | int | Maximum comment field capacity |
| `viable_as_host` | bool | Can carry injected payload |
| `viable_as_payload` | bool | Can be embedded as payload within another format |
| `category` | str | Format class: `"image"`, `"archive"`, `"document"`, `"web"` |
| `validator` | str | Validation backend: `"png"`, `"html"`, `"zip"`, `"native"` |

### Registered Formats (v2.4.0)

| Format | Magic Bytes | Append Tolerant | Has Comment | Viable Host | Viable Payload |
|:--|:--|:--|:--|:--|:--|
| PNG | `\x89PNG\r\n\x1a\n` | ✅ | ✅ (tEXt chunk) | ✅ | ❌ |
| JPEG | `\xff\xd8\xff` | ✅ | ✅ (APP/EXIF) | ✅ | ❌ |
| GIF | `GIF87a`/`GIF89a` | ✅ | ✅ (extension block) | ✅ | ❌ |
| PDF | `%PDF-` | ✅ | ✅ (comment field) | ✅ | ✅ |
| ZIP | `PK\x03\x04` | ❌ | ❌ | ❌ | ✅ |
| HTML | `<!DOCTYPE`/`<html` | ✅ | ✅ (comment) | ✅ | ✅ |
| SVG | `<svg`/`<?xml` | ✅ | ✅ (script element) | ✅ | ✅ |
| PHP | `<?php` | ✅ | ✅ (comment) | ❌ | ✅ |

---

## 6. Synthesis Strategies

### AppendStrategy

```
host_bytes  = read(file_a)
payload_bytes = read(file_b)
polyglot    = host_bytes + delimiter_if_needed + payload_bytes
```

The host format must be `append_tolerant=True` OR the payload format must be `scans_from_end=True`. The ZIP Central Directory Locator is at a fixed negative offset from EOF — ZIP parsers always find it regardless of what precedes.

**Validated polyglots:**
- PNG + ZIP → dual-valid: image renderers show PNG, ZIP utilities extract contents
- PDF + ZIP → dual-valid: PDF readers open the document, ZIP utilities extract files
- JPEG + PHP → dual-valid when served by PHP interpreter (PHP scans for `<?php` delimiter)

### InjectStrategy

```
offset = format_helpers.find_injection_offset(host_bytes)
polyglot = host_bytes[:offset] + encode(payload_bytes) + host_bytes[offset:]
```

The injection point is a comment or metadata field that the host parser treats as opaque. The payload is encoded to fit within the field's character set constraints.

**Validated polyglots:**
- PNG + HTML → `tEXt` chunk injection (HTML comment encoding)
- SVG + script → native `<script>` element in SVG XML DOM (CDATA-wrapped)

---

## 7. Three-Tier Testbed Design

The three testbed tiers were chosen to represent distinct architecture generations with different upload handling characteristics.

### Tier 1 — PHP Legacy Application

**Technology:** PHP 7.4 / Apache 2.4 / MySQL  
**Container:** `testbed/tier1_legacy/`  
**Upload surface:** Traditional `multipart/form-data` PHP upload handler  
**Validation controls:**
- `$_FILES['upload']['type']` check (bypassable via forged MIME)
- `pathinfo()` extension check (bypassable via double-extension: `shell.php.jpg`)
- File size limit
- No magic-byte verification

**Attack vectors demonstrated:**
- PNG+PHP polyglot: uploaded as PNG, executed as PHP when accessed via Apache
- ZIP+PHP polyglot: extracted server-side, PHP file executed
- Double-extension bypass: `malicious.php.jpg` bypasses extension allowlist

**Key finding:** When server configuration routes `.jpg` through the PHP interpreter (a misconfiguration common in legacy deployments), the PNG+PHP polyglot achieves remote code execution. No magic-byte check is performed by default.

---

### Tier 2 — MERN Stack (Modern API)

**Technology:** MongoDB / Express.js / React / Node.js  
**Container:** `testbed/tier2_mern/`  
**Upload surface:** REST API endpoint (`/api/upload`), Multer middleware  
**Validation controls:**
- `multer.fileFilter` with MIME type allowlist (`image/png`, `image/jpeg`)
- Mongoose schema validation on metadata
- No server-side content inspection beyond MIME header

**Attack vectors demonstrated:**
- PNG+ZIP polyglot: Multer accepts as `image/png`, Node.js `unzipper` subsequently extracts payload
- PNG+HTML polyglot: accepted as image, `<script>` payload in `tEXt` chunk (latent — served as image)
- API MIME confusion: `Content-Type: image/png` header forged on a PHP script body

**Key finding:** Multer trusts the client-supplied `Content-Type` header. Any file with `Content-Type: image/png` passes the filter regardless of actual content.

---

### Tier 3 — Cloud-Native Microservice

**Technology:** Nginx 1.25 / FastAPI (Python 3.11) / PostgreSQL  
**Container:** `testbed/tier3_cloud/`  
**Upload surface:** FastAPI endpoint with `python-magic` MIME detection  
**Validation controls:**
- `python-magic` library for content-based MIME detection (magic byte inspection)
- File extension allowlist enforced server-side
- Nginx `add_header X-Content-Type-Options nosniff` on served files
- PostgreSQL stores file metadata and checksums

**Attack vectors demonstrated:**
- PNG+ZIP polyglot: `python-magic` reads PNG magic bytes (`\x89PNG\r\n\x1a\n`) → classifies as `image/png` → passes. ZIP Central Directory in tail is ignored by magic check.
- ZIP Slip via polyglot: crafted ZIP with `../../../etc/passwd` traversal path in entry filename
- SVG upload: `python-magic` returns `image/svg+xml` correctly BUT FastAPI allowlist includes `image/svg+xml` for avatar uploads — SVG `<script>` payload stored and served

**Key finding:** Magic-byte detection protects against MIME header forgery but NOT against append-strategy polyglots that correctly present the host format's magic bytes. The ZIP payload portion is completely transparent to `python-magic`.

---

## 8. Studio — Interactive Synthesis & Recon GUI

Studio is a single-page web application (FastAPI backend + vanilla JS frontend) providing:

### Crafter Panel
- Format pair selection from registered FormatRegistry entries
- Strategy selection (Auto / Append / Inject)
- File upload or sample file selection
- Real-time hex dump preview of head and tail bytes
- SHA-256 fingerprint of synthesised polyglot
- Dual-format validation results
- Download link for synthesised artifact

### Recon Panel
- Target URL input with configurable scan depth
- Surface category display with severity badges
- Delivery chain visualisation for each detected surface
- Automated polyglot recommendation generation (format pair + strategy)
- Tech fingerprinting (framework detection from HTML signatures)

### Studio API Endpoints

| Method | Path | Description |
|:--|:--|:--|
| GET | `/api/crafter/formats` | List all registered FormatSpec entries |
| GET | `/api/crafter/info?fmt_a=&fmt_b=` | Analyse format pair viability |
| GET | `/api/crafter/samples` | List available sample files |
| POST | `/api/crafter/build` | Synthesise polyglot (multipart form) |
| GET | `/api/crafter/download/{filename}` | Download synthesised artifact |
| POST | `/api/recon/scan` | Full target scan and surface detection |

---

## 9. Recon Module: Target Scanner

`PolyMorph/probe/target_scanner.py` implements the `TargetScanner` class. Given a target URL, it performs:

1. **HTTP probe** — Fetches the target page; records response headers, status, redirect chain
2. **Tech fingerprinting** — Matches HTML/header signatures against `fingerprint_signatures.json` to detect framework, server, and library indicators
3. **Security gap detection** — Checks for absent `nosniff`, `CSP`, `Strict-Transport-Security`, missing `sandbox` on iframes
4. **Upload endpoint enumeration** — Identifies `<input type="file">` forms, checks `accept=` attribute for permissive MIME lists
5. **Content surface detection** — Categorises 9 surface types from DOM analysis (see §3)
6. **Recommendation synthesis** — Maps each detected surface to a polyglot format pair + strategy via `fingerprint_signatures.json::surface_strategy_map`

### SVG Surface Detection Logic (Section 7 — added v2.4.0)

The scanner detects SVG surfaces by:

```python
# External SVG asset references
for tag in soup.find_all(["img", "object", "embed", "source"]):
    src = tag.get("src", "") or tag.get("data", "")
    if src.lower().endswith(".svg") or "image/svg" in src.lower():
        svg_endpoints.append(urljoin(page_url, src))

# Inline SVG in page source
has_inline_svg = "<svg" in html_lower

# Upload forms accepting SVG-compatible MIME
svg_upload_forms = [form for form in soup.find_all("form")
    if any("svg" in inp.get("accept","").lower() or "image" in inp.get("accept","").lower()
           for inp in form.find_all("input", {"type": "file"}))]

# Avatar/profile image upload fields (common SVG upload vector)
has_avatar_upload = any(
    any(pat in inp.get("name","").lower() or pat in inp.get("id","").lower()
        for pat in ["avatar", "logo", "icon", "profile", "picture", "photo"])
    for form in soup.find_all("form")
    for inp in form.find_all("input", {"type": "file"})
)
```

**CSP awareness:** If `script-src: 'none'` is present in the response CSP, SVG severity is downgraded to `medium` (script execution is blocked by policy).

---

## 10. SVG Attack Vector — Live Demonstration

### Technical Background: Why SVG Executes Scripts

SVG (Scalable Vector Graphics) is fundamentally different from raster image formats (PNG, JPEG, GIF):

| Property | PNG / JPEG / GIF | SVG |
|:--|:--|:--|
| Data model | Binary pixel matrix | XML Document Object Model |
| Browser parsing | Image decode pipeline (no DOM) | Full XML/HTML parser |
| Script elements | Invalid — not part of spec | Native — W3C SVG spec §18 |
| Event handlers | None | `onload`, `onclick`, `onerror`, etc. |
| Magic bytes | Binary (`\x89PNG`, `\xff\xd8`) | None — text format |
| Magic-byte filter bypass | Impossible (binary header required) | Trivial — no binary signature |
| CSP enforcement | N/A | Applies (script-src, default-src) |

The W3C SVG specification explicitly includes `<script>` as a valid child element of `<svg>`:

> *"SVG makes extensive use of ECMAScript. The SVG `script` element is defined to allow an SVG document to include scripting."* — W3C SVG 1.1 §18.5

When a browser receives a document with `Content-Type: image/svg+xml`, it instantiates a **full XML DOM** and executes all `<script>` blocks.

### Why It Works in `<object>` Context

The HTML `<object>` element embeds external content by fetching the referenced URL and instantiating the appropriate handler based on the served `Content-Type`:

```html
<!-- No type= attribute → browser uses server's Content-Type header -->
<object data="preview.svg"></object>
```

If the server responds with `Content-Type: image/svg+xml`, the browser:
1. Instantiates an SVG frame (not an image decoder)
2. Parses the SVG as XML
3. Builds the SVG DOM
4. Executes `<script>` elements

**Critical:** If `type="image/png"` is hardcoded on the `<object>` element, the browser forces image decoding mode and scripts do NOT execute — WHATWG §8.4.

### Demonstrated Payload

The SVG polyglot demonstrated live at `https://abhineetagrawal.netlify.app/?preview=preview_poc.svg`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 200"
     onload="document.getElementById('xss-banner').style.display='block'">
  <defs>
    <style>
      .bg { fill: #1a1a2e; }
      .text { font-family: monospace; fill: #00ff88; font-size: 14px; }
      #xss-banner {
        display: none; fill: #ff4444; font-size: 11px;
        font-family: monospace;
      }
    </style>
  </defs>
  <rect class="bg" width="400" height="200"/>
  <text class="text" x="20" y="40">PolyMorph SVG Polyglot Demo</text>
  <text class="text" x="20" y="65">Format: SVG (XML DOM)</text>
  <text class="text" x="20" y="90">Vector: Reflected SVG via ?preview= parameter</text>
  <text id="xss-banner" x="20" y="130">
    [!] XSS DEMONSTRATED — SVG onload= executed in origin context
  </text>
  <script type="text/javascript">
    <![CDATA[
      (function() {
        var banner = document.getElementById('xss-banner');
        if (banner) banner.style.display = 'block';
        // Safe demonstration: no actual payload exfiltration
        console.log('[PolyMorph] SVG DOM script executed. Origin: ' + window.location.origin);
      })();
    ]]>
  </script>
</svg>
```

**Result:** `onload=` event handler and inline `<script>` both execute in the context of `https://abhineetagrawal.netlify.app`. Origin-scoped DOM access confirmed. Demonstrated alert/banner text rendered.

### CDATA Requirement

SVG is parsed as XML (not HTML). Inside `<script>` within XML, the characters `<`, `>`, and `&` are XML markup characters and must be escaped. The standard approach is wrapping script content in a `CDATA` section:

```xml
<script type="text/javascript">
  <![CDATA[
    if (a < b && b > 0) { alert("OK"); }
  ]]>
</script>
```

Without CDATA, the XML parser throws a parse error on any `<` or `&` inside the script.

### SVG Injection Point

For a standalone SVG file, the `<script>` element is inserted as a direct child of the root `<svg>` element, before visual content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="...">
  <!-- INJECTION POINT: add <script> here, inside root <svg> -->
  <script type="text/javascript"><![CDATA[
    alert(1);
  ]]></script>

  <!-- Visual SVG content follows -->
  <rect .../>
  <path .../>
</svg>
```

**NOT valid for `<symbol>`/`<use>` sprite patterns:** The `<symbol>` element defines a reusable component for inline HTML embedding. A standalone SVG file must have a single root `<svg>` element (XML well-formedness). Scripts in `<symbol>` only execute when the `<symbol>` is rendered, not on parse.

### Magic-Byte Bypass Property

SVG has no binary magic byte signature. Upload filters that check for specific binary headers (PNG: `\x89PNG`, JPEG: `\xff\xd8\xff`, GIF: `GIF89a`) cannot block SVG because SVG is plain text. An SVG file beginning with:

```xml
<?xml version="1.0"?>
<svg ...>
```

passes all binary magic-byte upload filters by default. Only an allowlist of explicitly permitted MIME types (enforced by content inspection, not header trust) can block SVG.

---

## 11. PNG+HTML Polyglot — Why It Fails on CDNs

### Construction

The PNG+HTML polyglot is constructed by injecting HTML+JavaScript into a PNG `tEXt` chunk:

```
PNG Header (\x89PNG\r\n\x1a\n)
IHDR chunk (image dimensions, bit depth)
tEXt chunk:
  keyword: "Comment"
  text:    <script>alert(document.domain)</script>
IDAT chunk (compressed pixel data)
IEND chunk (EOF marker: \xaeB`\x82)
```

The file is a valid PNG: image renderers decode the IHDR+IDAT blocks and display the image. The `tEXt` chunk content is opaque metadata — no image renderer executes it.

### Why XSS Cannot Fire on Netlify CDN

Netlify (and all standards-compliant CDNs) map file extensions to `Content-Type` headers at the CDN layer:

```
.png → Content-Type: image/png
```

Under the **WHATWG MIME Sniffing Standard (§8.4 — Sniffing in an image context)**:

> *"If the resource is an image type, return the computed MIME type."*

More critically, under **§7 — Determining the computed MIME type**:

> *"If the supplied type is an image type that is not an SVG MIME type or a text/html type, return the supplied type."*

This means: when the server supplies `Content-Type: image/png`, the browser **never promotes it to `text/html`**, regardless of the file content. The WHATWG standard explicitly prohibits this promotion for specific image types.

The `<script>` tag inside the PNG `tEXt` chunk is never seen by the HTML/JS engine — it is consumed entirely by the PNG pixel decoder as opaque metadata bytes.

### WHATWG Sniffing Table (Abbreviated)

| Supplied MIME | Content Sniff Result | Script Execution Possible |
|:--|:--|:--|
| `text/html` | HTML DOM | ✅ Yes |
| `image/svg+xml` | SVG XML DOM | ✅ Yes |
| `image/png` | PNG pixel decode | ❌ No |
| `image/jpeg` | JPEG pixel decode | ❌ No |
| `application/octet-stream` | Binary download | ❌ No |

**Conclusion:** PNG+HTML polyglots are valid academic demonstrations of format confusion in controlled lab environments where the server can be configured to serve `.png` files as `text/html` (a misconfiguration). On standards-compliant CDNs with correct MIME mapping, they cannot achieve client-side script execution. This distinction between lab capability and real-world exploitability is a core research finding.

---

## 12. Empirical Results

### Test Suite Coverage

```
PolyMorph/tests/test_append.py          2 tests  — Append strategy unit tests
PolyMorph/tests/test_inject.py          5 tests  — Inject strategy unit tests
PolyMorph/tests/test_content_surfaces.py 7 tests  — Surface detection + recommendations
studio/tests/test_studio_backend.py    10 tests  — Studio API endpoint tests

TOTAL: 24 tests | PASS: 24 | FAIL: 0 | WARNINGS: 1 (httpx deprecation, non-breaking)
```

### Synthesised Artifacts

| Artifact | Host Format | Payload Format | Strategy | Dual Valid | Notes |
|:--|:--|:--|:--|:--|:--|
| `polyglot_png_html_*.png` | PNG | HTML+JS | inject (tEXt) | PNG ✅ HTML ✅* | *HTML only valid when served as text/html |
| `polyglot_png_zip_*.png` | PNG | ZIP | append | PNG ✅ ZIP ✅ | Both parsers succeed unconditionally |
| `polyglot_jpeg_html_*.jpeg` | JPEG | HTML+JS | inject (APP) | JPEG ✅ HTML ✅* | Same caveat as PNG+HTML |
| `preview_poc.svg` | SVG | JS payload | inject (script) | SVG ✅ JS ✅ | Live demo confirmed |

### Testbed Results (Automated Harness)

Results stored in `test_results_all.json`.

| Tier | Upload Control | PNG+PHP | PNG+ZIP | SVG+Script | ZIP Slip |
|:--|:--|:--|:--|:--|:--|
| Tier 1 (PHP/Apache) | Extension allowlist | ✅ Executed | ✅ Extracted | ✅ Executed | N/A |
| Tier 2 (MERN) | MIME header check | ✅ Uploaded | ✅ Uploaded+Extracted | ✅ Uploaded | N/A |
| Tier 3 (Cloud-Native) | Magic-byte check | ✅ Uploaded | ✅ Uploaded+Extracted | ✅ Uploaded | ✅ Path traversal |

✅ = Attack surface confirmed exploitable under stated conditions

---

## 13. Source-Sink Correlation Model

PolyMorph models the exploitation chain as a **Source → Transform → Sink** triple:

```
SOURCE (attacker-controlled input)
  │
  ├── File upload form (multipart/form-data)
  ├── URL parameter reflected to DOM sink (URLSearchParams → object.data)
  ├── API endpoint accepting binary stream
  └── Supply-chain asset (CDN poisoning, repository commit)
  │
  ▼
TRANSFORM (server or client-side processing)
  │
  ├── Storage to disk / CDN
  ├── Server-side parse (pdfminer, PIL, ImageMagick)
  ├── API pass-through to downstream service
  └── DOM embedding (createElement, innerHTML, object.data assignment)
  │
  ▼
SINK (exploitation point)
  │
  ├── PHP execution (RCE)  ← Tier 1
  ├── ZIP extraction + path traversal (ZIP Slip)  ← Tier 3
  ├── XSS (script execution in victim browser)  ← SVG demo
  └── SSRF / XXE (XML-based formats)
```

### Exploitability Classification

| Source Type | Sink | Exploitability | Classification |
|:--|:--|:--|:--|
| Upload form → stored → served | XSS | Active | Stored XSS |
| URL param → DOM object.data | XSS | Active | Reflected/DOM XSS |
| Upload form → server parse | RCE | Active | Direct code execution |
| CDN asset (no upload path) | XSS | Latent | Supply-chain |

---

## 14. Limitations & Ethical Boundaries

### Technical Limitations

1. **CDN MIME enforcement:** PNG+HTML polyglots cannot achieve XSS on any CDN that correctly serves `.png` files as `Content-Type: image/png`. This covers Netlify, Cloudflare, AWS S3 (with proper bucket policies), and all WHATWG-compliant servers. Lab exploitation requires deliberate server misconfiguration.

2. **CSP blocking SVG scripts:** `Content-Security-Policy: script-src 'none'` or `default-src 'none'` blocks SVG `<script>` execution even when the SVG DOM is instantiated. The PolyMorph scanner detects and reports CSP presence, downgrading SVG surface severity accordingly.

3. **PNG `tEXt` chunk size limit:** PNG `tEXt` chunks support arbitrary-length text, but excessively large `tEXt` chunks may trigger warnings in strict PNG validators. Practical limit for payload injection: ~65 KB (well above typical XSS payload sizes).

4. **Automated recon without authentication:** The recon module cannot scan authenticated surfaces without valid session credentials. Upload endpoints behind authentication are not discovered by unauthenticated scans.

### Ethical Boundaries

- All live demonstrations were performed exclusively on `https://abhineetagrawal.netlify.app` — the researcher's own personal portfolio under their own control.
- No third-party systems, production applications, or external services were targeted.
- No actual data exfiltration or persistent payloads were deployed. All XSS demonstrations used visible on-page banners and console logging only.
- The PolyMorph tool is designed for authorised penetration testing and academic research. It includes no C2 (command-and-control) infrastructure.
- The testbed targets are entirely local Docker containers with no external network exposure.

### Academic Honesty Note

An earlier iteration of the demo attempted to force SVG execution by hardcoding `type="image/svg+xml"` on the `<object>` element in `preview.js`. This was removed because it would constitute an artificial shim — simulating a vulnerability that only exists due to the researcher's own code modification, not due to a real application weakness. The final demo uses `<object data="...">` without a `type=` attribute, correctly relying on the server's `Content-Type: image/svg+xml` response header — the realistic attack condition.

---

## 15. CVE Context & Related Work

### CVE-2025-64512 — pdfminer.six Polyglot Processing

A critical vulnerability in the `pdfminer.six` Python library (CVSS 9.8) in which a specially crafted PDF+ZIP polyglot causes the library's stream parser to interpret ZIP Central Directory structures as valid PDF cross-reference objects, leading to arbitrary object injection. PolyMorph's `doc_processing` surface category explicitly attributes this CVE pattern and uses it as a canonical example of server-side polyglot exploitation.

### OWASP File Upload Vulnerabilities

OWASP's File Upload Cheat Sheet identifies the core categories:

- **Extension bypass:** Double extension, case variation
- **MIME confusion:** Trusting client-supplied `Content-Type`
- **Magic byte bypass:** Only checking first N bytes, not entire structure
- **Archive bomb / ZIP Slip:** Malicious paths in ZIP entries

PolyMorph provides automated construction of artifacts for all four categories.

### MIME Sniffing & CWE-430

CWE-430 (Deployment of Wrong Handler) covers scenarios where a file is deployed to a handler that processes it differently from how it was validated. The key reference standard is the **WHATWG MIME Sniffing Standard** (https://mimesniff.spec.whatwg.org/), which defines the normative algorithm browsers use to determine a resource's computed MIME type. PolyMorph's recon module checks for `X-Content-Type-Options: nosniff` absence as a CWE-430 indicator.

### Related Academic Work

- **Polyglot Files: A Case Study** — Albertini (2012): seminal work on GIFAR (GIF+JAR) polyglots for Java applet exploitation
- **caution.pdf / angecryption** — Ange Albertini's ongoing polyglot research corpus
- **Stagefright (CVE-2015-3864)** — Media library polyglot exploitation on Android
- **ImageTragick (CVE-2016-3714)** — ImageMagick SSRF/RCE via crafted image files processed server-side

---

## 16. Research Journey Log

This section documents the progression of the research as it was conducted, including dead ends, key insights, and pivots.

### Phase 1 — Project Scoping (October 2025)

- Initial scope: build a tool that creates polyglot files for academic demonstration
- Selected format pairs: PNG+PHP (classic server-side), PNG+ZIP (dual-parser), PDF+ZIP (document/archive)
- Deliverables defined: PolyMorph CLI, Studio GUI, three-tier testbed, automated harness

### Phase 2 — Core Engine Development (October–November 2025)

- Implemented `FormatRegistry` with `FormatSpec` dataclass
- Implemented `AppendStrategy` and `InjectStrategy`
- Built `Constructor` orchestration layer with automatic strategy selection
- Built `format_validator` for post-synthesis dual validation
- Implemented format helpers: `png.py`, `jpeg.py`, `pdf.py`, `zip_fmt.py`, `html.py`
- Studio FastAPI backend + vanilla JS frontend built
- Three-tier Docker testbed designed and built by specialised subagents:
  - Tier 1: PHP/Apache legacy (subagent: Tier 1 PHP Legacy Testbed Builder)
  - Tier 2: MERN stack (subagent: Tier 2 MERN Testbed Builder)
  - Tier 3: Cloud-native FastAPI (subagent: Tier 3 Cloud-Native Testbed Builder)
  - Harness: Automated test runner (subagent: Harness and Orchestration Builder)

### Phase 3 — Recon Module (November 2025)

- Built `TargetScanner` for HTTP surface detection
- Implemented `fingerprint_signatures.json` with tech signatures and surface strategy map
- Added surface categories: `media_serving`, `doc_processing`, `content_embed`, `api_ingestion`, `cloud_storage`, `download_serve`
- Added `param_reflection` surface for client-side URLSearchParams → DOM sink pattern
- Discovered this pattern in researcher's own portfolio (`preview.js`)

### Phase 4 — Live Demo Attempt: PNG+HTML on Netlify (November 2025)

**Hypothesis:** Upload a PNG+HTML polyglot to Netlify portfolio. Use `?preview=polyglot_png_html_*.png` parameter. Browser would render HTML and execute `<script>`.

**Investigation:**
1. Examined `preview.js` — found `<object>` element with hardcoded `type="image/png"` attribute
2. Removed `type=` attribute from `<object>` — polyglot now served with correct Content-Type
3. Fetched polyglot PNG via `curl -I` — Netlify returns `Content-Type: image/png` (strict extension mapping)
4. WHATWG §8.4 analysis — `image/png` CANNOT be promoted to `text/html` by any compliant browser
5. Hex-inspected polyglot at offset 49 — `<script>alert(...)` bytes present and correct
6. **Finding confirmed:** PNG+HTML polyglot is correctly constructed but physically impossible to execute on a standards-compliant CDN

**Conclusion:** PNG+HTML polyglot is a valid lab artifact demonstrating format injection technique. It is NOT a deployable XSS vector on CDNs. This is a research finding, not a failure.

### Phase 5 — Pivot to SVG Attack Vector (November 2025)

**Question:** "If we had a generic MIME or SVG DOM, would the attack demo be successful?"

**Analysis:**
- SVG = XML DOM (not raster pixel matrix)
- SVG has W3C-native `<script>` element support
- `image/svg+xml` Content-Type → browser instantiates XML DOM, not image decoder
- SVG has NO binary magic bytes → trivially bypasses magic-byte upload filters
- `<object data="file.svg">` without `type=` → browser uses server header → SVG DOM → scripts execute

**Implementation:**
1. Created `preview_poc.svg` with `onload=` handler and `<script>` block (CDATA-wrapped)
2. Uploaded to Netlify portfolio git repository
3. Navigated to `https://abhineetagrawal.netlify.app/?preview=preview_poc.svg`
4. Browser instantiated SVG DOM — both `onload=` and `<script>` executed
5. **Result: Reflected XSS successfully demonstrated**

**Key technical note:** The `<symbol>/<use>` sprite pattern (from SVG icon libraries) uses the SVG inline in HTML embedding context, NOT as a standalone SVG file. For standalone SVG XSS, the script must be a direct child of the root `<svg>` element.

### Phase 6 — SVG Integration into PolyMorph (November 2025)

- Created `PolyMorph/formats/svg.py` with full helper suite
- Registered SVG `FormatSpec` in `FormatRegistry` with magic bytes `(<svg, <?xml, <!DOCTYPE svg)`
- Added `svg_serving` and `svg_upload` entries to `fingerprint_signatures.json::surface_strategy_map`
- Added SVG surface detection block (§7) to `target_scanner.py`
- Added SVG test cases to `test_content_surfaces.py`
- Registered SVG in `formats/__init__.py`
- Updated crafter sample glob to include `.svg`
- Bumped cache buster from `v=2.3.0` to `v=2.4.0`

**Final test suite: 24 tests passing, 0 failures**

### Key Insight Summary

> **The fundamental insight of this research is that "file format" and "execution format" are independent properties.** A file simultaneously valid as a PNG image and a PHP script is treated as an image by the CDN, an image by the browser's parser, BUT as a PHP script by the server-side interpreter. The exploitation surface is the gap between these two treatments — and that gap is not a bug in any single component, but an emergent property of a heterogeneous system where different components apply different validation semantics to the same byte stream.
>
> SVG demonstrates a special case: a format that is simultaneously a "safe" image format (from the perspective of magic-byte upload filters) and a fully scriptable DOM (from the perspective of the browser). This is not a vulnerability in SVG — it is by design. The vulnerability is treating SVG as equivalent to PNG from a security perspective.

---

*Documentation version 2.4.0 — Last updated: November 2025*  
*PolyMorph Capstone Project — NFSU M.Sc. Cyber Security*
