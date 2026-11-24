# PolyMorph — Tier 2 MERN Testbed

> [!CAUTION]
> **INTENTIONALLY VULNERABLE LOCAL LAB — FOR ACADEMIC RESEARCH ONLY**
> This environment contains deliberate security vulnerabilities. **Never deploy to production, public cloud, or any network-accessible host.** Run exclusively on a local, air-gapped machine inside a controlled research environment.

---

## Overview

This testbed demonstrates two file-upload bypass attack chains using a Node.js + Express (MERN-style) backend:

| Attack Vector | Technique | Root Cause |
|---|---|---|
| **Vector 1** | Stored XSS via MIME Sniffing | Missing `X-Content-Type-Options: nosniff` |
| **Vector 2** | Zip-Slip via Parser Differential | Dual-consumer + no path traversal sanitisation |

---

## Stack

| Component | Technology | Port |
|---|---|---|
| Backend API | Node.js 18, Express, Multer | `3001` |
| Frontend UI | Static HTML + Bootstrap 5 | `3000` (nginx) |

---

## Quick Start

**Prerequisites:** Docker Desktop (or Docker Engine + Compose plugin)

```bash
cd testbed/tier2_mern
docker compose up --build
```

| URL | Description |
|---|---|
| `http://localhost:3000` | Frontend profile/upload UI |
| `http://localhost:3001` | Backend REST API |
| `http://localhost:3001/health` | Liveness probe |
| `http://localhost:3001/files` | JSON list of uploaded files |

To stop:
```bash
docker compose down
```

---

## Attack Vector 1 — Stored XSS via MIME Sniffing (PNG + HTML Polyglot)

### What is vulnerable

The backend sets `Content-Type: image/png` when serving files but deliberately **omits** the `X-Content-Type-Options: nosniff` header. Browsers that perform content sniffing will inspect the file body; if they find HTML/JS content, they may execute it as an HTML document.

### How to reproduce

**Step 1 — Generate the polyglot:**
```bash
python -m PolyMorph build png \
  --inject "<script>alert('XSS from PNG tEXt chunk')</script>" \
  --output avatar.png
```
The resulting `avatar.png` has a valid PNG magic header (`\x89PNG\r\n\x1a\n`) so `file-type` accepts it, but the `tEXt` chunk contains raw HTML.

**Step 2 — Upload via the UI:**
Open `http://localhost:3000`, use the upload form to submit `avatar.png`. The server:
1. Validates `Content-Type: image/png` header ✔  
2. Reads magic bytes with `file-type` — detects `image/png` ✔  
3. Saves the file and returns the URL.

**Step 3 — Trigger XSS:**
Navigate directly to `http://localhost:3001/uploads/avatar_<timestamp>.png` in a browser without strict MIME enforcement.

**Why it works:**
```
Server response headers:
  Content-Type: image/png      ← force-set, but no nosniff
  X-Content-Type-Options:      ← ABSENT (the vulnerability)

Browser sniffs body → finds <script> → executes JavaScript
```

**Immunity:** Modern browsers with strict MIME type enforcement (Firefox ESR, Chrome 87+ with `--enable-features=CrossSiteDocumentBlockingIfIsolating`) are immune. The attack targets misconfigured or older browsers / embedded WebViews.

---

## Attack Vector 2 — Parser Differential → Zip-Slip (PNG + ZIP Polyglot)

### What is vulnerable

The server uses **two different parsers** on the same uploaded file:

| Parser | Reads from | Result |
|---|---|---|
| `file-type` (magic bytes) | **Start** of file — PNG header `\x89PNG` | ✔ Valid image |
| `adm-zip` (background worker) | **End** of file — ZIP EOCD signature `PK\x05\x06` | ✔ Valid archive |

This parser differential allows a file to simultaneously satisfy both checks. The `adm-zip` extraction does **not** sanitise entry names for path traversal sequences (`../../`).

### How to reproduce

**Step 1 — Generate the polyglot:**
```bash
# Craft a PNG+ZIP polyglot with a Zip-Slip entry (../../backend/injected.js)
python -m PolyMorph build png zip --append --output avatar.png
```

**Step 2 — Upload via the UI:**
The file passes both the header check and the `file-type` magic-byte check.

**Step 3 — Observe the worker:**
Check the backend container logs:
```
[WORKER] Archive detected inside "avatar_1234567890.png" — extracting 1 entries
[WORKER] Extracting: ../../backend/injected.js → ./extracted/../../backend/injected.js
[WORKER] Extraction complete
```
Files are written by `zip.extractEntryTo(entry, './extracted/', true, true)` with **no path sanitisation**, allowing writes outside `./extracted/`.

**Step 4 — Verify:**
```bash
ls backend/extracted/
# crafted entry content appears here (or outside, depending on traversal depth)
```

### The vulnerability in code

```javascript
// server.js — triggerArchiveWorker()
zip.extractEntryTo(entry, './extracted/', true, true);
// ^^^ entry.entryName is user-controlled; no path.normalize / containment check
```

**Safe fix (not applied here by design):**
```javascript
const safe = path.normalize(path.join('./extracted/', entry.entryName));
if (!safe.startsWith(path.resolve('./extracted/'))) throw new Error('Zip-Slip detected');
```

---

## File Structure

```
tier2_mern/
├── docker-compose.yml
├── README.md
├── backend/
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js          ← intentionally vulnerable Express API
│   ├── uploads/           ← user-uploaded files served without nosniff
│   └── extracted/         ← zip-slip extraction target
└── frontend/
    └── index.html         ← Bootstrap 5 UI; renders uploads as <img>
```

---

## API Reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/upload` | Upload a file (multipart/form-data, field: `file`) |
| `GET` | `/files` | List all uploaded files |
| `GET` | `/uploads/:filename` | Serve uploaded file (no nosniff) |
| `GET` | `/health` | Health check |

---

## Intentional Vulnerability Summary

| # | Location | Vulnerability | CWE |
|---|---|---|---|
| 1 | `app.use('/uploads', ...)` | Missing `X-Content-Type-Options: nosniff` | CWE-116 |
| 2 | `fileFilter` | MIME type check on header only (client-controlled) | CWE-434 |
| 3 | `triggerArchiveWorker` | Dual-consumer parser differential | CWE-436 |
| 4 | `zip.extractEntryTo(...)` | Zip-Slip — no path traversal sanitisation | CWE-22 |

---

> [!NOTE]
> All vulnerabilities are deliberate and documented. This testbed is part of the **PolyMorph** academic security research project studying polyglot file attack chains. See the project root `README.md` for context.
