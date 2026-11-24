# ⚠️ INTENTIONALLY VULNERABLE LAB — LOCAL RESEARCH ONLY

> **DISCLAIMER**: This testbed contains **deliberate, unfixed security vulnerabilities** for academic security research and controlled demonstrations. It is designed for use on a **local, isolated machine only**. **NEVER** expose this environment to any network, deploy it to any server, or use it against systems you do not own. The authors accept no liability for misuse.

---

# PolyMorph — Tier 3: Cloud-Native Testbed

**Research Focus:** File-upload bypass vulnerabilities in cloud-native S3-backed architectures.

**Vulnerabilities demonstrated:**
1. Pre-signed URL bypass (server validation completely skipped)
2. Parser differential attack → Zip-Slip (python-magic vs zipfile)
3. Public bucket MIME confusion (no `Content-Disposition: attachment`, no `nosniff`)

---

## Architecture

```
Browser (port 8080)
    │
    ├─► Nginx (static frontend)
    │
    ├─► FastAPI backend (port 8000)     ← python-magic validation here
    │       │
    │       └─► MinIO S3 (port 9000)   ← pre-signed upload bypasses backend entirely
    │
    └─► MinIO S3 (port 9000) ──────────── direct PUT via pre-signed URL (bypass path)
```

---

## Quick Start

```bash
cd testbed/tier3_cloud
docker compose up --build
```

| Service           | URL                                        | Credentials          |
|-------------------|--------------------------------------------|----------------------|
| Frontend          | http://localhost:8080                      | —                    |
| FastAPI backend   | http://localhost:8000                      | —                    |
| API docs (Swagger)| http://localhost:8000/docs                 | —                    |
| MinIO Console     | http://localhost:9001                      | minioadmin/minioadmin|
| MinIO S3 API      | http://localhost:9000                      | minioadmin/minioadmin|

---

## Attack Vectors

### Attack Vector 1: Pre-signed URL Bypass

**What it demonstrates:** The backend issues a time-limited signed URL. The client uses it to PUT a file **directly** into MinIO, bypassing all server-side validation (MIME checks, size limits, antivirus, etc.).

**Steps:**
1. Open `http://localhost:8080`
2. Select **"Pre-signed URL Upload (Bypass)"** radio button
3. Choose any file (e.g., a `.php` webshell, a `.html` file with XSS payload, or malware)
4. Optionally override the **Content-Type** field (e.g., set it to `image/png` while uploading a `.php` file)
5. Click **Upload File**
6. The file is stored in MinIO — the FastAPI backend **never inspects the bytes**

**Vulnerable code:** [`backend/main.py` — `get_upload_url()`](backend/main.py)

```python
# VULNERABILITY: content_type is user-controlled and not validated
url = s3.generate_presigned_url(
    "put_object",
    Params={"Bucket": BUCKET_NAME, "Key": filename, "ContentType": content_type},
    ExpiresIn=300,
)
```

**Real-world impact:** Attacker uploads PHP webshell, JavaScript backdoor, malware binary, or a config file override directly into the storage bucket without any gatekeeper.

---

### Attack Vector 2: Parser Differential → Zip-Slip

**What it demonstrates:** Two consumers of the same file make different trust decisions — python-magic sees a valid image header, while Python's `zipfile` module finds a valid ZIP structure appended at the end. The resulting extraction contains no path-traversal protection (Zip-Slip).

**Steps:**
1. Create a PNG+ZIP polyglot file (a valid PNG with a ZIP payload appended):
   ```bash
   # Craft polyglot: PNG header + ZIP payload
   cat sample.png malicious.zip > polyglot_avatar.png
   ```
   Or use a ZIP with a path-traversal entry:
   ```python
   import zipfile
   with zipfile.ZipFile("evil.zip", "w") as zf:
       zf.writestr("../../tmp/pwned.txt", "Zip-Slip payload!")
   # then: cat sample.png evil.zip > polyglot_avatar.png
   ```
2. Upload `polyglot_avatar.png` via **either** upload mode
3. Click **"Validate Uploaded File"** (or call `POST /validate-upload?filename=polyglot_avatar.png`)
4. Response will contain:
   ```json
   {
     "magic_mime": "image/png",
     "magic_pass": true,
     "zip_detected": true,
     "zip_entries": ["../../tmp/pwned.txt"],
     "differential_gap": "File passes image validation but also contains ZIP payload!",
     "extracted_to": "/tmp/polymorph_extracted"
   }
   ```
5. ZIP entries are extracted **without path sanitization** — a `../../etc/cron.d/backdoor` entry achieves Zip-Slip in a real system.

**Vulnerable code:** [`backend/main.py` — `validate_upload()`](backend/main.py)

```python
# No path traversal check — entry could be "../../etc/cron.d/backdoor"
extract_path = os.path.join(extract_dir, entry)
with zf.open(entry) as src, open(extract_path, 'wb') as dst:
    dst.write(src.read())
```

---

### Attack Vector 3: Public Bucket MIME Confusion

**What it demonstrates:** MinIO serves objects with no `Content-Disposition: attachment` and no `X-Content-Type-Options: nosniff` header. A polyglot file (PNG + HTML payload in tEXt chunk) opened directly in a browser may be rendered as HTML and execute JavaScript.

**Steps:**
1. Create a PNG with an HTML payload (or a file named `.png` that is actually HTML):
   ```bash
   echo '<html><script>alert("XSS from MinIO!")</script></html>' > xss.png
   ```
2. Upload `xss.png` via **Pre-signed URL mode** with `Content-Type: text/html`
3. Open the object URL directly: `http://localhost:9000/uploads/xss.png`
4. Browser receives the file without `nosniff` or `attachment` headers — may render and execute HTML/JS

**Root cause:** MinIO `init_bucket.sh` sets the bucket to `public` with no object-level response headers enforced.

---

## File Structure

```
tier3_cloud/
├── docker-compose.yml          # Orchestrates all services
├── README.md                   # This file
├── backend/
│   ├── main.py                 # FastAPI app (intentionally vulnerable)
│   ├── requirements.txt        # Python dependencies
│   └── Dockerfile              # Backend container image
├── frontend/
│   └── index.html              # Single-page UI (Bootstrap 5)
└── minio/
    └── init_bucket.sh          # Creates and publicizes the 'uploads' bucket
```

---

## Stopping the Lab

```bash
docker compose down -v   # -v also removes the MinIO data volume
```

---

*Part of the PolyMorph academic security research project. All vulnerabilities are intentional and documented. For educational use only.*
