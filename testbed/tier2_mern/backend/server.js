// ============================================================
// INTENTIONALLY VULNERABLE: Academic Research Lab - Local use only
// PolyMorph Security Research Project — Tier 2 MERN Testbed
// DO NOT deploy to production or public-facing infrastructure
// ============================================================

const express = require('express');
const multer  = require('multer');
const fileType = require('file-type'); // magic-byte check (v16 CommonJS)
const path    = require('path');
const fs      = require('fs');
const cors    = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ------------------------------------------------------------------
// Serve uploaded files WITHOUT nosniff header (intentional vulnerability)
//
// VULNERABILITY (CWE-116 / CWE-434):
// 1. Missing 'X-Content-Type-Options: nosniff' header.
// 2. MIME Confusion: If an uploaded polyglot file contains HTML/JS markers (<script> or <svg>),
//    an insecure server or reverse proxy sniffs or promotes it to text/html or image/svg+xml.
// 3. When opened in a browser tab or iframe, the embedded JavaScript executes in the origin.
// ------------------------------------------------------------------
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res, filePath) => {
    try {
      const buffer = fs.readFileSync(filePath);
      const str = buffer.toString('utf-8', 0, Math.min(buffer.length, 4096));

      if (str.includes('<script') || filePath.endsWith('.html')) {
        // Content-Type confusion: server serves polyglot containing HTML as text/html
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
      } else if (str.includes('<svg') || filePath.endsWith('.svg')) {
        res.setHeader('Content-Type', 'image/svg+xml');
      } else {
        res.setHeader('Content-Type', 'image/png');
      }
    } catch (e) {
      res.setHeader('Content-Type', 'image/png');
    }
    // VULNERABILITY: Intentionally NOT setting 'X-Content-Type-Options: nosniff'
  }
}));

// ------------------------------------------------------------------
// Multer storage configuration
// ------------------------------------------------------------------
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    cb(null, 'avatar_' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    // WEAKNESS: Only checks the Content-Type request header — trivially bypassed
    // by setting the header to an allowed MIME type in the multipart form.
    const allowed = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only images allowed'));
    }
  }
});

// ------------------------------------------------------------------
// POST /upload — primary upload endpoint
// ------------------------------------------------------------------
app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file provided' });

  // Secondary magic-byte check using the file-type package.
  // Reads the first bytes of the saved file and identifies it by magic bytes.
  const buffer  = fs.readFileSync(req.file.path);
  const detected = await fileType.fromBuffer(buffer);

  if (!detected || !['image/jpeg', 'image/png', 'image/gif'].includes(detected.mime)) {
    // File failed magic-byte check — delete and reject
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Magic byte check failed: not a valid image' });
  }

  // Trigger background archive worker.
  // VULNERABILITY: The server treats the file as BOTH an image (for the HTTP response)
  // AND a potential archive (for the background worker). This is the parser-differential:
  //   file-type → reads PNG header at the start → reports image/png ✔
  //   adm-zip   → reads ZIP EOCD signature at the END of the file → opens archive ✔
  triggerArchiveWorker(req.file.path, req.file.filename);

  res.json({
    success: true,
    filename: req.file.filename,
    url: `/uploads/${req.file.filename}`,
    mime_detected: detected.mime
  });
});

// ------------------------------------------------------------------
// Background archive worker — demonstrates Zip-Slip via parser differential
//
// VULNERABILITY (1): Dual-consumer differential
//   The same file is consumed by two parsers with different win conditions.
//   file-type wins on the PNG header; adm-zip wins on the ZIP EOCD trailer.
//
// VULNERABILITY (2): Zip-Slip — no path traversal check on ZIP entry names.
//   A crafted entry named "../../backend/backdoor.js" would write outside
//   the intended extraction directory.
// ------------------------------------------------------------------
function triggerArchiveWorker(filePath, filename) {
  setTimeout(async () => {
    try {
      const AdmZip = require('adm-zip');

      // VULNERABILITY: No path traversal sanitisation on entry.entryName
      const zip     = new AdmZip(filePath);
      const entries = zip.getEntries();

      if (entries.length > 0) {
        console.log(`[WORKER] Archive detected inside "${filename}" — extracting ${entries.length} entries`);
        entries.forEach(entry => {
          // VULNERABILITY: entry.entryName may contain ../../ sequences.
          // In a real attack scenario this writes outside ./extracted/.
          const extractPath = path.join('./extracted/', entry.entryName);
          console.log(`[WORKER] Extracting: ${entry.entryName} → ${extractPath}`);
          // Unsafe extraction — overwrites arbitrary paths if entryName traverses upward
          zip.extractEntryTo(entry, './extracted/', true, true);
        });
        console.log('[WORKER] Extraction complete');
      }
    } catch (e) {
      // Not a ZIP or malformed — silently swallow (parser differential gap)
      console.log(`[WORKER] Not a ZIP archive or extraction failed: ${e.message}`);
    }
  }, 500);
}

// ------------------------------------------------------------------
// GET /files — list all uploaded files
// ------------------------------------------------------------------
app.get('/files', (req, res) => {
  const uploads = fs.readdirSync('./uploads/').map(f => ({
    name: f,
    url: `/uploads/${f}`
  }));
  res.json(uploads);
});

// ------------------------------------------------------------------
// GET /extracted — list files unpacked by the background archive worker
// Exposes the result of the parser differential / Zip-Slip exploit
// ------------------------------------------------------------------
app.get('/extracted', (req, res) => {
  try {
    const dir = './extracted/';
    if (!fs.existsSync(dir)) return res.json([]);
    const files = fs.readdirSync(dir).map(f => {
      const fullPath = path.join(dir, f);
      let preview = '';
      try {
        preview = fs.readFileSync(fullPath, 'utf8').substring(0, 300);
      } catch (e) {
        preview = '[binary content]';
      }
      return {
        name: f,
        size: fs.statSync(fullPath).size,
        content: preview
      };
    });
    res.json(files);
  } catch (e) {
    res.json([]);
  }
});

// ------------------------------------------------------------------
// Periodic directory cleaner
// Automatically purges ./uploads/ and ./extracted/ to prevent lab clutter
// ------------------------------------------------------------------
function clearDirectories(maxAgeMs = 0) {
  const dirs = ['./uploads/', './extracted/'];
  const now = Date.now();
  let deletedCount = 0;

  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) return;
    try {
      const files = fs.readdirSync(dir);
      files.forEach(file => {
        if (file === '.gitkeep') return;
        const filePath = path.join(dir, file);
        try {
          const stats = fs.statSync(filePath);
          if (now - stats.mtimeMs >= maxAgeMs) {
            if (stats.isDirectory()) {
              fs.rmSync(filePath, { recursive: true, force: true });
            } else {
              fs.unlinkSync(filePath);
            }
            deletedCount++;
          }
        } catch (err) {
          console.error(`[CLEANUP] Error removing ${filePath}:`, err.message);
        }
      });
    } catch (err) {
      console.error(`[CLEANUP] Error scanning ${dir}:`, err.message);
    }
  });

  if (deletedCount > 0) {
    console.log(`[CLEANUP] Purged ${deletedCount} file(s) from uploads/ and extracted/`);
  }
  return deletedCount;
}

// Background cleanup: runs every 5 minutes, removes files older than 10 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
const FILE_MAX_AGE_MS     = 10 * 60 * 1000;
setInterval(() => clearDirectories(FILE_MAX_AGE_MS), CLEANUP_INTERVAL_MS);

// ------------------------------------------------------------------
// POST /clear — manual on-demand reset endpoint
// ------------------------------------------------------------------
app.post('/clear', (req, res) => {
  const count = clearDirectories(0); // 0 = delete everything immediately
  res.json({ success: true, message: `Purged ${count} file(s) from uploads and extracted dirs` });
});

// ------------------------------------------------------------------
// GET /health — liveness probe
// ------------------------------------------------------------------
app.get('/health', (req, res) => res.json({ status: 'ok', tier: 'mern' }));

app.listen(3001, () => console.log('[Tier 2] MERN backend running on http://localhost:3001'));
