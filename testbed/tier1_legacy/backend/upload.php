<?php
// INTENTIONALLY VULNERABLE: Academic Research Lab
// Weakness 1: Only checks file extension (bypassed by double extensions like avatar.php.jpg)
// Weakness 2: Uses exif_imagetype() which reads magic bytes but allows PHP-in-JPEG polyglots
// Weakness 3: Saves to webroot (uploads/ is inside document root — directly accessible via HTTP)
// Weakness 4: Preserves original filename (no UUID rename) enabling predictable path for LFI

$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$upload_dir = __DIR__ . '/uploads/';

// Ensure uploads directory exists
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

// Validate a file was actually sent
if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    $err_code = $_FILES['file']['error'] ?? 'no file';
    header('Location: index.php?upload=fail&msg=' . urlencode("Upload error code: $err_code"));
    exit;
}

// ── Weakness 1: Extension-only check ──────────────────────────────────────────
// Attacker bypasses by uploading avatar.php.jpg — extension is 'jpg', passes.
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_extensions)) {
    header('Location: index.php?upload=fail&msg=' . urlencode("Extension '$ext' not allowed"));
    exit;
}

// ── Weakness 2: Magic-byte check via exif_imagetype() ─────────────────────────
// exif_imagetype() checks the first few bytes (magic bytes) of the file.
// A JPEG+PHP polyglot starts with FF D8 FF (valid JPEG header), so it passes.
// The PHP engine later finds PHP code tags inside the binary data and executes them.
$image_type = exif_imagetype($_FILES['file']['tmp_name']);
if ($image_type === false) {
    header('Location: index.php?upload=fail&msg=' . urlencode('Not a valid image (magic byte check failed)'));
    exit;
}

// ── Weakness 3 & 4: Save to webroot with original filename ────────────────────
// No UUID rename → attacker knows exact path → exploitable via LFI or direct request.
$filename  = basename($_FILES['file']['name']);
$dest_path = $upload_dir . $filename;

if (move_uploaded_file($_FILES['file']['tmp_name'], $dest_path)) {
    // Return JSON if request expects it (e.g., curl/scripted exploit)
    if (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'path' => 'uploads/' . $filename]);
    } else {
        header('Location: index.php?upload=ok');
    }
} else {
    header('Location: index.php?upload=fail&msg=' . urlencode('move_uploaded_file() failed — check directory permissions'));
}
exit;
