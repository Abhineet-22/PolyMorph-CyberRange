<?php
// INTENTIONALLY VULNERABLE: Academic Research Lab - Do NOT deploy to production
// LFI sink: include($_GET['page']) with no sanitization
?>
<!-- INTENTIONALLY VULNERABLE: Academic Research Lab - Do NOT deploy to production -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PolyMorph Lab — User Profile</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    <style>
        body { background: #f0f2f5; }
        .profile-card { max-width: 720px; margin: 40px auto; }
        .avatar-wrap { width: 120px; height: 120px; border-radius: 50%; overflow: hidden; background: #ddd; }
        .avatar-wrap img { width: 100%; height: 100%; object-fit: cover; }
        .gallery-thumb { width: 80px; height: 80px; object-fit: cover; border-radius: 6px; border: 1px solid #ccc; }
        .lab-badge { background: #dc3545; color: #fff; font-size: 0.75rem; padding: 2px 8px; border-radius: 4px; }
    </style>
</head>
<body>
<div class="container">
    <div class="profile-card card shadow-sm p-4">

        <!-- Lab warning banner -->
        <div class="alert alert-danger d-flex align-items-center mb-4" role="alert">
            <strong class="me-2">⚠️ INTENTIONALLY VULNERABLE</strong>
            <span>Academic Research Lab — <em>Do NOT deploy to production</em></span>
            <span class="lab-badge ms-auto">PolyMorph Tier 1</span>
        </div>

        <!-- Avatar & basic info -->
        <div class="d-flex align-items-center mb-4">
            <div class="avatar-wrap me-4">
                <?php
                // Display the most recently uploaded file as avatar (if any)
                $uploads_dir = __DIR__ . '/uploads/';
                $avatar_src  = 'https://via.placeholder.com/120x120?text=No+Photo';
                if (is_dir($uploads_dir)) {
                    $files = array_filter(scandir($uploads_dir), fn($f) => !in_array($f, ['.', '..']));
                    if (!empty($files)) {
                        $latest = end($files);
                        $avatar_src = 'uploads/' . htmlspecialchars($latest);
                    }
                }
                ?>
                <img src="<?= $avatar_src ?>" alt="User Avatar" id="avatar-img">
            </div>
            <div>
                <h4 class="mb-1">Lab User</h4>
                <p class="text-muted mb-0">lab@polymorph.local</p>
                <small class="text-muted">Member since 2024</small>
            </div>
        </div>

        <hr>

        <!-- Edit Profile / Upload section -->
        <h5 class="mb-3">Edit Profile</h5>
        <form action="upload.php" method="POST" enctype="multipart/form-data" class="mb-3">
            <div class="mb-3">
                <label for="file" class="form-label fw-semibold">Upload Profile Photo</label>
                <input class="form-control" type="file" id="file" name="file" accept="image/*">
                <div class="form-text">Accepted: JPG, JPEG, PNG, GIF</div>
            </div>
            <button type="submit" class="btn btn-primary">Upload</button>
        </form>

        <?php
        // Show upload result flash message
        if (isset($_GET['upload'])) {
            $msg = $_GET['upload'] === 'ok'
                ? '<div class="alert alert-success">File uploaded successfully.</div>'
                : '<div class="alert alert-danger">Upload failed: ' . htmlspecialchars($_GET['msg'] ?? 'unknown error') . '</div>';
            echo $msg;
        }
        ?>

        <!-- Uploaded files gallery -->
        <h6 class="mt-2 mb-2">Previously Uploaded Files</h6>
        <div class="d-flex flex-wrap gap-2 mb-4">
        <?php
        if (is_dir($uploads_dir)) {
            $gallery_files = array_filter(scandir($uploads_dir), fn($f) => !in_array($f, ['.', '..', '.htaccess', '.htaccess_vulnerable']));
            if (empty($gallery_files)) {
                echo '<span class="text-muted small">No files uploaded yet.</span>';
            } else {
                foreach ($gallery_files as $gf) {
                    $thumb = 'uploads/' . htmlspecialchars($gf);
                    echo '<a href="' . $thumb . '" target="_blank">'
                       . '<img src="' . $thumb . '" class="gallery-thumb" alt="' . htmlspecialchars($gf) . '" '
                       . 'onerror="this.src=\'https://via.placeholder.com/80x80?text=File\'">'
                       . '</a>';
                }
            }
        }
        ?>
        </div>

        <hr>

        <!-- ────────────────────────────────────────────────
             LFI SINK — "View Page" section
             INTENTIONALLY VULNERABLE: include($_GET['page'])
             ──────────────────────────────────────────────── -->
        <h5 class="mb-2">View Page</h5>
        <p class="text-muted small mb-2">
            Load a local page by name. <span class="text-danger fw-bold">[LFI vector — research use only]</span>
        </p>
        <form method="GET" class="mb-3">
            <div class="input-group mb-2">
                <span class="input-group-text">File path:</span>
                <input type="text"
                       name="page"
                       class="form-control"
                       placeholder="e.g. uploads/shell.jpg"
                       value="<?= htmlspecialchars($_GET['page'] ?? '') ?>">
            </div>
            <div class="input-group mb-2">
                <span class="input-group-text">Command:</span>
                <input type="text"
                       name="cmd"
                       class="form-control"
                       placeholder="e.g. whoami or id or ls -la"
                       value="<?= htmlspecialchars($_GET['cmd'] ?? 'id') ?>">
                <button type="submit" class="btn btn-danger">Execute via LFI</button>
            </div>
        </form>

        <?php
        // ── INTENTIONALLY VULNERABLE: LFI via unsanitised $_GET['page'] ──
        // No path traversal protection, no allowlist, no realpath check.
        if (isset($_GET['page']) && $_GET['page'] !== '') {
            $page = $_GET['page'];
            echo '<div class="alert alert-warning small"><strong>Current page param:</strong> '
               . htmlspecialchars($page) . '</div>';

            // VULNERABLE include — do not sanitise (intentional for research)
            include($page);
        }
        ?>

    </div><!-- /.profile-card -->
</div><!-- /.container -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
