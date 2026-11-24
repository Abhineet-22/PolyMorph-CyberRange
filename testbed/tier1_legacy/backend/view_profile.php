<?php
// view_profile.php — thin redirect wrapper
// The primary LFI sink lives in index.php (?page=...)
header('Location: index.php');
exit;
