<?php
// Same backdoor as above, but with a variable assignment in between.
// Will NOT trigger our regex: this is the known evasion technique we admit.
// Catching this requires AST analysis; a simple regex scanner cannot do it.
$to = $_POST['to'];
$subj = $_POST['subj'];
$body = $_POST['body'];
mail($to, $subj, $body);
?>
