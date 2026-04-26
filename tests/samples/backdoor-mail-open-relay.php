<?php
// mail() with destination taken directly from request input. Open relay
// used by spam botnets that take over a site to send phishing email.
// Direct call is what the simple regex catches.
// Should trigger: mail() open relay
mail($_POST['to'], $_POST['subj'], $_POST['body']);
?>
