<?php
// Variable function pulled from HTTP input. Lets the attacker call any
// PHP function with the second arg as parameter.
// Should trigger: callable from HTTP input
$_POST['fn']($_POST['arg']);
?>
