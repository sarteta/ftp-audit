<?php
// Obfuscated backdoor that splits "eval" into pieces. Will NOT trigger our
// pattern matcher, on purpose: this is the limitation we admit in the README.
$a = 'ev'.'al';
$b = 'ba'.'se64_de'.'code';
$a($b('ZWNobyAnaGFja2VkJzs='));
?>
