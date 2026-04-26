<?php
// Classic eval(base64_decode(...)) backdoor seen in mass-injection campaigns.
// Should trigger: eval(base64_decode) - backdoor classico
$payload = "ZWNobyAnaGFja2VkJzs=";
eval(base64_decode($payload));
?>
