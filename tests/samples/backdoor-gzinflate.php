<?php
// eval(gzinflate(base64_decode(...))) chain. Common obfuscation technique
// to hide a backdoor as a compressed blob.
// Should trigger: eval(base64_decode) AND eval(gzinflate)
eval(gzinflate(base64_decode('aGVsbG8=')));
?>
