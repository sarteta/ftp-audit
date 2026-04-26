<?php
// assert() over user input. PHP 7+ deprecated but still common in legacy hacks.
// Should trigger: assert() over input
if (isset($_POST['cmd'])) {
    assert($_POST['cmd']);
}
?>
