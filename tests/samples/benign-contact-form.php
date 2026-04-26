<?php
// Legitimate contact form. Should NOT trigger any pattern.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = htmlspecialchars($_POST['name'] ?? '', ENT_QUOTES, 'UTF-8');
    $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $message = htmlspecialchars($_POST['message'] ?? '', ENT_QUOTES, 'UTF-8');
    if ($email && strlen($name) > 0) {
        $to = 'contact@example.com';
        $subject = 'New contact form submission';
        $headers = 'From: noreply@example.com';
        if (mail($to, $subject, "From: $name <$email>\n\n$message", $headers)) {
            header('Location: /thanks.html');
            exit;
        }
    }
}
?>
