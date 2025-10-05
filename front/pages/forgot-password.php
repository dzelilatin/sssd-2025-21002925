<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Include the configuration file
require_once __DIR__ . '/../../config_default.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password</title>
    <link rel="stylesheet" href="../assets/css/forgotpw.css">
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
</head>
<body>
    <div class="forgot-password-container">
        <h2>Forgot Password</h2>
        <form id="forgot-password-form" action="#" onsubmit="return false;">
            <div class="input-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <button type="submit">Submit</button>
            <div id="captcha-container" class="h-captcha" data-sitekey="<?php echo HCAPTCHA_SITE_KEY; ?>" style="display: none;"></div>

        </form>
        <div id="message"></div>
        <div class="links">
            <a href="login.php">Back to Login</a>
        </div>
    </div>

    <script src="../assets/js/forgot-password.js"></script>
</body>
</html>
