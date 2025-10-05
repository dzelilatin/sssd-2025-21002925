<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Include the configuration file
require_once __DIR__ . '/../../config_default.php';

// Track failed attempts (you can replace this with a session or DB check)
$failedAttempts = isset($_SESSION['failed_attempts']) ? $_SESSION['failed_attempts'] : 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
      window.onCaptchaLoad = function() {
        // This just needs to exist for hCaptcha to load
        // The actual logic is handled in your JS file
        console.log('hCaptcha loaded');
      };
    </script>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    <title>Login Form</title>
    <link rel="stylesheet" href="/sssd-2025-21002925/front/assets/css/login.css">
    <style>
        .login-button {
            width: 100%;
            padding: 12px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            margin-top: 20px;
            transition: background-color 0.3s ease;
            display: block !important;
            visibility: visible !important;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        <form id="loginForm" class="login-form">
            <div class="input-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" placeholder="Username or Email" required autocomplete="username">
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Password" required autocomplete="current-password">
            </div>
            <div id="captcha-container" style="display:<?php echo ($failedAttempts >= 3) ? 'block' : 'none'; ?>;">
                <div class="h-captcha" data-sitekey="<?php echo HCAPTCHA_SITE_KEY; ?>"></div>
            </div>
            <button type="submit" id="loginButton" class="login-button">Login</button>
        </form>
        <button id="google-signin-button" class="google-signin-button">Sign in with Google</button>
        <div class="links">
            <a href="signup.html">Sign Up</a> | 
            <a href="forgot-password.php">Forgot Password?</a>
        </div>
    </div>

    <script src="/sssd-2025-21002925/front/assets/js/login.js"></script>
</body>
</html>
