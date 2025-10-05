<?php
// Enable error reporting
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Use the Flight namespace and Controller class
use Flight as Flight;
use Sssd\Controller;
use OpenApi\Annotations as OA;
use OTPHP\TOTP;
use Google\Client;
use Firebase\JWT\JWT;

// Include the Composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config_default.php';
require_once 'Controller.php';
require_once __DIR__ . '/../utils/Utils.php';

// Register the database connection with Flight
Flight::register('db', 'PDO', array(
    "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";port=" . DB_PORT . ";charset=utf8mb4",
    DB_USERNAME,
    DB_PASSWORD
));

// Create a controller instance
$controller = new Controller();

// Define routes using the controller
Flight::route('POST /register', array($controller, 'register'));
Flight::route('POST /login', array($controller, 'login'));
Flight::route('POST /verify-2fa', array($controller, 'verify2FA'));
Flight::route('POST /send-2fa-code', array($controller, 'send2FACode'));
Flight::route('POST /forgot-password', array($controller, 'forgotPassword'));
Flight::route('POST /reset-password', array($controller, 'resetPassword'));
Flight::route('POST /generate-recovery-codes', array($controller, 'generateRecoveryCodes'));
Flight::route('POST /verify-recovery-code', array($controller, 'verifyRecoveryCodeAPI'));
Flight::route('POST /verify-totp', array($controller, 'verifyTOTPDirect'));
Flight::route('POST /delete-user', array($controller, 'deleteUser'));

// Google OAuth routes
Flight::route('GET /google-login', function () {
    $client = Utils::getGoogleClient();
    $authUrl = $client->createAuthUrl();
    if ($authUrl) {
        Flight::json(['authUrl' => $authUrl]);
    } else {
        Flight::json(['error' => 'Unable to create auth URL'], 500);
    }
});

Flight::route('GET /google-callback', function () {
    $client = Utils::getGoogleClient();

    if (!isset(Flight::request()->query['code'])) {
        Flight::json(['error' => 'Authorization code not provided'], 400);
        return;
    }

    $authCode = Flight::request()->query['code'];
    $token = $client->fetchAccessTokenWithAuthCode($authCode);

    if (isset($token['error'])) {
        Flight::json(['error' => $token['error_description']], 400);
        return;
    }

    $client->setAccessToken($token['access_token']);
    $oauth2 = new \Google\Service\Oauth2($client);
    $googleUserInfo = $oauth2->userinfo->get();

    // Check if user exists
    $stmt = Flight::db()->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$googleUserInfo->email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Generate a username from email prefix and ensure uniqueness
        $username = explode('@', $googleUserInfo->email)[0];
        $baseUsername = $username;
        $counter = 1;
        while (true) {
            $stmtCheck = Flight::db()->prepare("SELECT id FROM users WHERE username = ?");
            $stmtCheck->execute([$username]);
            if (!$stmtCheck->fetch()) break;
            $username = $baseUsername . $counter;
            $counter++;
        }
        // Create new user
        $stmt = Flight::db()->prepare("
            INSERT INTO users (email, full_name, username, google_id, is_verified) 
            VALUES (?, ?, ?, ?, 1)
        ");
        $stmt->execute([
            $googleUserInfo->email,
            $googleUserInfo->givenName . ' ' . $googleUserInfo->familyName,
            $username,
            $googleUserInfo->id
        ]);
        $userId = Flight::db()->lastInsertId();
    } else {
        $userId = $user['id'];
    }

    // Generate a session token (but don't mark as authenticated yet)
    $sessionToken = bin2hex(random_bytes(32));
    $stmt = Flight::db()->prepare("
        INSERT INTO user_sessions (user_id, session_token, created_at, expires_at, authenticated) 
        VALUES (:user_id, :session_token, NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR), 0)
    ");
    
    $stmt->execute([
        ':user_id' => $userId,
        ':session_token' => $sessionToken
    ]);

    // Redirect to login page or 2FA selection page with the session token
    // The frontend will then prompt for 2FA
    
    // Get the protocol (http or https)
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
    
    // Get the host (domain name)
    $host = $_SERVER['HTTP_HOST'];

    // Get the script name (e.g., /sssd-2025-21002925/api/index.php)
    $scriptName = $_SERVER['SCRIPT_NAME'];

    // Determine the position of the API entry point within the script name
    // Assuming your API is routed through api/index.php
    $apiPos = strpos($scriptName, '/api/index.php');

    // If /api/index.php is found, the base directory is the part before it
    if ($apiPos !== false) {
        $baseDir = substr($scriptName, 0, $apiPos);
    } else {
         // Fallback: find the last / and take everything before it
         $lastSlashPos = strrpos($scriptName, '/');
         if ($lastSlashPos !== false) {
              $baseDir = substr($scriptName, 0, $lastSlashPos);
         } else {
              $baseDir = ''; // Should not happen for web requests usually
         }
    }

    // Ensure baseDir doesn't end with / unless it's just /
    if (substr($baseDir, -1) === '/' && $baseDir !== '/') {
        $baseDir = rtrim($baseDir, '/');
    }
    
    // Construct the base URL (e.g., http://localhost/sssd-2025-21002925)
    $baseUrl = "{$protocol}://{$host}{$baseDir}";
    
    // Construct the redirect URL dynamically
    $redirectUrl = "{$baseUrl}/front/pages/login.php?session_token=" . $sessionToken;

    header('Location: ' . $redirectUrl);
    exit;
});

// Route to check Infobip account status
Flight::route('GET /check-infobip-status', function() {
    $controller = new Controller();
    $status = $controller->checkInfobipAccountStatus();
    Flight::json(['status' => 'success', 'infobip_status' => $status]);
});

Flight::route('/', function() {
    echo 'Welcome to the SSSD API';
});

// Test SMS route
Flight::route('GET /test/send-sms', function() {
    $controller = new Controller();
    $controller->testSendSMS();
});

// Test Email route
Flight::route('GET /test/send-email', function() {
    $controller = new Controller();
    $controller->testSendEmail();
});

// Add this route for testing email
Flight::route('GET /test-email', function() {
    $controller = new \Sssd\Controller();
    $controller->testSendEmail();
});

// TOTP routes
Flight::route('GET /generate-qr-code', function() {
    $controller = new Controller();
    $controller->generateNewQRCode();
});

Flight::route('GET /test', function() {
    echo "Test route works!";
});

// Add this route for verifying email
Flight::route('GET /verify-email', array($controller, 'verifyEmail'));

// Add this endpoint to check if captcha should be shown
Flight::route('GET /should-show-captcha', function() {
    try {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $identifier = $_GET['username'] ?? $_GET['email'] ?? '';
    $db = Flight::db();
        error_log('DEBUG: should-show-captcha check for identifier: ' . $identifier . ' at IP: ' . $ip);
        
        if (empty($identifier)) {
            Flight::json(['show_captcha' => false]);
            return;
        }
        
    $stmt = $db->prepare("SELECT COUNT(*) as fail_count FROM login_attempts WHERE (username = :identifier OR email = :identifier OR ip_address = :ip) AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)");
    $stmt->execute([':identifier' => $identifier, ':ip' => $ip]);
    $failCount = $stmt->fetch(PDO::FETCH_ASSOC)['fail_count'] ?? 0;
        error_log('DEBUG: should-show-captcha fail_count: ' . $failCount);
        
    Flight::json(['show_captcha' => $failCount >= 3]);
    } catch (\Exception $e) {
        error_log('Error in should-show-captcha: ' . $e->getMessage());
        Flight::json(['show_captcha' => false, 'error' => 'An error occurred while checking captcha status']);
    }
});

// Add route to get username for logged-in user
Flight::route('GET /get-username', array($controller, 'getUsername'));

// Add route to change password for logged-in user
Flight::route('POST /change-password', array($controller, 'changePassword'));

// Add route to get user's 2FA methods
Flight::route('GET /get-user-2fa-methods', array($controller, 'getUser2FAMethods'));

// Add route for user logout
Flight::route('POST /logout', array($controller, 'logout'));

// Start the FlightPHP framework
Flight::start();
