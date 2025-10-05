<?php

namespace Sssd;

use Flight;
use OpenApi\Annotations as OA;
use PDO;
use PDOException;
use OTPHP\TOTP;
use libphonenumber\PhoneNumberUtil;
use libphonenumber\PhoneNumberType;
use libphonenumber\NumberParseException;
use PHPMailer\PHPMailer\PHPMailer;

require_once __DIR__ . '/../config_default.php';
require_once __DIR__ . '/../vendor/autoload.php';

class Controller {

    private $db;
    private $reservedUsernames = ['admin', 'root', 'system', 'administrator'];

    public function __construct() {
        global $db;
        
        // Check if the global $db variable exists and is a PDO instance
        if (isset($db) && $db instanceof PDO) {
            // echo "Controller: Database connection is valid.<br>";
            $this->db = $db;
        } else {
            // If not, create a new database connection using config constants
            try {
                $host = defined('DB_HOST') ? DB_HOST : 'localhost';
                $dbname = defined('DB_NAME') ? DB_NAME : '';
                $user = defined('DB_USERNAME') ? DB_USERNAME : '';
                $pass = defined('DB_PASSWORD') ? DB_PASSWORD : '';
                $port = defined('DB_PORT') && DB_PORT !== '' ? DB_PORT : '3306';
                // If you want to support socket, add DB_SOCKET to config and use it here
                if (defined('DB_SOCKET') && DB_SOCKET !== '') {
                    $dsn = "mysql:unix_socket=" . DB_SOCKET . ";dbname=$dbname;charset=utf8mb4";
                } else {
                    $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";
                }
                $this->db = new PDO($dsn, $user, $pass);
                $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            } catch (PDOException $e) {
                // Log the error and throw an exception
                error_log('Database connection failed: ' . $e->getMessage());
                throw new \Exception('Database connection failed. Please check your configuration.');
            }
        }
    }

    private function isPasswordPwned($password) {
        $sha1Password = strtoupper(sha1($password));
        $prefix = substr($sha1Password, 0, 5);
        $suffix = substr($sha1Password, 5);
        $ch = curl_init("https://api.pwnedpasswords.com/range/" . $prefix);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        $response = curl_exec($ch);

        if ($response === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new \Exception("Could not retrieve data from the HIBP API. cURL error: " . $error);
        }

        curl_close($ch);
        return strpos($response, $suffix) !== false;
    }

    private function isValidUsername($username) {
        return preg_match('/^[a-zA-Z0-9]{4,}$/', $username);
    }

    private function isValidPhoneNumber($phone) {
        return preg_match('/^\+?[1-9]\d{9,14}$/', $phone);
    }

    /* private function isValidEmailDomain($email) {
        $domain = substr(strrchr($email, "@"), 1);
        return checkdnsrr($domain, "MX");
    } */

    public function testSendSMS() {
        try {
            echo "Entering testSendSMS function"; // Debugging line
            
            // Get phone number from query parameter or use default
            $phone = isset($_GET['phone']) ? trim($_GET['phone']) : '+387603380987';
            
            // Ensure phone number has the correct format
            if (!preg_match('/^\+/', $phone)) {
                $phone = '+' . $phone;
            }
            
            // Remove any spaces or special characters from the phone number
            $phone = preg_replace('/[^0-9+]/', '', $phone);
            
            // Generate verification code
            $verificationCode = rand(100000, 999999); // Random 6-digit code
            
            // Log the test parameters
            error_log("Testing SMS with phone: $phone and code: $verificationCode");
            
            // Call the method that sends SMS
            $this->sendVerificationSMS($phone, $verificationCode);
        
            // Respond with success message
            if (class_exists('Flight')) {
                Flight::json([
                    'status' => 'success', 
                    'message' => 'Test SMS sent successfully.',
                    'phone' => $phone,
                    'code' => $verificationCode // Including the code for testing purposes
                ]);
            } else {
                echo json_encode([
                    'status' => 'success', 
                    'message' => 'Test SMS sent successfully.',
                    'phone' => $phone,
                    'code' => $verificationCode // Including the code for testing purposes
                ]);
            }
        } catch (\Exception $e) {
            // Log the error
            error_log("Error in testSendSMS: " . $e->getMessage());
            
            // Return error response
            if (class_exists('Flight')) {
                Flight::json([
                    'status' => 'error',
                    'message' => 'Failed to send SMS: ' . $e->getMessage()
                ], 500);
            } else {
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Failed to send SMS: ' . $e->getMessage()
                ]);
            }
        }
    }
    
    /**
     * Check the Infobip account status
     */
    public function checkInfobipAccountStatus() {
        try {
            $curl = curl_init();
            
            if ($curl === false) {
                throw new \Exception("Failed to initialize cURL");
            }
            
            // NOTE: You may need to change this URL to the correct Infobip
            // endpoint for checking account status. For now, we use the base
            // part of your existing SMS API URL.
            $baseUrl = preg_replace('/\/sms\/2\/text\/advanced$/', '', INFOBIP_SMS_API_URL);
            $statusUrl = $baseUrl . '/account/1/status'; // Example endpoint, check Infobip docs

            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt_array($curl, array(
                // Use the constant for the URL
                CURLOPT_URL => $statusUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST => 'GET',
                CURLOPT_HTTPHEADER => array(
                    // Use the constant for the API Key
                    'Authorization: App ' . TEXT_MESSAGE_API_KEY,
                    'Accept: application/json'
                ),
            ));
            
            $response = curl_exec($curl);
            
            if ($response === false) {
                $error = curl_error($curl);
                curl_close($curl);
                throw new \Exception("cURL error: " . $error);
            }
            
            $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            
            // Log the response and HTTP code
            error_log("Infobip account status response code: $httpCode");
            error_log("Infobip account status response: " . $response);
            
            curl_close($curl);
            
            return $response;
        } catch (\Exception $e) {
            error_log("Error checking Infobip account status: " . $e->getMessage());
            return null;
        }
    }
    
    public function sendVerificationSMS($mobile_number, $code) {
        try {
            // Trim any whitespace from the phone number
            $mobile_number = trim($mobile_number);
            
            // Log the request details
            error_log("Attempting to send SMS to: $mobile_number with code: $code");
            
            $curl = curl_init();
            
            if ($curl === false) {
                throw new \Exception("Failed to initialize cURL");
            }

            // Prepare the request payload
            $payload = json_encode([
                "messages" => [
                    [
                        "destinations" => [["to" => $mobile_number]],
                        "from" => "InfoSMS",
                        "text" => "Verification code: $code"
                    ]
                ]
            ]);
            
            // Log the request payload
            error_log("SMS request payload: $payload");

            $apiUrl = INFOBIP_SMS_API_URL;
            
            // Log the API URL
            error_log("Using Infobip API URL: $apiUrl");
            
            // Use the API key from config
            $apiKey = TEXT_MESSAGE_API_KEY;
            
            // Log the API key (without the full key for security)
            error_log("Using Infobip API key: " . substr($apiKey, 0, 10) . "...");

            // Set cURL options
            curl_setopt_array($curl, array(
                CURLOPT_URL => $apiUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST => 'POST',
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_HTTPHEADER => array(
                    "Authorization: App " . $apiKey,
                    'Content-Type: application/json',
                    'Accept: application/json'
                ),
                CURLOPT_TIMEOUT => 30,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_VERBOSE => true,
                CURLOPT_SSL_VERIFYPEER => false
            ));

            // Create a temporary file to store the verbose output
            $verbose = fopen('php://temp', 'w+');
            curl_setopt($curl, CURLOPT_STDERR, $verbose);
            error_log('DEBUG: Executing Infobip cURL request...');

            $response = curl_exec($curl);
            error_log('DEBUG: Infobip cURL executed.');

            // Capture verbose output regardless of success/failure
            rewind($verbose);
            $verboseLog = stream_get_contents($verbose);
            error_log("Infobip cURL verbose output: " . $verboseLog);
            
            if ($response === false) {
                $error = curl_error($curl);
                curl_close($curl);
                throw new \Exception("Infobip cURL error: " . $error);
            }
            
            $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            
            // Log the response and HTTP code
            error_log("Infobip API response code: $httpCode");
            error_log("Infobip API response body: " . $response);
            
            // Close curl before checking HTTP code to ensure output captured
            curl_close($curl);

            if ($httpCode >= 400) {
                // Decode response to include potential Infobip error message
                $responseData = json_decode($response, true);
                $errorMessage = isset($responseData['requestError']['serviceException']['text']) ? $responseData['requestError']['serviceException']['text'] : 'Unknown Infobip error';
                throw new \Exception("Infobip API returned error code: " . $httpCode . ", Message: " . $errorMessage . ", Response: " . $response);
            }

            // Infobip successful response usually contains results array
            $responseData = json_decode($response, true);
            if (!isset($responseData['messages']) || count($responseData['messages']) === 0 || isset($responseData['messages'][0]['status']['groupId']) && $responseData['messages'][0]['status']['groupId'] !== 0) {
                $errorMessage = isset($responseData['messages'][0]['status']['groupName']) ? $responseData['messages'][0]['status']['groupName'] : 'SMS not sent successfully';
                throw new \Exception("Infobip reported non-success status. Message: " . $errorMessage . ", Response: " . $response);
            }
            
            // Log success for debugging
            error_log("SMS sent successfully to $mobile_number with code $code.");
            
            return true; // Indicate success
        } catch (\Exception $e) {
            error_log("Error sending SMS: " . $e->getMessage());
            // Re-throw to be caught by the caller and returned in JSON
            throw $e;
        }
    }

    public function generateNewQRCode() {
        // Get the authorization header
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        
        if (empty($authHeader) || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            Flight::json(['status' => 'error', 'message' => 'No valid authorization token provided.'], 401);
            return;
        }
        
        $token = $matches[1];
        
        // Verify the token and get user ID
        $stmt = $this->db->prepare("
            SELECT user_id 
            FROM user_sessions 
            WHERE session_token = :token 
            AND expires_at > NOW()
            LIMIT 1
        ");
        
        $stmt->execute([':token' => $token]);
        $session = $stmt->fetch(\PDO::FETCH_ASSOC);
        
        if (!$session) {
            Flight::json(['status' => 'error', 'message' => 'Invalid or expired token.'], 401);
            return;
        }
        
        $userId = $session['user_id'];
        
        // Generate new TOTP secret
        $newSecret = TOTP::generate()->getSecret();
        error_log("Generated new TOTP secret: " . $newSecret);
        
        // Update user's OTP secret in database
        $stmt = $this->db->prepare("
            UPDATE users 
            SET otp_secret = :secret 
            WHERE id = :user_id
        ");
        
        $stmt->execute([
            ':secret' => $newSecret,
            ':user_id' => $userId
        ]);
        
        // Get user's email for the QR code label
        $stmt = $this->db->prepare("SELECT email FROM users WHERE id = :user_id");
        $stmt->execute([':user_id' => $userId]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);
        
        // Generate QR code URI
        $otp = TOTP::createFromSecret($newSecret);
        $otp->setLabel($user['email']);
        $qrCodeUri = $otp->getProvisioningUri();
        
        // Return the QR code URL and current OTP for testing
        Flight::json([
            'status' => 'success',
            'message' => 'QR code generated successfully',
            'qr_code_url' => $qrCodeUri,
            'current_otp' => $otp->now(),
            'secret' => $newSecret // Including secret for testing purposes
        ]);
    }
    
    private function validatePhoneNumber($phoneNumber) {
        $phoneUtil = PhoneNumberUtil::getInstance();

        try {
            // Parse the phone number with the default region (Bosnia and Herzegovina)
            $parsedNumber = $phoneUtil->parse($phoneNumber, "BA");

            // Check if the number is valid
            if (!$phoneUtil->isValidNumber($parsedNumber)) {
                return [
                    'valid' => false,
                    'message' => 'Broj telefona nije validan'
                ];
            }

            // Check if the number belongs to Bosnia and Herzegovina
            $countryCode = $parsedNumber->getCountryCode();
            if ($countryCode !== 387) {
                return [
                    'valid' => false,
                    'message' => 'Broj telefona nije iz Bosne i Hercegovine'
                ];
            }

            // Return valid if all checks pass
            return [
                'valid' => true,
                'message' => 'Broj telefona je validan',
                'formatted_number' => $phoneUtil->format($parsedNumber, \libphonenumber\PhoneNumberFormat::E164)
            ];
        } catch (NumberParseException $e) {
            return [
                'valid' => false,
                'message' => 'Greška pri validaciji broja: ' . $e->getMessage()
            ];
        }
    }

    private function validateEmailTLD($email) {
        // Extract the TLD
        $parts = explode('.', $email);
        $tld = strtolower(end($parts));

        // Get valid TLDs from IANA
        $validTLDs = $this->getValidTLDs();

        // Check if the TLD is valid
        if (!in_array($tld, $validTLDs)) {
            return [
                'valid' => false,
                'message' => 'Invalid TLD in email address.'
            ];
        }

        return [
            'valid' => true,
            'message' => 'Valid TLD.'
        ];
    }

    private function getValidTLDs() {
        // Cache file path
        $cacheFile = __DIR__ . '/../cache/tlds.json';
        $cacheExpiry = 86400; // 24 hours

        // Create cache directory if it doesn't exist
        if (!is_dir(dirname($cacheFile))) {
            try {
                if (!@mkdir(dirname($cacheFile), 0755, true)) {
                    error_log("Failed to create cache directory: " . dirname($cacheFile));
                    // If we can't create the cache directory, just return the fallback list
                    return $this->getFallbackTLDs();
                }
            } catch (\Exception $e) {
                error_log("Error creating cache directory: " . $e->getMessage());
                return $this->getFallbackTLDs();
            }
        }

        // Check if cache exists and is valid
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < $cacheExpiry)) {
            try {
                $cachedData = json_decode(file_get_contents($cacheFile), true);
                if ($cachedData && isset($cachedData['tlds'])) {
                    return $cachedData['tlds'];
                }
            } catch (\Exception $e) {
                error_log("Error reading cache file: " . $e->getMessage());
                return $this->getFallbackTLDs();
            }
        }

        try {
            // Fetch TLDs from IANA with proper error handling
            $context = stream_context_create([
                'http' => [
                    'timeout' => 10,
                    'user_agent' => 'SSSD/1.0'
                ],
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false
                ]
            ]);

            $tldData = @file_get_contents('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', false, $context);
            
            if ($tldData === false) {
                throw new \Exception("Failed to fetch TLD list from IANA");
            }

            // Process the TLD list
            $tlds = array_filter(
                array_map(
                    function($line) {
                        $line = trim($line);
                        // Skip comments and empty lines
                        if (empty($line) || $line[0] === '#') {
                            return null;
                        }
                        return strtolower($line);
                    },
                    explode("\n", $tldData)
                )
            );

            // Try to save to cache, but don't fail if we can't
            try {
                if (file_put_contents($cacheFile, json_encode([
                    'tlds' => $tlds,
                    'last_updated' => time()
                ])) === false) {
                    error_log("Failed to write TLD cache file: " . $cacheFile);
                }
            } catch (\Exception $e) {
                error_log("Error writing cache file: " . $e->getMessage());
            }

            return $tlds;
        } catch (\Exception $e) {
            error_log("Error fetching TLD list: " . $e->getMessage());
            return $this->getFallbackTLDs();
        }
    }

    private function getFallbackTLDs() {
        return [
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'io', 'co', 'me', 'tv', 'xyz',
            'ba', 'rs', 'hr', 'si', 'me', 'mk', 'al', 'eu', 'de', 'uk', 'us', 'ca', 'au', 'nz', 'jp', 'cn',
            'tech', 'app', 'dev', 'cloud', 'online', 'site', 'website', 'blog', 'store', 'shop'
        ];
    }

    private function validateMXRecord($email) {
        $domain = substr(strrchr($email, "@"), 1);

        // Log the domain being validated
        error_log("Validating MX record for domain: " . $domain);

        // Check if the domain has MX records
        if (getmxrr($domain, $mx_details)) {
            error_log("MX records found for domain: " . $domain);
            error_log("MX details: " . print_r($mx_details, true));
            return [
                'valid' => true,
                'message' => 'Valid MX record found.',
                'mx_records' => $mx_details
            ];
        } else {
            error_log("No MX records found for domain: " . $domain);
            return [
                'valid' => false,
                'message' => 'No valid MX record found for the email domain.',
                'domain' => $domain
            ];
        }
    }

    private function sendEmail($to, $subject, $body) {
        // Create an instance; passing `true` enables exceptions
        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);

        try {
            // Server settings
            $mail->SMTPDebug = \PHPMailer\PHPMailer\SMTP::DEBUG_SERVER;  // Enable verbose debug output
            $mail->isSMTP();                                              // Send using SMTP
            $mail->Host = SMTP_HOST;                                      // Set the SMTP server to send through (SendGrid)
            $mail->SMTPAuth = true;                                       // Enable SMTP authentication
            $mail->Username = SMTP_USERNAME;                              // SMTP username (for SendGrid, this is 'apikey')
            $mail->Password = SMTP_PASSWORD;                              // SMTP password (SendGrid API key)
            $mail->SMTPSecure = SMTP_ENCRYPTION === 'ssl' ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = SMTP_PORT;                                      // TCP port to connect to
            
            // Additional SMTP options for better reliability
            $mail->SMTPOptions = array(
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true
                )
            );
            
            // Set timeout
            $mail->Timeout = 60; // 60 seconds timeout
            
            // Custom debug output function
            $mail->Debugoutput = function($str, $level) {
                error_log("PHPMailer Debug [$level]: $str");
            };

            // Log attempt to send email
            error_log("Attempting to send email to: $to");
            error_log("SMTP Host: {$mail->Host}, Port: {$mail->Port}, Username: {$mail->Username}");
            
            // Recipients
            $mail->setFrom('dzelilatin@dzelilat.tech', 'SSSD System'); // Use a verified sender in SendGrid
            $mail->addAddress($to);                                       // Add a recipient
            
            // Content
            $mail->isHTML(true);                                          // Set email format to HTML
            $mail->Subject = $subject;
            $mail->Body = "
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
                        .content { padding: 20px; }
                        .footer { text-align: center; padding: 20px; font-size: 0.9em; color: #666; }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <div class='header'>
                            <h2>SSSD System</h2>
                        </div>
                        <div class='content'>
                            {$body}
                        </div>
                        <div class='footer'>
                            <p>This is an automated message, please do not reply.</p>
                        </div>
                    </div>
                </body>
                </html>";
            $mail->AltBody = strip_tags($body);                           // Plain text version for non-HTML mail clients
            
            // Send email
            $mail->send();
            error_log("Email sent successfully to: " . $to);
            return true;
        } catch (\Exception $e) {
            error_log("Failed to send email to: " . $to);
            error_log("SMTP Error: " . $mail->ErrorInfo);
            error_log("Exception: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            throw new \Exception("Email could not be sent. Mailer Error: " . $mail->ErrorInfo);
        }
    }

    /**
     * @OA\Post(
     *   path="/register",
     *   summary="Register a new user",
     *   description="Register a new user with email verification.",
     *   tags={"Users"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"username", "email", "password", "full_name", "phone"},
     *           @OA\Property(property="full_name", type="string", example="John Doe"),
     *           @OA\Property(property="username", type="string", example="johndoe"),
     *           @OA\Property(property="email", type="string", format="email", example="johndoe@example.com"),
     *           @OA\Property(property="password", type="string", format="password", example="password123"),
     *           @OA\Property(property="phone", type="string", example="+1234567890")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="User registered successfully",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="User registered successfully. Please check your email to confirm your registration."),
     *           @OA\Property(property="confirmation_required", type="boolean", example=true)
     *       )
     *   ),
     *   @OA\Response(
     *       response=400,
     *       description="Validation failed",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="error"),
     *           @OA\Property(property="errors", type="array", 
     *               @OA\Items(type="string", example="Username must be at least 4 characters.")
     *           )
     *       )
     *   )
     * )
     */
    public function register() {
        try {
            // Ensure no output before JSON response
            ob_clean();
            
            $data = Flight::request()->data->getData();
            error_log("Registration attempt data: " . print_r($data, true));
            $errors = [];
        
            if (empty($data['full_name'])) {
                $errors[] = "Full Name is required.";
            } else {
                // Full name must be at least two words, each at least 2 characters
                $nameParts = preg_split('/\s+/', trim($data['full_name']));
                if (count($nameParts) < 2) {
                    $errors[] = "Full Name must contain at least two words.";
                } else {
                    foreach ($nameParts as $part) {
                        if (mb_strlen($part) < 2) {
                            $errors[] = "Each part of the Full Name must be at least 2 characters.";
                            break;
                        }
                    }
                }
            }
        
            if (empty($data['username'])) {
                $errors[] = "Username is required.";
            } elseif (in_array(strtolower($data['username']), $this->reservedUsernames)) {
                $errors[] = "This username is reserved.";
            } elseif (!$this->isValidUsername($data['username'])) {
                $errors[] = "Username must be at least 4 characters, letters/numbers only.";
            } else {
                // Check if username already exists (case-insensitive)
                $stmt = $this->db->prepare("SELECT id FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1");
                $stmt->execute([$data['username']]);
                if ($stmt->fetch()) {
                    $errors[] = "This username is already taken.";
                }
            }
        
            if (empty($data['password'])) {
                $errors[] = "Password is required.";
            } elseif (strlen($data['password']) < 8 || 
                      !preg_match('/[A-Z]/', $data['password']) || 
                      !preg_match('/[a-z]/', $data['password']) || 
                      !preg_match('/\d/', $data['password']) || 
                      !preg_match('/[\W_]/', $data['password'])) {
                $errors[] = "Password must be 8+ characters with upper/lowercase, number, special char.";
            } elseif ($this->isPasswordPwned($data['password'])) {
                $errors[] = "Password is compromised. Use a different one.";
            }
        
            if (empty($data['phone']) || !$this->validatePhoneNumber($data['phone'])['valid']) {
                $errors[] = "Valid Bosnian mobile phone number is required.";
            }

            // Email validation
            if (empty($data['email'])) {
                $errors[] = "Email is required.";
            } else {
                // First, validate the email format
                if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
                    $errors[] = "Invalid email format.";
                } else {
                    try {
                        // Validate the TLD
                        $tldValidation = $this->validateEmailTLD($data['email']);
                        error_log("TLD validation result: " . print_r($tldValidation, true));
                        if (!$tldValidation['valid']) {
                            $errors[] = $tldValidation['message'];
                        }

                        // Validate the email domain's MX record
                        $mxValidation = $this->validateMXRecord($data['email']);
                        error_log("MX validation result: " . print_r($mxValidation, true));
                        if (!$mxValidation['valid']) {
                            $errors[] = $mxValidation['message'];
                        }
                    } catch (\Exception $e) {
                        error_log("Error during email validation: " . $e->getMessage());
                        $errors[] = "Error validating email: " . $e->getMessage();
                    }
                }
            }

            // If there are any errors, return them
            if (!empty($errors)) {
                error_log("Registration validation errors: " . print_r($errors, true));
                Flight::json(['status' => 'error', 'errors' => $errors], 400);
                return;
            }

            // If we get here, all validations passed
            $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);
            $otp_secret = TOTP::generate()->getSecret();

            try {
                $stmt = $this->db->prepare("INSERT INTO users (full_name, username, email, password, phone, otp_secret, is_verified) VALUES (?, ?, ?, ?, ?, ?, 0)");
                $stmt->execute([
                    $data['full_name'],
                    $data['username'],
                    $data['email'],
                    $hashedPassword,
                    $data['phone'],
                    $otp_secret
                ]);

                // Generate a secure verification token
                $verificationToken = bin2hex(random_bytes(32));
                $expiresAt = date('Y-m-d H:i:s', strtotime('+24 hours'));

                // Store the verification token
                $stmt = $this->db->prepare("
                    INSERT INTO email_verifications (user_id, token, expires_at, created_at) 
                    VALUES (LAST_INSERT_ID(), ?, ?, NOW())
                ");
                $stmt->execute([$verificationToken, $expiresAt]);

                // Send verification email with link
                $verificationLink = "http://localhost/sssd-2025-21002925/api/verify-email?token=" . $verificationToken;
                $emailSubject = "Welcome to SSSD - Verify Your Email";
                $emailBody = "
                    <h2>Welcome to SSSD!</h2>
                    <p>Dear {$data['full_name']},</p>
                    <p>Thank you for registering with us. To complete your registration, please verify your email address by clicking the link below:</p>
                    <p><a href='{$verificationLink}' style='display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;'>Verify Email Address</a></p>
                    <p>Or copy and paste this link in your browser:</p>
                    <p>{$verificationLink}</p>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you did not request this registration, please ignore this email.</p>
                    <br>
                    <p>Best regards,<br>SSSD Team</p>
                ";

                error_log("Attempting to send verification email to: " . $data['email']);
                try {
                    $this->sendEmail($data['email'], $emailSubject, $emailBody);
                    error_log("Verification email sent successfully to: " . $data['email']);
                } catch (\Exception $e) {
                    error_log("Failed to send verification email: " . $e->getMessage());
                    error_log("Email error details: " . $e->getTraceAsString());
                    // Continue with registration even if email fails
                }

                // Ensure clean output before sending JSON response
                ob_clean();
                Flight::json([
                    'status' => 'success',
                    'message' => 'User registered successfully. Please check your email to confirm your registration.',
                    'confirmation_required' => true
                ]);
            } catch (\PDOException $e) {
                error_log("Database error during registration: " . $e->getMessage());
                if ($e->getCode() === '23000' && strpos($e->getMessage(), 'Duplicate entry') !== false) {
                    if (strpos($e->getMessage(), 'username') !== false) {
                        $message = "This username is already taken.";
                    } elseif (strpos($e->getMessage(), 'email') !== false) {
                        $message = "This email is already registered.";
                    } elseif (strpos($e->getMessage(), 'phone') !== false) {
                        $message = "This phone number is already registered.";
                    } else {
                        $message = "Duplicate entry detected.";
                    }

                    ob_clean();
                    Flight::json([
                        'status' => 'error',
                        'message' => $message
                    ], 400);
                } else {
                    ob_clean();
                    Flight::json([
                        'status' => 'error',
                        'message' => 'An unexpected error occurred. Please try again later.'
                    ], 500);
                }
            }
        } catch (\Exception $e) {
            error_log("Unexpected error during registration: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            ob_clean();
            Flight::json([
                'status' => 'error',
                'message' => 'An unexpected error occurred: ' . $e->getMessage()
            ], 500);
        }
    }

    // Add this function to verify hCaptcha
    private function verify_hcaptcha($hcaptcha_response) {
        $secret = HCAPTCHA_SERVER_SECRET; // Replace with your real secret key
        $data = [
            'secret' => $secret,
            'response' => $hcaptcha_response
        ];
        $verify = curl_init();
        curl_setopt($verify, CURLOPT_URL, "https://hcaptcha.com/siteverify");
        curl_setopt($verify, CURLOPT_POST, true);
        curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($verify);
        $responseData = json_decode($response);
        return $responseData && $responseData->success;
    }

    /**
     * @OA\Post(
     *   path="/login",
     *   summary="User login",
     *   description="Login a user.",
     *   tags={"Users"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"password"},
     *           @OA\Property(property="username", type="string", example="johndoe"),
     *           @OA\Property(property="email", type="string", format="email", example="johndoe@example.com"),
     *           @OA\Property(property="password", type="string", format="password", example="password123")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="Login successful",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="Choose your 2FA method"),
     *           @OA\Property(property="user_id", type="integer", example=1)
     *       )
     *   )
     * )
     */
    public function login() {
        try {
            error_log('DEBUG: Raw POST data: ' . file_get_contents('php://input'));
            $data = Flight::request()->data->getData();
            error_log("Login attempt data: " . print_r($data, true));

            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $identifier = $data['username'] ?? $data['email'] ?? '';

            // Count failed attempts in the last 10 minutes
            $stmt = $this->db->prepare("
                SELECT COUNT(*) as fail_count FROM login_attempts
                WHERE (username = :identifier OR email = :identifier OR ip_address = :ip)
                AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
            ");
            $stmt->execute([':identifier' => $identifier, ':ip' => $ip]);
            $failCount = $stmt->fetch(\PDO::FETCH_ASSOC)['fail_count'] ?? 0;
            error_log('DEBUG: failCount for ' . $identifier . ' at IP ' . $ip . ' = ' . $failCount);
            error_log('DEBUG: POST data: ' . print_r($data, true));

            // hCaptcha verification if too many failed attempts
            if ($failCount >= 3) {
                if (empty($data['h-captcha-response']) || !$this->verify_hcaptcha($data['h-captcha-response'])) {
                    Flight::json(['status' => 'error', 'message' => 'Captcha failed. Please try again.', 'show_captcha' => true], 400);
                    return;
                }
            }

            if (empty($data['username']) && empty($data['email'])) {
                Flight::json(['status' => 'error', 'message' => 'Username or Email is required.'], 400);
                return;
            }

            if (empty($data['password'])) {
                Flight::json(['status' => 'error', 'message' => 'Password is required.'], 400);
                return;
            }

            try {
                error_log("Attempting database connection...");
                $stmt = $this->db->prepare("
                    SELECT id, password, full_name, email, phone, otp_secret, is_verified FROM users 
                    WHERE username = :username OR LOWER(email) = LOWER(:email)
                    LIMIT 1
                ");
                $params = [
                    ':username' => $data['username'] ?? '',
                    ':email' => trim($data['email'] ?? '')
                ];
                error_log("Executing query with params: :username = '" . $params[':username'] . "', :email = '" . $params[':email'] . "'");
                $stmt->execute($params);
                $user = $stmt->fetch(\PDO::FETCH_ASSOC);
                error_log('DEBUG: User found: ' . print_r($user, true));
                if ($user) {
                    error_log('DEBUG: Input password: ' . $data['password']);
                    error_log('DEBUG: Stored hash: ' . $user['password']);
                    $passwordCheck = password_verify($data['password'], $user['password']);
                    error_log('DEBUG: password_verify result: ' . ($passwordCheck ? 'true' : 'false'));
                }
                error_log("Query result: " . print_r($user, true));

                if ($user && password_verify($data['password'], $user['password'])) {
                    // Check if email is verified
                    if (!$user['is_verified']) {
                        Flight::json([
                            'status' => 'error',
                            'message' => 'Please verify your email address before logging in.',
                            'email_verification_required' => true
                        ], 403);
                        return;
                    }

                    error_log("Password verified successfully for user ID: " . $user['id']);
                    // Reset failed attempts on successful login (optional: delete old attempts)
                    $stmt = $this->db->prepare("DELETE FROM login_attempts WHERE (username = :identifier OR email = :identifier OR ip_address = :ip)");
                    $stmt->execute([':identifier' => $identifier, ':ip' => $ip]);
                    
                    // Generate a session token
                    $sessionToken = bin2hex(random_bytes(32));
                    error_log("Generated session token: " . $sessionToken);
                    
                    // Store session token in database
                    $stmt = $this->db->prepare("
                        INSERT INTO user_sessions (user_id, session_token, created_at, expires_at) 
                        VALUES (:user_id, :session_token, NOW(), DATE_ADD(NOW(), INTERVAL 24 HOUR))
                    ");
                    
                    $stmt->execute([
                        ':user_id' => $user['id'],
                        ':session_token' => $sessionToken
                    ]);
                    error_log("Session token stored in database");
                    
                    // Store user info in session
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['full_name'] = $user['full_name'];
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['session_token'] = $sessionToken;
                    error_log("Session variables set");
                    
                    // Return success with 2FA options
                    Flight::json([
                        'status' => 'success',
                        'message' => 'Choose your 2FA method',
                        'user_id' => $user['id'],
                        'session_token' => $sessionToken,
                        '2fa_methods' => [
                            'sms' => !empty($user['phone']),
                            'totp' => !empty($user['otp_secret']),
                            'email' => !empty($user['email'])
                        ]
                    ]);
                } else {
                    // Log failed attempt
                    error_log('DEBUG: Login failed. Attempting to log failed attempt.');
                    $userId = $user['id'] ?? null;
                    $stmt = $this->db->prepare("INSERT INTO login_attempts (user_id, username, email, ip_address, created_at) VALUES (:user_id, :username, :email, :ip, NOW())");
                    try {
                        $stmt->execute([
                            ':user_id' => $userId,
                            ':username' => $data['username'] ?? null,
                            ':email' => $data['email'] ?? null,
                            ':ip' => $ip
                        ]);
                        error_log('DEBUG: Failed attempt logged successfully.');
                    } catch (\PDOException $e) {
                        error_log('ERROR: Failed to insert login attempt into database: ' . $e->getMessage());
                    }
                    error_log("Invalid credentials for username/email: " . ($data['username'] ?? $data['email']));
                    Flight::json([
                        'status' => 'error',
                        'message' => 'Login failed. Incorrect username or password.',
                        'show_captcha' => $failCount >= 3
                    ], 400);
                }
            } catch (\PDOException $e) {
                error_log("Database error during login: " . $e->getMessage());
                error_log("Stack trace: " . $e->getTraceAsString());
                Flight::json([
                    'status' => 'error',
                    'message' => 'Database error: ' . $e->getMessage()
                ], 500);
            }
        } catch (\Exception $e) {
            error_log("Unexpected error during login: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            Flight::json([
                'status' => 'error',
                'message' => 'An unexpected error occurred: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *   path="/verify-2fa",
     *   summary="Verify 2FA",
     *   description="Verify 2FA code for login.",
     *   tags={"Authentication"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"method", "code", "session_token"},
     *           @OA\Property(property="method", type="string", example="sms", enum={"sms", "totp", "email"}),
     *           @OA\Property(property="code", type="string", example="123456"),
     *           @OA\Property(property="session_token", type="string", example="abc123")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="2FA verification successful",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="Login successful"),
     *           @OA\Property(property="user", type="object")
     *       )
     *   )
     * )
     */
    public function verify2FA() {
        error_log('DEBUG: verify2FA function entered.'); // New debug log at the start
        $data = Flight::request()->data->getData();
        error_log('DEBUG: verify2FA received data: ' . print_r($data, true)); // Log received data
        
        if (empty($data['method']) || empty($data['code']) || empty($data['session_token'])) {
            error_log('DEBUG: verify2FA: Missing required fields');
            Flight::json(['status' => 'error', 'message' => 'Method, code, and session token are required.'], 400);
            return;
        }
        
        try {
            // Verify session token
            $stmt = $this->db->prepare("
                SELECT user_id FROM user_sessions 
                WHERE session_token = :session_token AND expires_at > NOW()
                LIMIT 1
            ");
            $stmt->execute([':session_token' => $data['session_token']]);
            $session = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$session) {
                error_log('DEBUG: verify2FA: Invalid or expired session');
                Flight::json(['status' => 'error', 'message' => 'Invalid or expired session.'], 401);
                return;
            }
            
            // Get user data
            $stmt = $this->db->prepare("
                SELECT id, full_name, email, phone, otp_secret FROM users 
                WHERE id = :user_id
                LIMIT 1
            ");
            $stmt->execute([':user_id' => $session['user_id']]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$user) {
                error_log('DEBUG: verify2FA: User not found');
                Flight::json(['status' => 'error', 'message' => 'User not found.'], 404);
                return;
            }
            
            $verificationSuccess = false;
            
            // Verify based on method
            switch ($data['method']) {
                case 'sms':
                    $verificationSuccess = $this->verifySMSCode($user['phone'], $data['code']);
                    break;
                case 'totp':
                    $verificationSuccess = $this->verifyTOTPCode($user['otp_secret'], $data['code']);
                    break;
                case 'email':
                    $verificationSuccess = $this->verifyEmailCode($user['email'], $data['code']);
                    break;
                case 'recovery_code':
                    error_log('DEBUG: verify2FA: Attempting recovery code verification');
                    $stmt = $this->db->prepare("
                        SELECT id, code FROM recovery_codes 
                        WHERE user_id = :user_id AND code = :code AND used = 0
                        LIMIT 1
                    ");
                    
                    $bindParams = [
                        ':user_id' => $user['id'],
                        ':code' => $data['code']
                    ];
                    error_log('DEBUG: verify2FA: Recovery code query params: ' . json_encode($bindParams));
                    
                    $stmt->execute($bindParams);
                    $recoveryCode = $stmt->fetch(\PDO::FETCH_ASSOC);
                    error_log('DEBUG: verify2FA: Recovery code query result: ' . json_encode($recoveryCode));
                    
                    if ($recoveryCode) {
                        error_log('DEBUG: verify2FA: Valid recovery code found');
                        // Mark recovery code as used
                        $stmt = $this->db->prepare("
                            UPDATE recovery_codes 
                            SET used = 1, used_at = NOW() 
                            WHERE id = :id
                        ");
                        $stmt->execute([':id' => $recoveryCode['id']]);
                        $verificationSuccess = true;
                    } else {
                        error_log('DEBUG: verify2FA: Invalid or used recovery code');
                    }
                    break;
                default:
                    error_log('DEBUG: verify2FA: Invalid 2FA method: ' . $data['method']);
                    Flight::json(['status' => 'error', 'message' => 'Invalid 2FA method.'], 400);
                    return;
            }
            
            if ($verificationSuccess) {
                error_log('DEBUG: verify2FA: Verification successful');
                // Update session to mark as fully authenticated
                $stmt = $this->db->prepare("
                    UPDATE user_sessions 
                    SET authenticated = 1, authenticated_at = NOW() 
                    WHERE session_token = :session_token
                ");
                $stmt->execute([':session_token' => $data['session_token']]);
                
                // Return success with user data
                Flight::json([
                    'status' => 'success',
                    'message' => 'Login successful',
                    'user' => [
                        'id' => $user['id'],
                        'full_name' => $user['full_name'],
                        'email' => $user['email']
                    ],
                    'session_token' => $data['session_token']
                ]);
            } else {
                error_log('DEBUG: verify2FA: Verification failed');
                Flight::json(['status' => 'error', 'message' => 'Invalid verification code.'], 400);
            }
        } catch (\PDOException $e) {
            error_log("Database error during 2FA verification: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            Flight::json([
                'status' => 'error',
                'message' => 'An unexpected error occurred. Please try again later.'
            ], 500);
        }
    }
    
    /**
     * Verify SMS code
     */
    private function verifySMSCode($phone, $code) {
        try {
            // In a real implementation, you would check against a stored code
            // For this example, we'll just check if the code is a 6-digit number
            return preg_match('/^\d{6}$/', $code);
        } catch (\Exception $e) {
            error_log("Error verifying SMS code: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Verify TOTP code
     */
    private function verifyTOTPCode($secret, $code) {
        try {
            if (empty($secret)) {
                return false;
            }
            
            // Create TOTP object
            $totp = TOTP::createFromSecret($secret);
            
            // Verify the code
            return $totp->verify($code);
        } catch (\Exception $e) {
            error_log("Error verifying TOTP code: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Verify email code
     */
    private function verifyEmailCode($email, $code) {
        try {
            // Find the most recent valid email verification code for the user
            $stmt = $this->db->prepare("
                SELECT vc.id
                FROM verification_codes vc
                JOIN users u ON vc.user_id = u.id
                WHERE u.email = :email
                AND vc.code = :code
                AND vc.method = 'email'
                AND vc.expires_at > NOW()
                ORDER BY vc.created_at DESC
                LIMIT 1
            ");
            $stmt->execute([
                ':email' => $email,
                ':code' => $code
            ]);
            $verificationCode = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($verificationCode) {
                // Mark the code as used
                $stmt = $this->db->prepare("
                    UPDATE verification_codes
                    SET used = 1
                    WHERE id = :id
                ");
                $stmt->execute([':id' => $verificationCode['id']]);
                error_log("Email 2FA code verified successfully for email: " . $email);
                return true;
            } else {
                error_log("Invalid or expired Email 2FA code for email: " . $email);
                return false;
            }
        } catch (\Exception $e) {
            error_log("Error verifying email code: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Internal method to verify recovery code
     */
    private function _verifyRecoveryCodeInternal($userId, $code) {
        error_log('DEBUG: _verifyRecoveryCodeInternal function entered.');
        try {
            // Verify recovery code
            error_log('DEBUG: _verifyRecoveryCodeInternal: Received code: ' . $code);
            error_log('DEBUG: _verifyRecoveryCodeInternal: Querying for recovery code for user ID: ' . $userId);
            $stmt = $this->db->prepare("
                SELECT id, code FROM recovery_codes 
                WHERE user_id = :user_id AND code = :code AND used = 0
                LIMIT 1
            ");
            
            // Log parameters being bound
            $bindParams = [
                ':user_id' => $userId,
                ':code' => $code
            ];
            error_log('DEBUG: _verifyRecoveryCodeInternal: Binding parameters: ' . json_encode($bindParams));

            $stmt->execute($bindParams);
            
            // Log the raw fetch result
            $recoveryCode = $stmt->fetch(\PDO::FETCH_ASSOC);
            error_log('DEBUG: _verifyRecoveryCodeInternal: Raw fetch result: ' . json_encode($recoveryCode));

            if ($recoveryCode) {
                error_log('DEBUG: _verifyRecoveryCodeInternal: Code found in DB: ' . $recoveryCode['code']);
                // Mark recovery code as used
                $stmt = $this->db->prepare("
                    UPDATE recovery_codes 
                    SET used = 1, used_at = NOW() 
                    WHERE id = :id
                ");
                $stmt->execute([':id' => $recoveryCode['id']]);
                return true;
            }

            error_log('DEBUG: _verifyRecoveryCodeInternal: Invalid or used recovery code attempt.');
            return false;
        } catch (\Exception $e) {
            error_log("Error in _verifyRecoveryCodeInternal: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * @OA\Post(
     *   path="/send-2fa-code",
     *   summary="Send 2FA code",
     *   description="Send 2FA code via SMS, TOTP, or email.",
     *   tags={"Authentication"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"method", "session_token"},
     *           @OA\Property(property="method", type="string", example="sms", enum={"sms", "totp", "email"}),
     *           @OA\Property(property="session_token", type="string", example="abc123")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="2FA code sent successfully",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="2FA code sent successfully")
     *       )
     *   )
     * )
     */
    public function send2FACode() {
        $data = Flight::request()->data->getData();
        
        if (empty($data['method']) || empty($data['session_token'])) {
            Flight::json(['status' => 'error', 'message' => 'Method and session token are required.'], 400);
            return;
        }
        
        try { // Wrap the main logic in a try-catch
            // Verify session token
            $stmt = $this->db->prepare("
                SELECT user_id FROM user_sessions 
                WHERE session_token = :session_token AND expires_at > NOW()
                LIMIT 1
            ");
            $stmt->execute([':session_token' => $data['session_token']]);
            $session = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$session) {
                Flight::json(['status' => 'error', 'message' => 'Invalid or expired session.'], 401);
                return;
            }
            
            // Get user data
            $stmt = $this->db->prepare("
                SELECT id, full_name, email, phone FROM users 
                WHERE id = :user_id
                LIMIT 1
            ");
            $stmt->execute([':user_id' => $session['user_id']]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$user) {
                Flight::json(['status' => 'error', 'message' => 'User not found.'], 404);
                return;
            }
            
            $code = rand(100000, 999999); // Generate a 6-digit code
            
            // Send code based on method
            switch ($data['method']) {
                case 'sms':
                    if (empty($user['phone'])) {
                        Flight::json(['status' => 'error', 'message' => 'Phone number not available.'], 400);
                        return;
                    }
                    // This call is now safely within the outer try block
                    $this->sendVerificationSMS($user['phone'], $code);
                    break;
                case 'email':
                    if (empty($user['email'])) {
                        Flight::json(['status' => 'error', 'message' => 'Email not available.'], 400);
                        return;
                    }
                    
                    // **Implement actual email sending here**
                    $emailSubject = 'Your SSSD 2FA Verification Code';
                    $emailBody = "
                        <h2>Your Verification Code</h2>
                        <p>Dear {$user['full_name']},</p>
                        <p>Your verification code is: <strong>{$code}</strong></p>
                        <p>This code is valid for 10 minutes.</p>
                        <p>If you did not request this code, please ignore this email.</p>
                        <br>
                        <p>Best regards,<br>SSSD Team</p>
                    ";
                    try {
                        $this->sendEmail($user['email'], $emailSubject, $emailBody);
                        error_log("2FA Email sent successfully to: " . $user['email']);
                    } catch (\Exception $e) {
                        error_log("Failed to send 2FA email: " . $e->getMessage());
                        // Propagate the error to the outer catch block
                        throw new \Exception("Failed to send verification email: " . $e->getMessage());
                    }
                    
                    break;
                case 'totp':
                    // TOTP doesn't need to send a code, it's generated by the authenticator app
                    Flight::json(['status' => 'success', 'message' => 'Please use your authenticator app to generate a code.']);
                    return;
                default:
                    Flight::json(['status' => 'error', 'message' => 'Invalid 2FA method.'], 400);
                    return;
            }
            
            // Store the code in the database
            $stmt = $this->db->prepare("
                INSERT INTO verification_codes (user_id, code, method, created_at, expires_at) 
                VALUES (:user_id, :code, :method, NOW(), DATE_ADD(NOW(), INTERVAL 10 MINUTE))
            ");
            $stmt->execute([
                ':user_id' => $user['id'],
                ':code' => $code,
                ':method' => $data['method']
            ]);
            
            Flight::json([
                'status' => 'success',
                'message' => '2FA code sent successfully.'
            ]);
        } catch (\Exception $e) { // Catch any exception in the process
            error_log("Error in send2FACode: " . $e->getMessage());
            Flight::json([
                'status' => 'error',
                'message' => 'Failed to send 2FA code: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *   path="/forgot-password",
     *   summary="Request password reset",
     *   description="Request a password reset link.",
     *   tags={"Authentication"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"email"},
     *           @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="Password reset link sent",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="Password reset link sent to your email.")
     *       )
     *   )
     * )
     */
    public function forgotPassword() {
        $data = Flight::request()->data->getData();
        
        if (empty($data['email'])) {
            Flight::json(['status' => 'error', 'message' => 'Email is required.'], 400);
            return;
        }
        
        try {
            // Check if email exists
            $stmt = $this->db->prepare("
                SELECT id, email, full_name FROM users 
                WHERE email = :email
                LIMIT 1
            ");
            $stmt->execute([':email' => $data['email']]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$user) {
                // For security reasons, don't reveal that the email doesn't exist
                Flight::json([
                    'status' => 'success',
                    'message' => 'If your email is registered, you will receive a password reset link.'
                ]);
                return;
            }
            
            // Check for too many reset attempts
            $stmt = $this->db->prepare("
                SELECT COUNT(*) as attempt_count FROM password_reset_attempts 
                WHERE user_id = :user_id 
                AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
            ");
            $stmt->execute([':user_id' => $user['id']]);
            $attempts = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if ($attempts['attempt_count'] >= 2) {
                // Only require captcha if there have been multiple attempts
                if (empty($data['h-captcha-response'])) {
                    Flight::json([
                        'status' => 'error',
                        'message' => 'Too many password reset attempts. Please complete the captcha.',
                        'require_captcha' => true
                    ], 429);
                    return;
                }
            }
            
            // Generate reset token
            $resetToken = bin2hex(random_bytes(32));
            $expiresAt = date('Y-m-d H:i:s', strtotime('+5 minutes'));
            
            // Store reset token
            $stmt = $this->db->prepare("
                INSERT INTO password_resets (user_id, token, expires_at, created_at) 
                VALUES (:user_id, :token, :expires_at, NOW())
            ");
            $stmt->execute([
                ':user_id' => $user['id'],
                ':token' => $resetToken,
                ':expires_at' => $expiresAt
            ]);
            
            // Log the attempt
            $stmt = $this->db->prepare("
                INSERT INTO password_reset_attempts (user_id, created_at) 
                VALUES (:user_id, NOW())
            ");
            $stmt->execute([':user_id' => $user['id']]);
            
            // In a real implementation, you would send an email with the reset link
            // For this example, we'll just log it
            
            // Get the protocol (http or https)
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
            
            // Get the host (domain name)
            $host = $_SERVER['HTTP_HOST'];
            
            // Get the script name to determine the project path
            // Example: /sssd-2025-21002925/api/index.php
            $scriptName = $_SERVER['SCRIPT_NAME'];
            
            // Determine the base directory path (e.g., /sssd-2025-21002925/)
            // Find the position of '/api/' and take the substring before it
            // Ensure it works whether the script is index.php or something else in /api/
            $baseDir = substr($scriptName, 0, strpos($scriptName, '/api/'));

            // Construct the base URL (e.g., http://localhost/sssd-2025-21002925)
            $baseUrl = "{$protocol}://{$host}{$baseDir}";

            // Construct the reset link using the base URL and the path to the reset password page
            $resetLink = "{$baseUrl}/front/pages/reset-password.html?token=" . $resetToken;

            error_log("Password reset link for {$user['email']}: {$resetLink}");
            
            // Send the email with the reset link
            $subject = "Password Reset Request";
            $body = "Hello {$user['full_name']},

            We received a request to reset your password. Click the link below to set a new password:

            {$resetLink}

            This link will expire in 5 minutes.

            If you did not request a password reset, please ignore this email.

            Thank you,
            Your Application Team";

            // Assuming sendEmail function is implemented in Controller.php
            $emailSent = $this->sendEmail($user['email'], $subject, $body);

            if ($emailSent) {
                Flight::json([
                    'status' => 'success',
                    'message' => 'If your email is registered, you will receive a password reset link.'
                ]);
            } else {
                error_log("ERROR: Failed to send password reset email to {$user['email']}.");
                 Flight::json([
                    'status' => 'error',
                    'message' => 'Failed to send password reset email. Please try again later.'
                ], 500);
            }

        } catch (\PDOException $e) {
            error_log("Database error during password reset request: " . $e->getMessage());
            Flight::json([
                'status' => 'error',
                'message' => 'An unexpected error occurred. Please try again later.'
            ], 500);
        }
    }
    
    /**
     * @OA\Post(
     *   path="/reset-password",
     *   summary="Reset password",
     *   description="Reset password using token.",
     *   tags={"Authentication"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"token", "password", "confirm_password"},
     *           @OA\Property(property="token", type="string", example="abc123"),
     *           @OA\Property(property="password", type="string", format="password", example="newpassword123"),
     *           @OA\Property(property="confirm_password", type="string", format="password", example="newpassword123")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="Password reset successful",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="Password reset successful.")
     *       )
     *   )
     * )
     */
    public function resetPassword() {
        $data = Flight::request()->data->getData();
        
        if (empty($data['token']) || empty($data['password']) || empty($data['confirm_password'])) {
            Flight::json(['status' => 'error', 'message' => 'Token, password, and confirmation are required.'], 400);
            return;
        }
        
        if ($data['password'] !== $data['confirm_password']) {
            Flight::json(['status' => 'error', 'message' => 'Passwords do not match.'], 400);
            return;
        }
        
        // Validate password strength
        if (strlen($data['password']) < 8 || 
            !preg_match('/[A-Z]/', $data['password']) || 
            !preg_match('/[a-z]/', $data['password']) || 
            !preg_match('/\d/', $data['password']) || 
            !preg_match('/[\W_]/', $data['password'])) {
            Flight::json([
                'status' => 'error',
                'message' => 'Password must be 8+ characters with upper/lowercase, number, special char.'
            ], 400);
            return;
        }
        
        // Check if password is pwned
        if ($this->isPasswordPwned($data['password'])) {
            Flight::json([
                'status' => 'error',
                'message' => 'Password is compromised. Use a different one.'
            ], 400);
            return;
        }
        
        try {
            // Verify reset token
            $stmt = $this->db->prepare("
                SELECT user_id FROM password_resets 
                WHERE token = :token AND expires_at > NOW() AND used = 0
                LIMIT 1
            ");
            $stmt->execute([':token' => $data['token']]);
            $reset = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$reset) {
                Flight::json(['status' => 'error', 'message' => 'Invalid or expired reset token.'], 400);
                return;
            }
            
            // Hash the new password
            $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);
            
            // Update password
            $stmt = $this->db->prepare("
                UPDATE users 
                SET password = :password 
                WHERE id = :user_id
            ");
            $stmt->execute([
                ':password' => $hashedPassword,
                ':user_id' => $reset['user_id']
            ]);
            
            // Mark token as used
            $stmt = $this->db->prepare("
                UPDATE password_resets 
                SET used = 1, used_at = NOW() 
                WHERE token = :token
            ");
            $stmt->execute([':token' => $data['token']]);
            
            // In a real implementation, you would send a confirmation email
            // For this example, we'll just log it
            error_log("Password reset successful for user ID: {$reset['user_id']}");
            
            // Send password reset confirmation email
            try {
                // Fetch user's email and full name
                $stmt = $this->db->prepare("SELECT email, full_name FROM users WHERE id = :user_id LIMIT 1");
                $stmt->execute([':user_id' => $reset['user_id']]);
                $user = $stmt->fetch(\PDO::FETCH_ASSOC);

                if ($user) {
                    $subject = "Password Successfully Reset";
                    $body = "Hello {$user['full_name']},

Your password for your SSSD account has been successfully reset.

If you did not perform this action, please contact support immediately.

Thank you,
Your Application Team";

                    error_log("Attempting to send password reset confirmation email to: " . $user['email']);
                    $this->sendEmail($user['email'], $subject, $body);
                    error_log("Password reset confirmation email sent successfully.");
                } else {
                     error_log("ERROR: User not found for password reset confirmation email (user_id: {$reset['user_id']}).");
                }
            } catch (\Exception $e) {
                error_log("ERROR: Failed to send password reset confirmation email: " . $e->getMessage());
                // Log the error but do not prevent the success response, as the password *was* reset.
            }
            
            Flight::json([
                'status' => 'success',
                'message' => 'Password reset successful.'
            ]);
        } catch (\PDOException $e) {
            error_log("Database error during password reset: " . $e->getMessage());
            Flight::json([
                'status' => 'error',
                'message' => 'An unexpected error occurred. Please try again later.'
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *   path="/generate-recovery-codes",
     *   summary="Generate 2FA recovery codes",
     *   description="Generate recovery codes for 2FA backup.",
     *   tags={"Authentication"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"session_token"},
     *           @OA\Property(property="session_token", type="string", example="abc123")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="Recovery codes generated successfully",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="Recovery codes generated successfully"),
     *           @OA\Property(property="recovery_codes", type="array", @OA\Items(type="string"))
     *       )
     *   )
     * )
     */
    public function generateRecoveryCodes() {
        // Get the authorization header
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        error_log('DEBUG: generateRecoveryCodes: Received Authorization header: ' . ($authHeader ? substr($authHeader, 0, 20) . '...' : 'None'));

        if (empty($authHeader) || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            error_log('DEBUG: generateRecoveryCodes: No valid authorization token provided.');
            Flight::json(['status' => 'error', 'message' => 'No valid authorization token provided.'], 401);
            return;
        }
        
        $token = $matches[1];
        error_log('DEBUG: generateRecoveryCodes: Extracted token: ' . substr($token, 0, 20) . '...');
        
        try {
            // Verify session token
            $stmt = $this->db->prepare("
                SELECT user_id FROM user_sessions 
                WHERE session_token = :token AND expires_at > NOW() AND authenticated = 1
                LIMIT 1
            ");
             error_log('DEBUG: generateRecoveryCodes: Executing session token verification query.');
            $stmt->execute([':token' => $token]);
            $session = $stmt->fetch(\PDO::FETCH_ASSOC);
            error_log('DEBUG: generateRecoveryCodes: Session verification result: ' . ($session ? 'Found' : 'Not Found'));
            
            if (!$session) {
                error_log('DEBUG: generateRecoveryCodes: Invalid, expired, or unauthenticated session.');
                Flight::json(['status' => 'error', 'message' => 'Invalid, expired, or unauthenticated session.'], 401);
                return;
            }
            
            // Get user data
             error_log('DEBUG: generateRecoveryCodes: Fetching user data.');
            $stmt = $this->db->prepare("
                SELECT id FROM users 
                WHERE id = :user_id
                LIMIT 1
            ");
            $stmt->execute([':user_id' => $session['user_id']]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
             error_log('DEBUG: generateRecoveryCodes: User data fetch result: ' . ($user ? 'Found' : 'Not Found'));
            
            if (!$user) {
                 error_log('DEBUG: generateRecoveryCodes: User not found for session user_id.');
                Flight::json(['status' => 'error', 'message' => 'User not found.'], 404);
                return;
            }
            
            // Delete existing recovery codes
             error_log('DEBUG: generateRecoveryCodes: Deleting existing recovery codes.');
            $stmt = $this->db->prepare("
                DELETE FROM recovery_codes 
                WHERE user_id = :user_id
            ");
            $stmt->execute([':user_id' => $user['id']]);
             error_log('DEBUG: generateRecoveryCodes: Existing recovery codes deleted.');
            
            // Generate 10 recovery codes
            $recoveryCodes = [];
             error_log('DEBUG: generateRecoveryCodes: Generating new recovery codes.');
            for ($i = 0; $i < 10; $i++) {
                $code = bin2hex(random_bytes(4)); // 8 characters
                $recoveryCodes[] = $code;
                
                // Store in database
                 error_log('DEBUG: generateRecoveryCodes: Inserting new recovery code.');
                $stmt = $this->db->prepare("
                    INSERT INTO recovery_codes (user_id, code) 
                    VALUES (:user_id, :code)
                ");
                $stmt->execute([
                    ':user_id' => $user['id'],
                    ':code' => $code
                ]);
            }
             error_log('DEBUG: generateRecoveryCodes: All new recovery codes inserted.');
            
            Flight::json([
                'status' => 'success',
                'message' => 'Recovery codes generated successfully.',
                'recovery_codes' => $recoveryCodes
            ]);
        } catch (\PDOException $e) {
            error_log("ERROR: Database error during recovery code generation: " . $e->getMessage());
            Flight::json([
                'status' => 'error',
                'message' => 'Database error during recovery code generation.'
            ], 500);
        } catch (\Exception $e) {
            error_log("ERROR: Unexpected error during recovery code generation: " . $e->getMessage());
            Flight::json([
                'status' => 'error',
                'message' => 'An unexpected error occurred during recovery code generation.'
            ], 500);
        }
    }
    
    /**
     * @OA\Post(
     *   path="/verify-recovery-code",
     *   summary="Verify recovery code",
     *   description="Verify a recovery code for 2FA bypass.",
     *   tags={"Authentication"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"code", "session_token"},
     *           @OA\Property(property="code", type="string", example="abc123"),
     *           @OA\Property(property="session_token", type="string", example="abc123")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="Recovery code verified successfully",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="Recovery code verified successfully")
     *       )
     *   )
     * )
     */
    public function verifyRecoveryCode() {
        $data = Flight::request()->data->getData();
        
        if (empty($data['code']) || empty($data['session_token'])) {
            Flight::json(['status' => 'error', 'message' => 'Code and session token are required.'], 400);
            return;
        }
        
        try {
            // Verify session token
            $stmt = $this->db->prepare("
                SELECT user_id FROM user_sessions 
                WHERE session_token = :session_token AND expires_at > NOW()
                LIMIT 1
            ");
            $stmt->execute([':session_token' => $data['session_token']]);
            $session = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$session) {
                Flight::json(['status' => 'error', 'message' => 'Invalid or expired session.'], 401);
                return;
            }
            
            // Get user data
            $stmt = $this->db->prepare("
                SELECT id, full_name, email FROM users 
                WHERE id = :user_id
                LIMIT 1
            ");
            $stmt->execute([':user_id' => $session['user_id']]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$user) {
                Flight::json(['status' => 'error', 'message' => 'User not found.'], 404);
                return;
            }
            
            // Verify recovery code
            error_log('DEBUG: verifyRecoveryCode: Received code: ' . $data['code']);
            error_log('DEBUG: verifyRecoveryCode: Querying for recovery code for user ID: ' . $user['id']);
            $stmt = $this->db->prepare("
                SELECT id, code FROM recovery_codes 
                WHERE user_id = :user_id AND code = :code AND used = 0
                LIMIT 1
            ");
            
            // Log parameters being bound
            $bindParams = [
                ':user_id' => $user['id'],
                ':code' => $data['code']
            ];
            error_log('DEBUG: verifyRecoveryCode: Binding parameters: ' . json_encode($bindParams));

            $stmt->execute($bindParams);
            
            // Log the raw fetch result
            $recoveryCode = $stmt->fetch(\PDO::FETCH_ASSOC);
            error_log('DEBUG: verifyRecoveryCode: Raw fetch result: ' . json_encode($recoveryCode));

            if (!$recoveryCode) {
                error_log('DEBUG: verifyRecoveryCode: Invalid or used recovery code attempt.');
                Flight::json(['status' => 'error', 'message' => 'Invalid or used recovery code.'], 400);
                return;
            }

            error_log('DEBUG: verifyRecoveryCode: Recovery code found and valid. Proceeding to update and authenticate.');

            // Mark recovery code as used
            $stmt = $this->db->prepare("
                UPDATE recovery_codes 
                SET used = 1, used_at = NOW() 
                WHERE id = :id
            ");
            $stmt->execute([':id' => $recoveryCode['id']]);
            
            // Update session to mark as fully authenticated
            $stmt = $this->db->prepare("
                UPDATE user_sessions 
                SET authenticated = 1, authenticated_at = NOW() 
                WHERE session_token = :session_token
            ");
            $stmt->execute([':session_token' => $data['session_token']]);
            
            Flight::json([
                'status' => 'success',
                'message' => 'Recovery code verified successfully.',
                'user' => [
                    'id' => $user['id'],
                    'full_name' => $user['full_name'],
                    'email' => $user['email']
                ],
                'session_token' => $data['session_token']
            ]);
        } catch (\PDOException $e) {
            error_log("Database error during recovery code verification: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            Flight::json([
                'status' => 'error',
                'message' => 'An unexpected error occurred. Please try again later.'
            ], 500);
        }
    }

    /**
     * @OA\Post(
     *   path="/verify-totp",
     *   summary="Verify TOTP code",
     *   description="Verify a TOTP code directly.",
     *   tags={"Authentication"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"secret", "code"},
     *           @OA\Property(property="secret", type="string", example="NOQGSOV3IK2MIIG3NDMR2AHGFIPS4SIKE6RHHOSMKPBHVCZHR626GTKH74KNJX2ZA3K5NIAVXPW4GHRHCUNF2LETFKHIAK7UFE7XRZA"),
     *           @OA\Property(property="code", type="string", example="123456")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="TOTP code verified successfully",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="TOTP code verified successfully"),
     *           @OA\Property(property="current_otp", type="string", example="123456")
     *       )
     *   )
     * )
     */
    public function verifyTOTPDirect() {
        $data = Flight::request()->data->getData();
        
        if (empty($data['secret']) || empty($data['code'])) {
            Flight::json(['status' => 'error', 'message' => 'Secret and code are required.'], 400);
            return;
        }
        
        try {
            // Create TOTP object from the secret
            $otp = TOTP::createFromSecret($data['secret']);
            
            // Get the current OTP
            $currentOtp = $otp->now();
            
            // Verify the code
            $isValid = $otp->verify($data['code']);
            
            if ($isValid) {
                Flight::json([
                    'status' => 'success',
                    'message' => 'TOTP code verified successfully',
                    'current_otp' => $currentOtp
                ]);
            } else {
                Flight::json([
                    'status' => 'error',
                    'message' => 'Invalid TOTP code',
                    'current_otp' => $currentOtp
                ], 400);
            }
        } catch (\Exception $e) {
            error_log("Error verifying TOTP code: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'Error verifying TOTP code: ' . $e->getMessage()], 500);
        }
    }

    /**
     * @OA\Delete(
     *   path="/delete-user",
     *   summary="Delete a user",
     *   description="Delete a user by email.",
     *   tags={"Users"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"email"},
     *           @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="User deleted successfully",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="User deleted successfully")
     *       )
     *   )
     * )
     */
    public function deleteUser() {
        try {
            $data = Flight::request()->data->getData();
            
            if (empty($data['email'])) {
                Flight::json(['status' => 'error', 'message' => 'Email is required.'], 400);
                return;
            }

            // Delete the user
            $stmt = $this->db->prepare("DELETE FROM users WHERE email = ?");
            $result = $stmt->execute([$data['email']]);

            if ($result && $stmt->rowCount() > 0) {
                Flight::json([
                    'status' => 'success',
                    'message' => 'User deleted successfully'
                ]);
            } else {
                Flight::json([
                    'status' => 'error',
                    'message' => 'User not found'
                ], 404);
            }
        } catch (\Exception $e) {
            error_log("Error deleting user: " . $e->getMessage());
            Flight::json([
                'status' => 'error',
                'message' => 'An error occurred while deleting the user'
            ], 500);
        }
    }

    public function testSendEmail() {
        try {
            // Get email from query parameter or use default
            $testEmail = isset($_GET['email']) ? $_GET['email'] : 'your@email.com';

            $subject = 'Test Email from SSSD System';
            $body = '
                <h2>Test Email</h2>
                <p>This is a test email to verify the email sending functionality.</p>
                <p>If you receive this email, the email system is working correctly.</p>
                <p>Time sent: ' . date('Y-m-d H:i:s') . '</p>
            ';

            error_log("Starting test email send to: " . $testEmail);
            $this->sendEmail($testEmail, $subject, $body);
            error_log("Test email sent successfully");

            Flight::json([
                'status' => 'success',
                'message' => 'Test email sent successfully to ' . $testEmail
            ]);
        } catch (\Exception $e) {
            error_log("Test email failed: " . $e->getMessage());
            error_log("Test email error trace: " . $e->getTraceAsString());
            Flight::json([
                'status' => 'error',
                'message' => 'Failed to send test email: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * @OA\Get(
     *   path="/verify-email",
     *   summary="Verify email address",
     *   description="Verify user's email address using token.",
     *   tags={"Authentication"},
     *   @OA\Parameter(
     *       name="token",
     *       in="query",
     *       required=true,
     *       @OA\Schema(type="string")
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="Email verified successfully",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="Email verified successfully")
     *       )
     *   )
     * )
     */
    public function verifyEmail() {
        try {
            $token = Flight::request()->query['token'];
            
            if (empty($token)) {
                Flight::json(['status' => 'error', 'message' => 'Verification token is required.'], 400);
                return;
            }

            // Verify token and get user ID
            $stmt = $this->db->prepare("
                SELECT v.user_id, v.used 
                FROM email_verifications v
                WHERE v.token = ? 
                AND v.expires_at > NOW()
                AND v.used = 0
                LIMIT 1
            ");
            $stmt->execute([$token]);
            $verification = $stmt->fetch(\PDO::FETCH_ASSOC);

            if (!$verification) {
                Flight::json(['status' => 'error', 'message' => 'Invalid or expired verification token.'], 400);
                return;
            }

            // Update user's verification status
            $stmt = $this->db->prepare("
                UPDATE users 
                SET is_verified = 1 
                WHERE id = ?
            ");
            $stmt->execute([$verification['user_id']]);

            // Mark verification token as used
            $stmt = $this->db->prepare("
                UPDATE email_verifications 
                SET used = 1, used_at = NOW() 
                WHERE token = ?
            ");
            $stmt->execute([$token]);

            // Redirect to login page with success message
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
            $redirectUrl = "{$baseUrl}/front/pages/login.php?verified=1";

            header('Location: ' . $redirectUrl);
            exit;
        } catch (\Exception $e) {
            error_log("Error verifying email: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'An error occurred while verifying your email.'], 500);
        }
    }

    /**
     * Get username for logged-in user
     */
    public function getUsername() {
        // Get the authorization header
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        
        if (empty($authHeader) || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            Flight::json(['status' => 'error', 'message' => 'No valid authorization token provided.'], 401);
            return;
        }
        
        $token = $matches[1];
        
        try {
            // Verify session token and get user ID
            $stmt = $this->db->prepare("
                SELECT us.user_id, u.username
                FROM user_sessions us
                JOIN users u ON us.user_id = u.id
                WHERE us.session_token = :token 
                AND us.expires_at > NOW()
                AND us.authenticated = 1 
                LIMIT 1
            ");
            
            $stmt->execute([':token' => $token]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$user) {
                Flight::json(['status' => 'error', 'message' => 'Invalid, expired, or unauthenticated session.'], 401);
                return;
            }
            
            Flight::json(['status' => 'success', 'username' => $user['username']]);

        } catch (\PDOException $e) {
            error_log("Database error fetching username: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'Database error fetching username.'], 500);
        } catch (\Exception $e) {
            error_log("Unexpected error fetching username: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'An unexpected error occurred.'], 500);
        }
    }

    /**
     * Change password for logged-in user
     */
    public function changePassword() {
        // Get the authorization header
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        
        if (empty($authHeader) || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            Flight::json(['status' => 'error', 'message' => 'No valid authorization token provided.'], 401);
            return;
        }
        
        $token = $matches[1];
        $data = Flight::request()->data->getData();

        if (empty($data['new_password'])) {
            Flight::json(['status' => 'error', 'message' => 'New password is required.'], 400);
            return;
        }

        // Validate password strength
        if (strlen($data['new_password']) < 8 || 
            !preg_match('/[A-Z]/', $data['new_password']) || 
            !preg_match('/[a-z]/', $data['new_password']) || 
            !preg_match('/\d/', $data['new_password']) || 
            !preg_match('/[\W_]/', $data['new_password'])) {
            Flight::json([
                'status' => 'error',
                'message' => 'Password must be 8+ characters with upper/lowercase, number, special char.'
            ], 400);
            return;
        }

        // Check if password is pwned
        if ($this->isPasswordPwned($data['new_password'])) {
            Flight::json([
                'status' => 'error',
                'message' => 'Password is compromised. Use a different one.'
            ], 400);
            return;
        }
        
        try {
            // Verify session token and get user ID
            $stmt = $this->db->prepare("
                SELECT us.user_id
                FROM user_sessions us
                WHERE us.session_token = :token 
                AND us.expires_at > NOW()
                AND us.authenticated = 1 
                LIMIT 1
            ");
            
            $stmt->execute([':token' => $token]);
            $session = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$session) {
                Flight::json(['status' => 'error', 'message' => 'Invalid, expired, or unauthenticated session.'], 401);
                return;
            }

            $userId = $session['user_id'];

            // Hash the new password
            $hashedPassword = password_hash($data['new_password'], PASSWORD_DEFAULT);
            
            // Update password
            $stmt = $this->db->prepare("
                UPDATE users 
                SET password = :password 
                WHERE id = :user_id
            ");
            $stmt->execute([
                ':password' => $hashedPassword,
                ':user_id' => $userId
            ]);
            
            error_log("Password changed successfully for user ID: {$userId}");
            
            Flight::json(['status' => 'success', 'message' => 'Password changed successfully.']);

        } catch (\PDOException $e) {
            error_log("Database error during password change: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'Database error changing password.'], 500);
        } catch (\Exception $e) {
            error_log("Unexpected error during password change: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'An unexpected error occurred.'], 500);
        }
    }

    /**
     * Get enabled 2FA methods for a logged-in user
     */
    public function getUser2FAMethods() {
        // Get the authorization header
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        
        if (empty($authHeader) || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            Flight::json(['status' => 'error', 'message' => 'No valid authorization token provided.'], 401);
            return;
        }
        
        $token = $matches[1];
        
        try {
            // Verify session token and get user ID and 2FA related fields
            $stmt = $this->db->prepare("
                SELECT us.user_id, u.phone, u.otp_secret, u.email
                FROM user_sessions us
                JOIN users u ON us.user_id = u.id
                WHERE us.session_token = :token 
                AND us.expires_at > NOW()
                LIMIT 1
            ");
            
            $stmt->execute([':token' => $token]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
            
            if (!$user) {
                Flight::json(['status' => 'error', 'message' => 'Invalid or expired session.'], 401);
                return;
            }
            
            // Determine enabled 2FA methods
            $twoFAMethods = [
                'sms' => !empty($user['phone']),
                'totp' => !empty($user['otp_secret']),
                'email' => !empty($user['email'])
            ];
            
            Flight::json(['status' => 'success', '2fa_methods' => $twoFAMethods]);

        } catch (\PDOException $e) {
            error_log("Database error fetching 2FA methods: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'Database error fetching 2FA methods.'], 500);
        } catch (\Exception $e) {
            error_log("Unexpected error fetching 2FA methods: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'An unexpected error occurred.'], 500);
        }
    }

    /**
     * @OA\Post(
     *   path="/logout",
     *   summary="User logout",
     *   description="Invalidate user session on logout.",
     *   tags={"Users"},
     *   @OA\RequestBody(
     *       required=true,
     *       @OA\JsonContent(
     *           required={"session_token"},
     *           @OA\Property(property="session_token", type="string", example="abc123")
     *       )
     *   ),
     *   @OA\Response(
     *       response=200,
     *       description="Logout successful",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="success"),
     *           @OA\Property(property="message", type="string", example="Logout successful.")
     *       )
     *   ),
     *   @OA\Response(
     *       response=401,
     *       description="Unauthorized",
     *       @OA\JsonContent(
     *           @OA\Property(property="status", type="string", example="error"),
     *           @OA\Property(property="message", type="string", example="Invalid or expired session token.")
     *       )
     *   )
     * )
     */
    public function logout() {
        session_start();
        // Get the authorization header
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        error_log('DEBUG: logout: Received Authorization header: ' . ($authHeader ? substr($authHeader, 0, 20) . '...' : 'None'));

        if (empty($authHeader) || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            error_log('DEBUG: logout: No valid authorization token provided.');
            Flight::json(['status' => 'error', 'message' => 'No valid authorization token provided.'], 401);
            return;
        }
        
        $token = $matches[1];
        error_log('DEBUG: logout: Extracted token: ' . substr($token, 0, 20) . '...');

        try {
            error_log('DEBUG: logout: Inside try block.');
            // Invalidate the session token in the database
            error_log('DEBUG: logout: Preparing database query to invalidate session.');
            $stmt = $this->db->prepare("
                UPDATE user_sessions 
                SET expires_at = NOW() 
                WHERE session_token = :session_token
            ");
            error_log('DEBUG: logout: Executing database query.');
            $stmt->execute([':session_token' => $token]);
            error_log('DEBUG: logout: Database query executed. Session token invalidated for token: ' . substr($token, 0, 20) . '...');

            // Clear session variables (optional, as database is the source of truth)
            error_log('DEBUG: logout: Attempting to unset PHP session variables.');
            session_unset();
            error_log('DEBUG: logout: PHP session variables unset. Attempting to destroy session.');
            session_destroy();
             error_log('DEBUG: logout: PHP session variables unset and destroyed.');

            error_log('DEBUG: logout: Returning success response.');
            Flight::json([
                'status' => 'success',
                'message' => 'Logout successful.'
            ]);
        } catch (\PDOException $e) {
            error_log("ERROR: Database error during logout: " . $e->getMessage());
            Flight::json([
                'status' => 'error',
                'message' => 'Database error during logout.'
            ], 500);
        } catch (\Exception $e) {
            error_log("Unexpected error during logout: " . $e->getMessage());
            Flight::json(['status' => 'error', 'message' => 'An unexpected error occurred.'], 500);
        }
    }
}