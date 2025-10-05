document.addEventListener('DOMContentLoaded', function() {
    console.log('DEBUG: login.js DOMContentLoaded fired.');
    const loginForm = document.getElementById('loginForm');
    const loginButton = document.getElementById('loginButton');
    const captchaContainer = document.getElementById('captcha-container');
    let failedAttempts = 0;  // Track failed attempts
    let selectedMethod = '';
    let sessionToken = '';  // Store session token

    if (!loginButton) {
        console.error('Login button not found!');
        return;
    }

    // --- Set up ALL Event Listeners FIRST ---

    // Add event listener to username/email input to check captcha status
    const usernameInput = document.getElementById('username');
    function checkCaptchaStatus() {
        const username = usernameInput.value;
        // Keep captcha hidden if no username is entered
        if (!username) {
            captchaContainer.style.display = 'none';
            if (typeof hcaptcha !== 'undefined') hcaptcha.reset(); // Reset captcha if hidden
            return;
        }
        // Only fetch if hCaptcha API is loaded
        if (typeof hcaptcha === 'undefined') {
            console.log('hCaptcha API not loaded yet, deferring checkCaptchaStatus');
            return;
        }

        fetch('/sssd-2025-21002925/api/should-show-captcha?username=' + encodeURIComponent(username))
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.show_captcha) {
                    captchaContainer.style.display = 'block';
                } else {
                    captchaContainer.style.display = 'none';
                    if (typeof hcaptcha !== 'undefined') hcaptcha.reset(); // Explicitly reset if hiding
                }
            })
            .catch(error => {
                console.error('Error fetching captcha status:', error);
                // In case of error, ensure captcha is hidden by default
                captchaContainer.style.display = 'none';
                if (typeof hcaptcha !== 'undefined') hcaptcha.reset();
            });
    }
    if (usernameInput) {
        usernameInput.addEventListener('input', checkCaptchaStatus);
        // Modify onCaptchaLoad to trigger the status check after API is ready
        window.onCaptchaLoad = function() {
            console.log('hCaptcha API loaded');
            if (usernameInput && usernameInput.value) {
                 checkCaptchaStatus();
            }
        };

        // Ensure checkCaptchaStatus is called if hCaptcha is already loaded (e.g., cached) and username is present
        if (typeof hcaptcha !== 'undefined' && hcaptcha.render) {
            console.log('hCaptcha API already loaded');
            if (usernameInput && usernameInput.value) {
                 checkCaptchaStatus();
            }
        }
    }

    // Handle form submission for standard login
    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault();
            console.log('Form submission intercepted');

            // Only check hCaptcha if the widget is visible
            const computedStyle = window.getComputedStyle(captchaContainer);
            console.log('DEBUG: Captcha container computed display style:', computedStyle.display);
            const captchaVisible = captchaContainer && computedStyle.display === 'block';
            console.log('DEBUG: captchaVisible flag:', captchaVisible);
            let hCaptchaResponse = '';

            if (captchaVisible && typeof hcaptcha !== 'undefined') {
                try {
                    hCaptchaResponse = hcaptcha.getResponse();
                    console.log('hCaptcha response:', hCaptchaResponse);
                } catch (e) {
                    alert('Captcha is not ready. Please wait a moment.');
                    return;
                }
                if (!hCaptchaResponse) {
                    alert('Please complete the CAPTCHA.');
                    return;
                }
            }

            const formData = new FormData(loginForm);
            const loginData = {};
            formData.forEach((value, key) => { loginData[key] = value; });
            // If the username input is present, send it as both username and email
            if (loginData.username) {
                loginData.email = loginData.username;
            }
            if (captchaVisible && typeof hcaptcha !== 'undefined') {
                loginData['h-captcha-response'] = hCaptchaResponse;
            }

            const jsonData = JSON.stringify(loginData);
            console.log('JSON data to be sent:', jsonData);

            // Disable the login button while processing
            loginButton.disabled = true;
            loginButton.textContent = 'Logging in...';

            console.log('Sending login request to /sssd-2025-21002925/api/login');
            fetch('/sssd-2025-21002925/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(loginData)
            })
            .then(response => response.json().then(data => ({ ok: response.ok, data })))
            .then(({ ok, data }) => {
                if (ok && data.status === 'success') {
                    // Success: reset everything
                    if (captchaContainer) {
                        captchaContainer.style.display = 'none';
                        if (typeof hcaptcha !== 'undefined') hcaptcha.reset();
                    }
                    // Re-enable button and reset text on success
                    loginButton.disabled = false;
                    loginButton.textContent = 'Login';

                    // Pass the session token and 2FA methods to the next step
                    if (data['2fa_methods'] && data['session_token']) {
                        show2FAMethods(data['2fa_methods'], data['session_token']); // Pass session_token
                    } else if (data['session_token']) {
                        // If no 2FA methods but successful login with token, maybe redirect?
                        // Or handle this case as per your app's flow.
                        // For now, assume 2FA methods are always provided on successful login.
                        console.error('Successful login but no 2FA methods provided!');
                        // Optional: Redirect or show an error
                        // window.location.href = '/sssd-2025-21002925/front/pages/landing.html?token=' + data['session_token'];

                    } else {
                         // Should not happen if backend is correct, but handle defensively
                         alert('Login successful, but received no session token.');
                    }
                } else {
                    // Show backend error
                    if (data.message) {
                        alert(data.message);
                        // Also show the error message in a visible div if available
                        const errorDiv = document.getElementById('login-error-message');
                        if (errorDiv) {
                            errorDiv.innerText = data.message;
                            errorDiv.style.display = 'block';
                        }
                    }
                    // If backend says show_captcha, show it
                    if (data.show_captcha && captchaContainer) {
                        captchaContainer.style.display = 'block';
                    }
                    // Always re-check captcha status after a failed login
                    checkCaptchaStatus();

                    // Re-enable button and reset text on error
                    loginButton.disabled = false;
                    loginButton.textContent = 'Login';
                }
            })
            .catch(() => {
                // CATCH CASE (Network error, etc.): Also re-enable button
                alert('Error logging in. Please try again.');
                loginButton.disabled = false;
                loginButton.textContent = 'Login';
            });
        });
    }

    // Add event listener for the Google Sign-In button on the login page
    const googleSignInButton = document.getElementById('google-signin-button');
    if (googleSignInButton) {
        googleSignInButton.addEventListener('click', async function(event) {
            event.preventDefault();
            console.log('DEBUG: Google Sign-In button clicked on login page.');
            try {
                const response = await fetch('/sssd-2025-21002925/api/google-login');
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                if (data.authUrl) {
                    console.log('DEBUG: Received Google auth URL, redirecting.', data.authUrl);
                    window.location.href = data.authUrl;
                } else {
                    console.error('ERROR: Failed to get Google login URL from backend.', data);
                    alert('Failed to initiate Google Sign-In. Please try again.');
                }
            } catch (error) {
                console.error('Error initiating Google Sign-In:', error);
                alert('Error initiating Google Sign-In: ' + error.message);
            }
        });
    }


    // --- AFTER setting up listeners, check for session token in URL ---
    const urlParams = new URLSearchParams(window.location.search);
    const urlSessionToken = urlParams.get('session_token');

    if (urlSessionToken) {
        // If token is in URL, store it and proceed to 2FA selection
        sessionToken = urlSessionToken;
        localStorage.setItem('session_token', sessionToken); // Store for later use
        console.log('DEBUG: Session token found in URL. Proceeding to 2FA selection.', sessionToken);

        // Fetch user info and 2FA methods using the token
        fetch('/sssd-2025-21002925/api/get-user-2fa-methods', { // Assuming a new endpoint to get 2FA methods
             method: 'GET',
             headers: {
                 'Authorization': 'Bearer ' + sessionToken
             }
        })
        .then(response => response.json())
        .then(data => {
             if (data.status === 'success' && data['2fa_methods']) {
                  show2FAMethods(data['2fa_methods'], sessionToken); // Show 2FA options
             } else {
                  alert('Failed to fetch 2FA methods: ' + (data.message || 'Unknown error'));
                  // Redirect to login if unable to get 2FA methods
                  window.location.href = 'login.php';
             }
        })
        .catch(error => {
             console.error('Error fetching 2FA methods:', error);
             alert('Error fetching 2FA methods.');
             // Redirect to login on error
             window.location.href = 'login.php';
        });

        // Hide the standard login form
        if (loginForm) {
            loginForm.style.display = 'none';
        }
    } else {
         // If no token in URL, ensure the standard login form is visible
         if (loginForm) {
            loginForm.style.display = 'block';
         }
         // Also ensure captcha is hidden by default unless triggered by failed attempts
          if (captchaContainer) {
            captchaContainer.style.display = 'none';
          }
    }

    function handleSuccessResponse(data) {
        // Reset failed attempts and hide captcha on successful login
        failedAttempts = 0;
        if (captchaContainer) {
            captchaContainer.style.display = 'none';
            if (typeof hcaptcha !== 'undefined') {
                hcaptcha.reset();
            }
        }
        if (data['2fa_methods']) {
            show2FAMethods(data['2fa_methods']);
        } else {
            window.location.href = '/sssd-2025-21002925/front/pages/landing.html';
        }
    }

    function handleError(data) {
        // Only increment failedAttempts and show captcha after 3 fails
        failedAttempts++;
        console.log('Failed attempts:', failedAttempts);
        if (data.show_captcha || failedAttempts >= 3) {
            showCaptcha();
        }
        // Show backend error message
        if (data.message) {
            alert(data.message);
        }
    }

    // Modify show2FAMethods to accept the session token
    window.show2FAMethods = function(methods, token) {
        sessionToken = token; // Store the token in the global variable
        console.log('DEBUG: show2FAMethods called with methods:', methods, 'and token:', sessionToken);
        console.log('DEBUG: show2FAMethods called', methods);
        document.body.innerHTML = [
            '<div class="container">',
            '  <h1>Choose your 2FA method</h1>',
            methods.sms ? '  <button class="2fa-button" onclick="send2FACode(\'sms\')">SMS Verification</button>' : '',
            methods.totp ? '  <button class="2fa-button" onclick="send2FACode(\'totp\')">Authenticator App</button>' : '',
            methods.email ? '  <button class="2fa-button" onclick="send2FACode(\'email\')">Email Verification</button>' : '',
            '  <button class="2fa-button" onclick="setRecoveryCodeMethod()">Recovery Code</button>',
            '</div>'
        ].join('\n');
    };

    // Modify send2FACode to use the globally stored sessionToken and handle TOTP setup
    window.send2FACode = function(method) {
        selectedMethod = method;
        console.log('Selected method:', selectedMethod);

        // Use the globally stored sessionToken
        const requestData = JSON.stringify({ 
            method: method,
            session_token: sessionToken
        });
        console.log('JSON data to be sent for 2FA:', requestData);

        if (method === 'totp') {
            // For TOTP, first fetch the QR code
            fetch('/sssd-2025-21002925/api/generate-qr-code', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + sessionToken
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // Display the QR code and then prompt for the code
                    showTOTPSetup(data.qr_code_url);
                } else {
                    alert('Failed to generate QR code: ' + data.message);
                }
            })
            .catch(error => {
                console.error('TOTP QR code error:', error);
                alert('Error generating TOTP QR code: ' + error.message);
            });
        } else { // For SMS and Email, send code via backend
             fetch('../../api/send-2fa-code', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: requestData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                     alert(data.message); // Show success message (e.g., code sent)
                     show2FAInput(method); // Show input for SMS/Email code
                } else {
                    alert('Failed to send 2FA code: ' + data.message);
                }
            })
            .catch(error => {
                console.error('2FA error:', error);
                alert('Error sending 2FA code: ' + error.message);
            });
        }
    };
    
    window.setRecoveryCodeMethod = function() {
        selectedMethod = 'recovery_code';
        show2FAInput('recovery_code');
    };

    window.show2FAInput = function(method) {
        let methodText;
        switch (method) {
            case 'sms':
                methodText = 'SMS';
                break;
            case 'email':
                methodText = 'Email';
                break;
            case 'totp':
                methodText = 'Authenticator App';
                break;
            case 'recovery_code':
                methodText = 'Recovery Code';
                break;
        }
        document.body.innerHTML = [
            '<div class="container">',
            '  <h1>Enter the code sent via ' + methodText + '</h1>',
            '  <div id="2fa-error-message" style="color:red; margin-bottom:10px;"></div>',
            '  <input type="text" id="2fa-code" placeholder="Enter ' + methodText + ' code" />',
            '  <button onclick="verify2FACode()">Verify</button>',
            '</div>'
        ].join('\n');
    };

    // Modify verify2FACode to use the globally stored sessionToken
    window.verify2FACode = function() {
        const code = document.getElementById('2fa-code').value;
        console.log('Selected method:', selectedMethod);
        console.log('2FA code:', code);

        // Use the globally stored sessionToken
        const requestData = JSON.stringify({ 
            method: selectedMethod, 
            code: code,
            session_token: sessionToken // Use the globally stored sessionToken
        });
        console.log('JSON data to be sent for 2FA verification:', requestData);

        fetch('../../api/verify-2fa', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: requestData
        })
        .then(response => {
            console.log('Verify 2FA response:', response);
            const errorMessageDiv = document.getElementById('2fa-error-message');
            
            if (!response.ok) {
                // Attempt to read the response body for a message
                return response.json().then(errorData => {
                    // Display the specific backend error message
                     if (errorMessageDiv) {
                         errorMessageDiv.textContent = errorData.message || `HTTP error! status: ${response.status}`;
                     }
                    console.error('Verify 2FA error:', errorData);
                    // Prevent the next .then from executing on error
                    return Promise.reject('Handled error');
                }).catch(() => {
                    // Fallback error if JSON parsing fails or handled error is rejected
                     if (errorMessageDiv) {
                         errorMessageDiv.textContent = `HTTP error! status: ${response.status}`;
                     }
                    console.error('Verify 2FA error: HTTP error', response.status);
                    // Prevent the next .then from executing on error
                    return Promise.reject('Handled error');
                });
            }
            // If response is OK, proceed to the next .then
            return response.json();
        })
        .then(data => {
            console.log('Verify 2FA data:', data);
            const errorMessageDiv = document.getElementById('2fa-error-message');
            
            if (data.status === 'success') {
                 // On success, clear any previous error message
                if (errorMessageDiv) {
                     errorMessageDiv.textContent = '';
                }
                alert(data.message);
                // Store the session token in localStorage
                localStorage.setItem('session_token', data.session_token);
                window.location.href = '/sssd-2025-21002925/front/pages/landing.html';
            } else {
                 // Handle non-success status codes from backend API response
                if (errorMessageDiv) {
                     errorMessageDiv.textContent = data.message || 'An unknown error occurred.';
                } else {
                     alert(data.message || 'An unknown error occurred.');
                }
                 console.error('Backend reported non-success status with OK response:', data);
            }
        })
        .catch(error => {
            // This catch block will now primarily handle network errors or the rejected promise
            console.error('Fetch or unhandled error during 2FA verification:', error);
            // Only show a generic error if it wasn't a handled HTTP error
            if (error !== 'Handled error') {
                 const errorMessageDiv = document.getElementById('2fa-error-message');
                if (errorMessageDiv) {
                    errorMessageDiv.textContent = 'An unexpected error occurred during 2FA verification. Please try again later.';
                } else {
                     alert('An unexpected error occurred during 2FA verification. Please try again later.');
                }
            }
        });
    };

    // Add a new function to display TOTP setup instructions and QR code
    window.showTOTPSetup = function(qrCodeUri) {
        // We need a way to display the QR code from the URI
        // For simplicity, let's just show the URI for now and ask the user to use an external QR code generator or app
        // In a real app, you'd use a library like qrious or qr-code-styling to draw the QR code on a canvas or img tag.
        document.body.innerHTML = [
            '<div class="container">',
            '  <h1>Set up Authenticator App</h1>',
            '  <p>Scan the QR code below with your authenticator app (e.g., Google Authenticator, Microsoft Authenticator).</p>',
            '  <p>If you cannot scan, manually enter the secret key: <strong>' + qrCodeUri.split('secret=')[1].split('&')[0] + '</strong></p>', // Extract secret from URI
            '  <img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=' + encodeURIComponent(qrCodeUri) + '" alt="QR Code">',
            '  <br><br>',
            '  <button onclick="show2FAInput(\'totp\')">I have scanned the code / entered the secret</button>',
            '</div>'
        ].join('\n');
    };
});
