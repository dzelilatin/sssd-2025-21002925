document.addEventListener('DOMContentLoaded', function() {
    console.log('DEBUG: landing.js DOMContentLoaded fired.');
    const logoutButton = document.getElementById('logout-button');
    const passwordForm = document.getElementById('password-form'); // Added this to check if form exists
    const newPasswordInput = document.getElementById('new-password'); // Added this
    const usernameDisplay = document.getElementById('welcome-message'); // Added this
    const generateQrButton = document.querySelector('button[onclick="generateNewQRCode()"]'); // Added this
    const generateRecoveryButton = document.querySelector('button[onclick="generateNewRecoveryCode()"]'); // Added this

    // Add event listeners using .addEventListener for better practice
    if (logoutButton) {
        logoutButton.addEventListener('click', function() {
             console.log('DEBUG: Logout button clicked.');
            
            const sessionToken = localStorage.getItem('session_token');
            if (!sessionToken) {
                // If no session token, redirect to login immediately
                console.log('DEBUG: No session token found on logout click, redirecting to login.');
                window.location.href = 'login.php';
                return;
            }

            console.log('DEBUG: Logout fetch with token:', sessionToken);

            fetch('../../api/logout', {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + sessionToken
                }
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                if (data.status === 'success') {
                    // Clear session token on successful logout
                    localStorage.removeItem('session_token');
                    window.location.href = 'login.php';  
                }
            })
            .catch(error => console.error('Error logging out:', error));
        });
    }

     if (passwordForm) {
        // Prevent default form submission
        passwordForm.addEventListener('submit', function(event) {
             event.preventDefault();
             console.log('DEBUG: Password change form submitted.');
             changePassword(); // Call the existing function
        });
     }

     // Attach event listeners to buttons directly instead of onclick attribute
     if (generateQrButton) {
         generateQrButton.addEventListener('click', function() {
             console.log('DEBUG: Generate QR button clicked.');
             generateNewQRCode(); // Call the existing function
         });
     }

     if (generateRecoveryButton) {
         generateRecoveryButton.addEventListener('click', function() {
             console.log('DEBUG: Generate Recovery button clicked.');
             generateNewRecoveryCode(); // Call the existing function
         });
     }

    // Retrieve the session token for authenticated requests
    const sessionToken = localStorage.getItem('session_token');
    if (!sessionToken) {
        // If no session token, redirect to login
        console.log('DEBUG: No session token found, redirecting to login.');
        window.location.href = 'login.php';
        return;
    }

    console.log('DEBUG: Session token found. Attempting to fetch username.');
    fetch('/sssd-2025-21002925/api/get-username', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + sessionToken
        }
    })
    .then(response => {
         console.log('DEBUG: get-username response status:', response.status);
         if (!response.ok) {
            return response.json().then(errorData => {
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }).catch(() => {
                throw new Error(`HTTP error! status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('DEBUG: get-username response data:', data);
        if (data.status === 'success') {
            if (usernameDisplay) {
                 usernameDisplay.innerText = `Welcome, ${data.username || 'User'}!`;
                  console.log('DEBUG: Username displayed.');
            } else {
                 console.error('ERROR: Username display element not found.');
            }
        } else {
            alert('Error fetching username: ' + (data.message || 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Error fetching username:', error);
        alert('Error fetching username: ' + error.message);
         // Redirect to login if unauthorized (e.g., invalid or expired token)
        if (error.message.includes('status: 401')) {
             console.log('DEBUG: Received 401, redirecting to login.');
             window.location.href = 'login.php';
        }
    });
});

function changePassword() {
    const newPasswordInput = document.getElementById('new-password');
    const newPassword = newPasswordInput ? newPasswordInput.value : '';

    if (!newPassword) {
        alert('New password cannot be empty.');
        return;
    }

    const sessionToken = localStorage.getItem('session_token');
    if (!sessionToken) {
        alert('Session token not found. Please log in again.');
        window.location.href = 'login.php';
        return;
    }

    const data = {
        new_password: newPassword
    };

    console.log('DEBUG: Sending change password request.');
    fetch('/sssd-2025-21002925/api/change-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + sessionToken
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        console.log('DEBUG: change-password response status:', response.status);
        const errorMessageDiv = document.getElementById('landing-error-message');
        
        if (!response.ok) {
            // If response is not OK, read the error message from the body
            return response.json().then(errorData => {
                const displayMessage = errorData.message || `Error: HTTP status ${response.status}.`;
                if (errorMessageDiv) {
                    errorMessageDiv.style.display = 'block';
                    errorMessageDiv.innerHTML = '<p>' + displayMessage + '</p>';
                }
                console.error('Error changing password:', displayMessage, errorData);
                // Re-enable button and reset text on error
                const changePasswordButton = document.querySelector('#password-form button');
                 if (changePasswordButton) {
                    changePasswordButton.disabled = false;
                    changePasswordButton.textContent = 'Change Password';
                }
                // Return a specific value or marker to indicate that the error has been handled
                return { handledError: true, message: displayMessage };
            }).catch(() => {
                // Fallback for non-OK response where JSON body is not readable
                 const fallbackMessage = `Error: HTTP status ${response.status}. Could not read error details.`;
                if (errorMessageDiv) {
                    errorMessageDiv.style.display = 'block';
                    errorMessageDiv.innerHTML = '<p>' + fallbackMessage + '</p>';
                }
                console.error('Error changing password: HTTP error (JSON parse failed)', response.status);
                 // Re-enable button and reset text on error
                 const changePasswordButton = document.querySelector('#password-form button');
                 if (changePasswordButton) {
                    changePasswordButton.disabled = false;
                    changePasswordButton.textContent = 'Change Password';
                }
                // Return a specific value or marker to indicate that the error has been handled
                return { handledError: true, message: fallbackMessage };
            });
        }
        // If response is OK, proceed to parse JSON as usual
        return response.json();
    })
    .then(data => {
        console.log('DEBUG: change-password response data:', data);
        const errorMessageDiv = document.getElementById('landing-error-message');

        // Check if the previous step indicated a handled error
        if (data && data.handledError) {
             console.log('DEBUG: Previous step handled HTTP error.', data.message);
             // No further action needed here, error message is already displayed
             return;
        }

        // Handle successful response (status === 'success') or other non-error backend responses
        if (data.status === 'success') {
            if (errorMessageDiv) {
                 errorMessageDiv.style.display = 'none';
                 errorMessageDiv.innerHTML = '';
            }
            alert(data.message || 'Password changed successfully.');
            const newPasswordInput = document.getElementById('new-password');
            if (newPasswordInput) newPasswordInput.value = '';
             console.log('DEBUG: Password change successful.');
        } else {
            // Handle cases where backend returns 200 OK but status is not 'success'
            const displayMessage = data.message || 'An unknown error occurred.';
            if (errorMessageDiv) {
                 errorMessageDiv.style.display = 'block';
                 errorMessageDiv.innerHTML = '<p>' + displayMessage + '</p>';
            }
             console.error('Backend reported non-success status with OK response:', data);
        }

         // Re-enable button and reset text - already handled in !response.ok block, but for safety in success path
         const changePasswordButton = document.querySelector('#password-form button');
         if (changePasswordButton) {
            changePasswordButton.disabled = false;
            changePasswordButton.textContent = 'Change Password';
        }
    })
    .catch(error => {
        // This catch block should now only be for genuine network errors or errors before the first .then
        console.error('Fetch or unhandled error during password change:', error);
        const errorMessageDiv = document.getElementById('landing-error-message');
        if (errorMessageDiv) {
            errorMessageDiv.style.display = 'block';
            errorMessageDiv.innerHTML = '<p>' + 'An unexpected network error occurred during password change. Please try again.' + '</p>';
        } else {
             alert('An unexpected network error occurred during password change. Please try again.');
        }
        // Button re-enabling is handled in the .then blocks
    });
}

function generateNewQRCode() {
    const sessionToken = localStorage.getItem('session_token');
    if (!sessionToken) {
        alert('Session token not found. Please log in again.');
        window.location.href = 'login.php';
        return;
    }

    console.log('DEBUG: Sending generate QR code request.');
    fetch('/sssd-2025-21002925/api/generate-qr-code', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + sessionToken
        }
    })
    .then(response => {
         console.log('DEBUG: generate-qr-code response status:', response.status);
         if (!response.ok) {
            return response.json().then(errorData => {
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }).catch(() => {
                throw new Error(`HTTP error! status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('DEBUG: generate-qr-code response data:', data);
        if (data.status === 'success') {
            const qrCodeContainer = document.getElementById('qr-code-container');
            const qrCodeImg = document.getElementById('qr-code');

            if (qrCodeContainer && qrCodeImg) {
                 qrCodeImg.src = 'https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=' + encodeURIComponent(data.qr_code_url);
                 qrCodeContainer.style.display = 'block';
                 alert(data.message || 'New QR code generated successfully.');
                 console.log('DEBUG: QR code displayed.');
            } else {
                console.error('ERROR: HTML elements for QR code display not found.');
                alert('QR code generated, but cannot display. Check console.');
            }
        } else {
            alert('Error generating new QR code: ' + (data.message || 'Unknown error'));
            const qrCodeContainer = document.getElementById('qr-code-container');
            if (qrCodeContainer) qrCodeContainer.style.display = 'none';
        }
    })
    .catch(error => {
        console.error('Error generating new QR code:', error);
        alert('Error generating new QR code: ' + error.message);
        const qrCodeContainer = document.getElementById('qr-code-container');
        if (qrCodeContainer) qrCodeContainer.style.display = 'none';
    });
}

function generateNewRecoveryCode() {
    const sessionToken = localStorage.getItem('session_token');
    if (!sessionToken) {
        alert('Session token not found. Please log in again.');
        window.location.href = 'login.php';
        return;
    }

    console.log('DEBUG: Sending generate recovery codes request.');
    fetch('/sssd-2025-21002925/api/generate-recovery-codes', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + sessionToken
        }
    })
    .then(response => {
        console.log('DEBUG: generate-recovery-codes response status:', response.status);
        if (!response.ok) {
            return response.json().then(errorData => {
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }).catch(() => {
                throw new Error(`HTTP error! status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('DEBUG: generate-recovery-codes response data:', data);
        if (data.status === 'success' && data.recovery_codes && data.recovery_codes.length > 0) {
            console.log('DEBUG: Attempting to get recovery code display elements.');
            const recoveryCodesArea = document.getElementById('recoveryCodesArea');
            const recoveryCodesList = document.getElementById('recoveryCodesList');
            console.log('DEBUG: recoveryCodesArea element:', recoveryCodesArea);
            console.log('DEBUG: recoveryCodesList element:', recoveryCodesList);

            if (recoveryCodesList && recoveryCodesArea) {
                recoveryCodesList.innerHTML = ''; // Clear previous codes
                data.recovery_codes.forEach(code => {
                    const p = document.createElement('p');
                    p.textContent = code;
                    recoveryCodesList.appendChild(p);
                });
                recoveryCodesArea.style.display = 'block'; // Show the area
                alert(data.message || 'Recovery codes generated successfully.');
                 console.log('DEBUG: Recovery codes displayed.');
            } else {
                 console.error('ERROR: HTML elements for recovery codes display not found.');
                 alert('Recovery codes generated, but cannot display. Check console.');
            }
        } else {
            alert('Failed to generate recovery codes: ' + (data.message || 'Unknown error'));
            const recoveryCodesArea = document.getElementById('recoveryCodesArea');
            if (recoveryCodesArea) recoveryCodesArea.style.display = 'none';
        }
    })
    .catch(error => {
        console.error('Error generating recovery codes:', error);
        alert('Error generating recovery codes: ' + error.message);
        const recoveryCodesArea = document.getElementById('recoveryCodesArea');
        if (recoveryCodesArea) recoveryCodesArea.style.display = 'none';
    });
}
