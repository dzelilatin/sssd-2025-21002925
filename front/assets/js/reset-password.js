document.addEventListener('DOMContentLoaded', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (!token) {
        document.getElementById('message').innerHTML = '<p style="color:red;">Invalid or missing reset token.</p>';
        document.getElementById('reset-password-form').style.display = 'none';
        return;
    }
    document.getElementById('token').value = token;
});

document.getElementById('reset-password-form').addEventListener('submit', function(e) {
    e.preventDefault();

    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const token = document.getElementById('token').value;
    const messageDiv = document.getElementById('message');

    // Validate passwords match
    if (password !== confirmPassword) {
        messageDiv.innerHTML = '<p style="color:red;">Passwords do not match.</p>';
        return;
    }

    // Validate password strength
    if (password.length < 8 || 
        !/[A-Z]/.test(password) || 
        !/[a-z]/.test(password) || 
        !/\d/.test(password) || 
        !/[\W_]/.test(password)) {
        messageDiv.innerHTML = '<p style="color:red;">Password must be 8+ characters with upper/lowercase, number, and special character.</p>';
        return;
    }

    fetch('../../api/reset-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
            password: password,
            confirm_password: confirmPassword,
            token: token 
        })
    })
    .then(response => {
        // Check for HTTP errors
        if (!response.ok) {
            // Attempt to read the response body for a message
            return response.json().then(errorData => {
                // Throw an error that includes the backend message if available
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }).catch(() => {
                // If reading JSON fails, just throw a generic error with status
                throw new Error(`HTTP error! status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        const messageDiv = document.getElementById('message');
        messageDiv.style.display = 'block'; // Ensure message div is visible
        if (data.status === 'success') {
            messageDiv.innerHTML = '<p style="color:green;">' + data.message + '</p>';
            // Redirect to login page after 3 seconds
            setTimeout(() => {
                window.location.href = '/sssd-2025-21002925/front/pages/login.php';
            }, 3000);
        } else {
            // This block handles non-success status codes from the backend API response
            // which might still be 200 but indicate a logical error
            messageDiv.innerHTML = '<p style="color:red;">' + (data.message || 'An unknown error occurred.');
        }
    })
    .catch(error => {
        const messageDiv = document.getElementById('message');
        messageDiv.style.display = 'block'; // Ensure message div is visible
        console.error('Error:', error);
        // Display the error message from the caught exception
        messageDiv.innerHTML = '<p style="color:red;">' + (error.message || 'An error occurred during password reset. Please try again later.') + '</p>';
    });
});
