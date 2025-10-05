document.addEventListener('DOMContentLoaded', function() {
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    const captchaContainer = document.getElementById('captcha-container');
    const messageDiv = document.getElementById('message');
    const submissionLimit = 2;
    const timeLimit = 10 * 60 * 1000; // 10 minutes in milliseconds
    const storageKey = 'forgot-password-submissions';

    function getSubmissions() {
        const submissions = localStorage.getItem(storageKey);
        return submissions ? JSON.parse(submissions) : [];
    }

    function addSubmission() {
        const submissions = getSubmissions();
        const now = Date.now();
        submissions.push(now);
        localStorage.setItem(storageKey, JSON.stringify(submissions));
    }

    function cleanUpOldSubmissions() {
        const submissions = getSubmissions();
        const now = Date.now();
        const filteredSubmissions = submissions.filter(timestamp => now - timestamp <= timeLimit);
        localStorage.setItem(storageKey, JSON.stringify(filteredSubmissions));
        return filteredSubmissions;
    }

    forgotPasswordForm.addEventListener('submit', function(event) {
        event.preventDefault();

        const recentSubmissions = cleanUpOldSubmissions();
        if (recentSubmissions.length >= submissionLimit) {
            captchaContainer.style.display = 'block';
            const hCaptchaResponse = hcaptcha.getResponse();
            if (!hCaptchaResponse) {
                alert('Please complete the CAPTCHA.');
                return;
            }
        }

        proceedWithPasswordReset();
    });

    function proceedWithPasswordReset() {
        const email = document.getElementById('email').value;
        const captchaResponse = hcaptcha.getResponse();

        const data = {
            email: email
        };

        if (captchaResponse) {
            data['h-captcha-response'] = captchaResponse;
        }

        fetch('../../api/forgot-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Show message to check email
                const messageDiv = document.createElement('div');
                messageDiv.style.cssText = 'color: #155724; background-color: #d4edda; padding: 15px; margin: 10px 0; border-radius: 4px; text-align: center;';
                messageDiv.textContent = 'If your email is registered, you will receive a password reset link. Please check your email.';
                
                // Clear the form and show the message
                forgotPasswordForm.reset();
                forgotPasswordForm.style.display = 'none';
                
                // Hide the static 'Back to Login' link
                const staticLinksDiv = document.querySelector('.links');
                if (staticLinksDiv) {
                    staticLinksDiv.style.display = 'none';
                }

                document.querySelector('.forgot-password-container').appendChild(messageDiv);
                
                // Add a link to go back to login
                const loginLink = document.createElement('a');
                loginLink.href = '/sssd-2025-21002925/front/pages/login.php';
                loginLink.textContent = 'Return to Login';
                loginLink.style.cssText = 'display: block; text-align: center; margin-top: 15px; color: #007bff; text-decoration: none;';
                document.querySelector('.forgot-password-container').appendChild(loginLink);
            } else {
                messageDiv.innerHTML = '<p style="color:red;">' + data.message + '</p>';
                if (data.require_captcha) {
                    captchaContainer.style.display = 'block';
                }
            }
            addSubmission();
        })
        .catch(error => {
            console.error('Error:', error);
            messageDiv.innerHTML = '<p style="color:red;">An error occurred. Please try again later.</p>';
            addSubmission();
        });
    }
});
