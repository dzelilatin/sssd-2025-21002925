document.getElementById('signup-form').addEventListener('submit', function(event) {
    event.preventDefault();
    registerUser();
});

function registerUser() {
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const full_name = document.getElementById('full_name').value;
    const phone = document.getElementById('phone').value;
    const messageContainer = document.getElementById('error-message');

    // Clear previous message
    messageContainer.innerText = '';

    // Validate required fields
    if (!full_name || !username || !email || !phone || !password) {
        messageContainer.innerText = 'All fields are required!';
        return;
    }

    const data = {
        username,
        email,
        password,
        full_name,
        phone
    };

    console.log('Data being sent:', data);

    fetch('../../api/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        console.log('Response status:', response.status);
        console.log('Response headers:', response.headers);
        
        // Check if the response is JSON
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Server returned non-JSON response. Please try again later.');
        }
        
        return response.json();
    })
    .then(data => {
        console.log('Registration API response:', data);
        console.log('Validation errors:', data.errors);

        if (data.status === 'success') {
            // Show success message
            let successMessage = data.message;
            if (data.confirmation_required) {
                successMessage = 'Registration successful! Please check your email to verify your account.';
            }
            messageContainer.innerText = successMessage;
            messageContainer.style.color = 'green';
            messageContainer.style.fontWeight = 'bold';
            messageContainer.style.fontSize = '18px';
            // Disable the form to prevent multiple submissions
            document.getElementById('signup-form').style.display = 'none';
            // Show the message container
            messageContainer.style.display = 'block';
            // Redirect to login page after 5 seconds
            setTimeout(() => {
                window.location.href = 'login.php';
            }, 5000);
        } else {
            // Handle validation errors
            if (data.errors && Array.isArray(data.errors)) {
                messageContainer.innerHTML = '<strong>Please fix the following errors:</strong><br>' + 
                    data.errors.map(error => `• ${error}`).join('<br>');
            } else {
                messageContainer.innerText = data.message || 'An error occurred during registration.';
            }
            messageContainer.style.color = 'red';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        messageContainer.innerText = error.message || 'An error occurred during registration. Please try again later.';
        messageContainer.style.color = 'red';
    });
}
