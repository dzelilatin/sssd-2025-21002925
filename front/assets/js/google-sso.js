document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('google-login-btn');
    if (btn) {
        btn.addEventListener('click', async function() {
            const response = await fetch('/sssd-2025-21002925/api/google-login');
            const data = await response.json();
            if (data.authUrl) {
                window.location.href = data.authUrl;
            } else {
                alert('Failed to get Google login URL');
            }
        });
    }
}); 