# Secure User Authentication System

![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-005C84?style=for-the-badge&logo=mysql&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Composer](https://img.shields.io/badge/Composer-885610?style=for-the-badge&logo=composer&logoColor=white)

A comprehensive user authentication and management system developed as a university project for a Secure Software System Design course. This project implements a secure RESTful API backend in PHP, featuring robust security practices and a complete authentication workflow.

---

## ✨ Key Features

* **User Registration:** Secure registration with server-side validation.
* **User Login:** Standard login with username/email and password.
* **Multi-Factor Authentication (2FA/MFA):**
    * Time-Based One-Time Password (TOTP) via Authenticator Apps (e.g., Google Authenticator).
    * SMS-based verification codes.
    * Email-based verification codes.
* **Social Login:** Seamless authentication using Google OAuth 2.0.
* **Password Security:**
    * Password hashing using modern algorithms.
    * "Pwned Passwords" API check to prevent the use of compromised passwords.
    * Secure password reset functionality via email link.
* **Account Security:**
    * Brute-force protection with hCaptcha integration after multiple failed login attempts.
    * Email verification for new user registrations.
    * Generation of one-time use recovery codes.
* **Session Management:** Secure, token-based session handling for authenticated users.

---

## 🔧 Technology Stack

* **Backend:** PHP
* **API Framework:** [FlightPHP](https://flightphp.com/)
* **Database:** MySQL / MariaDB
* **Dependencies:**
    * `phpmailer/phpmailer` for sending emails (via SendGrid).
    * `spomky-labs/otphp` for TOTP generation and verification.
    * `google/apiclient` for Google OAuth 2.0 integration.
    * `libphonenumber-for-php` for phone number validation.
* **Frontend:** HTML, CSS, JavaScript (for user interface and API interaction).
* **Development Environment:** XAMPP

---

## 🚀 Getting Started

Follow these instructions to get a local copy of the project up and running for development and testing.

### Prerequisites

* A local web server environment like [XAMPP](https://www.apachefriends.org/) or WAMP (with PHP 8.0+ and MySQL).
* [Composer](https://getcomposer.org/) for managing PHP dependencies.
* Git for version control.

### Installation

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/dzelilatin/sssd-2025-21002925.git](https://github.com/dzelilatin/sssd-2025-21002925.git)
    cd sssd-2025-21002925
    ```

2.  **Install PHP dependencies:**
    ```sh
    composer install
    ```

3.  **Set up the database:**
    * Open your database management tool (e.g., phpMyAdmin).
    * Create a new database.
    * Import the `database.sql` file into the new database to create the necessary tables.

4.  **Configure environment variables:**
    * Create a `.env` file in the root directory by copying the example structure:
        ```sh
        cp .env.example .env
        ```
    * Open the `.env` file and fill in your credentials for the database, Google OAuth, SendGrid, Infobip, and hCaptcha.

5.  **Configure your web server:**
    * Point the document root of your local server (e.g., Apache Virtual Host) to the project's root directory.
    * Ensure that `mod_rewrite` is enabled to allow `.htaccess` to handle API routing.

---

## ⚙️ Configuration

All sensitive information and environment-specific settings are stored in the `.env` file. Create a `.env.example` file in your repository to show what variables are needed.

**.env.example**
```ini
# Database
DB_HOST=your_database_host
DB_USERNAME=your_database_username
DB_PASSWORD=your_database_password
DB_NAME=your_database_name
DB_PORT=3306

# Infobip (for SMS)
TEXT_MESSAGE_API_KEY=your_infobip_api_key
INFOBIP_SMS_API_URL=your_infobip_api_url

# SendGrid (for Email)
SMTP_HOST=smtp.sendgrid.net
SMTP_USERNAME=apikey
SMTP_PASSWORD=your_sendgrid_api_key
SMTP_PORT=587
SMTP_ENCRYPTION=tls

# hCaptcha
HCAPTCHA_SERVER_SECRET=your_hcaptcha_server_secret
HCAPTCHA_SITE_KEY=your_hcaptcha_site_key

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost/path/to/project/api/google-callback
```

---

## 🔑 API Endpoints

The core API is built with FlightPHP. Here are some of the main endpoints:

| Method | Endpoint                    | Description                                       |
|--------|-----------------------------|---------------------------------------------------|
| `POST` | `/register`                 | Registers a new user.                             |
| `POST` | `/login`                    | Logs in a user and initiates the 2FA process.     |
| `GET`  | `/google-login`             | Initiates the Google OAuth 2.0 login flow.        |
| `GET`  | `/google-callback`          | Handles the callback from Google after login.     |
| `POST` | `/send-2fa-code`            | Sends a 2FA code via SMS or Email.                |
| `POST` | `/verify-2fa`               | Verifies a TOTP, SMS, or Email code to complete login. |
| `POST` | `/forgot-password`          | Sends a password reset link to the user's email.  |
| `POST` | `/reset-password`           | Resets the user's password using a valid token.   |
| `POST` | `/generate-recovery-codes`  | Generates a new set of backup recovery codes.     |
| `POST` | `/logout`                   | Invalidates the user's current session token.     |
| `GET`  | `/get-username`             | Retrieves the username for the logged-in user.    |
| `POST` | `/change-password`          | Allows a logged-in user to change their password. |

---

## 🛡️ Security Features Implemented

This project prioritizes security by implementing the following measures:

* **Environment Variables:** All secrets (API keys, DB credentials) are stored outside the codebase in a `.env` file, which is excluded from version control.
* **Password Hashing:** Uses PHP's `password_hash()` and `password_verify()` functions, which implement the secure Bcrypt algorithm.
* **Multi-Factor Authentication:** Provides multiple layers of security for user accounts, preventing unauthorized access even if the password is compromised.
* **Brute-Force Protection:** Implements rate limiting and hCaptcha challenges on the login form after several failed attempts to thwart automated attacks.
* **Pwned Password Prevention:** Checks user passwords against the "Have I Been Pwned" database to block commonly used or previously breached passwords.
* **Prepared Statements:** All database queries use PDO with prepared statements to prevent SQL injection vulnerabilities.
* **Secure Email & SMS Transport:** Uses trusted third-party services (SendGrid, Infobip) for reliable and secure delivery of verification codes.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## 👨‍💻 Author

**Dzelil Atin**
* GitHub: [@dzelilatin](https://github.com/dzelilatin)