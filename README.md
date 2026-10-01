# SecOps_Lab## Features

### Dashboard

Provides an overview of the security tools available in SecOps Lab and acts as the main navigation page.

### Password Tools

Provides tools for analyzing password strength and demonstrating secure password hashing methods.

Supported hashing methods include:

* Argon2
* bcrypt
* scrypt
* PBKDF2

The password analysis feature also uses **zxcvbn** to evaluate password strength.

### Hash Tools

Provides a practical environment for working with hashing concepts and understanding how hash functions are used in cybersecurity.

### Encoding Tools

Provides tools for experimenting with common encoding techniques and understanding the difference between encoding and encryption.

### Network Tools

Contains basic network security-related tools and concepts designed to help users understand network information and security operations.

### Web Tools

Allows users to enter a URL and check commonly used HTTP security headers.

The tool checks:

* Strict-Transport-Security (HSTS)
* Content-Security-Policy (CSP)
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy

This section helps demonstrate how HTTP security headers can improve the security of web applications.

### JWT Tools

Provides tools for learning about JSON Web Tokens (JWT), including token structure and authentication concepts.

### Log Analyzer

Provides a basic environment for analyzing log data and understanding how logs can be used in security monitoring and Security Operations.

### Authentication

The application includes user registration and login functionality with JWT-based authentication. Protected pages require an authenticated user session.

### Logout

Allows authenticated users to securely end their current session.
