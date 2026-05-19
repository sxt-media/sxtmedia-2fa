# SXT 2FA

Enhanced two-factor authentication for WordPress with TOTP authenticator apps, email verification, backup codes and hardened login security.

---

## Features

### Multi-Channel 2FA
Supports:

- Google Authenticator
- Bitwarden
- Authy
- Microsoft Authenticator
- E-Mail verification

### Brute-Force Protection
Integrated login protection with:

- IP-based rate limiting
- account-based throttling
- temporary lockouts

### REST API & XML-RPC Hardening

- Disables XML-RPC
- Restricts REST API access
- Forces authentication for sensitive endpoints
- Blocks application passwords when 2FA is enabled

### Secure Login Flow

- HMAC-SHA256 cookie validation
- user-agent verification
- temporary signed login sessions
- protected 2FA challenge flow

### Secure Cryptography

- AES-256-GCM encryption for TOTP secrets
- OpenSSL-based encryption
- hashed recovery codes
- secure token generation using `random_bytes()`

---

## Requirements

- WordPress 6.0+
- PHP 8.0+
- OpenSSL extension enabled

---

## Installation

1. Upload the plugin to:

```text
/wp-content/plugins/sxtmedia-2fa/
