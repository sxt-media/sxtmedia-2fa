# sxtmedia-2fa
WordPress Plugin: Enhanced two-factor authentication with an authenticator app, email verification, backup codes, and a secure login process from sxtmedia.

# sxtmedia 2FA Schutz
Erweiterter Zwei-Faktor-Schutz mit Authenticator-App (TOTP), E-Mail-Verifizierung, Backup-Codes und abgesichertem Login-Flow für WordPress.

# Features
Multi-Channel 2FA: Unterstützt TOTP-Apps (Google Authenticator, Bitwarden etc.) und E-Mail-Verifizierung.

Brute-Force Schutz: Integriertes IP- und Account-basiertes Rate-Limiting für Login-Versuche.

REST-API & XML-RPC Härtung: XML-RPC wird deaktiviert, REST-API erzwingt Authentifizierung und App-Passwörter bei aktivem 2FA.

Session-Validierung: Cookie-Validierung via HMAC-SHA256 und User-Agent-Abgleich während des 2FA-Flows.

Sichere Crypto: Verschlüsselung der TOTP-Secrets in der Datenbank mittels OpenSSL (AES-256-GCM).

Anforderungen
WordPress 6.0+

PHP 8.0+ (Ergibt sich aus der Nutzung von random_bytes(), random_int() und OpenSSL AEAD)

Installation
Ordner sxtmedia-2fa-schutz in das Verzeichnis /wp-content/plugins/ hochladen.

Das Plugin über das WordPress-Dashboard aktivieren.

Die Einrichtung wird für alle Benutzer beim nächsten Admin-Besuch erzwungen.

# Technische Details
Meta-Keys:
_sxt_2fa_secret (encrypted)
_sxt_2fa_totp_enabled
_sxt_2fa_email_enabled
_sxt_2fa_recovery_codes (hashed)

Transients: sxt_bf_[md5] (Rate-Limiting), sxt_2fa_[token] (Session-Zwischenspeicher).
