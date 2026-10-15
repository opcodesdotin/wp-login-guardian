=== Login Guardian ===
Contributors: opcodesin, ygohel18
Tags: login, security, 2fa, brute force, rate limit
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 8.0
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced WordPress login security with brute-force protection, login rate limiting, 2FA, username enumeration protection, IP management, activity logging, and threat reporting.

== Description ==

Login Guardian is an advanced WordPress security plugin that protects your website from brute-force attacks, unauthorized login attempts, username enumeration, and malicious IPs. It combines login protection, two-factor authentication (2FA), activity monitoring, IP management, and threat intelligence into one lightweight security solution.

= Features =

* Smart login rate limiting and brute-force protection
* Username enumeration protection
* Two-Factor Authentication (TOTP)
* Login activity monitoring with CSV export
* IP whitelist and blacklist management
* Automatic and manual reporting to Spamhaus and AbuseIPDB
* Login page customization
* Lightweight and performance optimized

== Installation ==

1. Upload the `wp-login-guardian` directory to the `/wp-content/plugins/` directory.
2. Activate the plugin from the 'Plugins' menu in WordPress dashboard.
3. Configure settings under 'Login Guardian' in your WordPress Admin menu.

== Frequently Asked Questions ==

= How does Two-Factor Authentication (2FA) work? =
Login Guardian uses Time-based One-Time Passwords (TOTP). It works with standard authenticator applications such as Google Authenticator, Authy, Microsoft Authenticator, and 1Password.

= What services does threat reporting integrate with? =
You can enable automatic or manual IP reporting for Spamhaus and AbuseIPDB to share threat intelligence and block offending IPs.

= How do I report issues or contribute? =
Please use the GitHub repository: https://github.com/opcodesdotin/wp-login-guardian

== Screenshots ==

1. Dashboard & Security Status Overview
2. Activity Monitor & Logs Export
3. Rate Limiting & Lockout Rules
4. 2FA Configuration & Backup Codes
5. IP Whitelist, Blacklist, and Reporting Controls

== Changelog ==

= 1.0.0 =
* Initial release of Login Guardian.
