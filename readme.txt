=== Branded Reset Emails (Advanced) ===
Contributors: Van Isle Web Solutions
Tags: email, password reset, branding, wp_mail, html email, multisite
Tested up to: 6.8.2
Stable tag: 1.2.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Rebrand WordPress password reset and related emails with admin-configurable From name/email, subject brand, optional HTML template, a test email button, and multisite network overrides.

== Features ==
- Change From Name and From Email
- Customize Subject brand/prefix ([Brand] Password Reset)
- Optional **HTML email** template with placeholders ({{brand}}, {{username}}, {{reset_url}}, {{body_intro}}, {{closing}})
- **Preview** the HTML template in-browser
- **Send test email** to the current admin user
- Multisite: set network defaults and optionally **force** them on subsites

== Installation ==
1. Upload the ZIP via **Plugins → Add New → Upload Plugin**.
2. Activate **Branded Reset Emails (Advanced)**.
3. Go to **Settings → Branded Emails** to configure.
4. (Multisite) In **Network Admin → Settings → Branded Emails**, set network defaults/force.

== Notes ==
- Works with SMTP plugins (respecting your From headers unless you override here).
- For best deliverability, set up SPF, DKIM, and DMARC for the From domain.
