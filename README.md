# Vulnerable SAML App

A deliberately vulnerable SAML infrastructure for learning and practicing SAML-based attacks. Forked from the original [Vulnerable SAML App](https://github.com/yogisec/VulnerableSAMLApp) by yogisec.

## Overview

| Service | Technology | Port |
|---------|-----------|------|
| **IDP** | SimpleSAMLphp 1.19.8 / PHP 8.1 | `80` |
| **SP** | Flask + uWSGI / Python | `8000` |

The SP uses a heavily modified [OneLogin python-saml](https://github.com/onelogin/python-saml) library to enable configurable SAML vulnerabilities.

**References:** [Application Walkthrough](https://jellyparks.com/posts/vulnerable-saml-app/) · [SAML Refresher](https://jellyparks.com/web-things/saml-overview.html)

---

## Quick Start

```bash
docker compose up -d --build
```

- SP: **http://127.0.0.1:8000**
- IDP: **http://127.0.0.1**

Rebuild a single service: `docker compose up -d --build sp` or `docker compose up -d --build idp`

> **Note:** No persistent volumes — all data resets on container rebuild.

---

## Login Credentials

| User | Username | Password | Role |
|------|----------|----------|------|
| Unprivileged | `yogi` | `bear` | users |
| HR Staff | `cindy` | `$Up3rS3cr3tEmpl0y33P@ssw0rd` | staffs |
| Admin | `admin` | `this-is-the-administrator-pasword-oh-no-is-that-a-typo-in-password` | administrators |
| Instructor | `instructor` | `th1s-1s-th3-r34l-4dm1n157r470r-p455w0rd-y0u-th0ugh7-17-w45-4-7yp0-bu7-n0p3-7h15-15-4c7u4lly-th3-v4l1d-0n3-g00d-luck-gu355ing-17` | PlatformConfiguration |

User accounts are defined in `vulnerableidp/authsources.php`. New users can also self-register at the IDP registration page.

---

## User Roles

| Role | Access |
|------|--------|
| `users` | Profile, complaints, learn page |
| `staffs` | Staff Panel (HR group management) |
| `administrators` | Admin Panel (when enabled by instructor) |
| `PlatformConfiguration` | Instructor — security settings, instruction mode |

---

## Security Settings

Configurable via the **Settings** page (Instructor only) or `advanced_settings.json`:

| Setting | Description |
|---------|-------------|
| `wantMessagesSigned` | Check `<Signature>` element **exists** in Response (presence only, not validity) |
| `wantAssertionsSigned` | Check `<Signature>` element **exists** in Assertion (presence only, not validity) |
| `validMessage` | **Validate** Response signature cryptographically |
| `validAssertion` | **Validate** Assertion signature cryptographically |
| `signMetadata` | Sign SP metadata |
| `adminPanelEnabled` | Toggle Admin Panel access for admin users |
> **Key:** `wantMessagesSigned` / `wantAssertionsSigned` only check signature **presence**. Without `validMessage` / `validAssertion`, attackers can freely modify SAML content.

**Vulnerability Settings** (separate toggle card in Settings):

| Setting | Description |
|---------|-------------|
| `xswVulnerable` | XML Signature Wrapping (XSW1–XSW8) — bypasses schema validation and signature verification |
| `xxeVulnerable` | XML External Entity — parser resolves external entities, enabling OOB exfiltration |
| `xsltVulnerable` | XSLT Injection — XSLT stylesheets in `<ds:Transform>` are executed, enabling local file read and OOB requests |
> **OOB Restriction:** XXE and XSLT attacks only allow out-of-band requests to `*.oastify.com` (Burp Collaborator). XSLT also allows local file access (e.g. `/etc/passwd`). All other external requests are blocked.

**CVE Settings** (separate toggle card in Settings):

| Setting | Description |
|---------|-------------|
| `cve-2017-11427` | XML Comment Injection |
| `cve-2022-41912` | Multiple Assertion Signature Bypass — SP validates signature on first (signed) Assertion but reads data from last (unsigned) Assertion |
| `cve-2025-23369` | XML Entity ID Confusion — SP accepts DTD entity definitions; libxml2's XPath hash optimization skips entity ref nodes, causing signature validation to verify an injected Assertion in `ds:Object` instead of the Response root |
| `cve-2025-25291` | SAML Round-trip Attack — `DOCTYPE SYSTEM` single-quoted identifier shifts XML comment boundaries after REXML re-serializes (single→double quotes), causing REXML to verify original CDATA-wrapped signed content while Nokogiri reads attacker-controlled Assertion attributes |
| `cve-2025-25292` | SAML Namespace Confusion — duplicate `xmlns` ATTLIST in DTD causes REXML to validate real `<Signature>` in `StatusDetail` while Nokogiri reads forged Assertion; void canonicalization (relative namespace URI → libxml2 returns empty string → DigestValue = SHA-256("") always passes) completes the bypass |
> More will be added in future update


---

## Attack Scenarios

Security settings are configurable via toggle switches on the **Settings** page (Instructor login required). You can test each vulnerability scenario as described in the [original blog walkthrough](https://jellyparks.com/posts/vulnerable-saml-app/).

### Challenge

With the current configuration, the intended attack chain is:

1. **Register** a new user at the IDP (`http://127.0.0.1/register`)
2. **XSW Attack** — Use XML Signature Wrapping to escalate your role from `users` to `staffs`
3. **Create a Custom Group** — As a staff member, use the Staff Panel to create a group named `administratorsnot` and assign yourself to it
4. **CVE-2017-11427** — Re-login, intercept the SAML Response, and inject an XML comment (`administrators<!---->not`) to escalate to `administrators`
5. **Self-Assignment** — Using the Admin Panel to assign the `administrators` group to your account for persistent admin privileges.
---

## Multi-Host Deployment

Run `configure_platform.py` to interactively configure IPs, or manually edit:

- **IDP:** Replace `127.0.0.1:8000` in `vulnerableidp/saml20-sp-remote.php`
- **SP:** Replace `127.0.0.1` addresses in `vulnerablesp/yogiSP/saml/settings.json`

---

## TODO

- Add more attack scenarios and CVE implementations, primarily based on Burp Suite's [SAMLRaider](https://github.com/CompassSecurity/SAMLRaider) extension

---
Shout out to E.D. for initial dockerization of the IDP.
