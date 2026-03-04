# Vulnerable SAML App

A deliberately vulnerable SAML infrastructure for learning and practicing SAML-based attacks in a safe environment. This is the forked version of the original Vulnerable SAML App created by yogisec.

## Overview

This project provides a two-container Docker setup:

| Service | Technology | Port | Description |
|---------|-----------|------|-------------|
| **IDP** (Identity Provider) | SimpleSAMLphp 1.19.8 / PHP 8.1 | `80` | Authenticates users, issues SAML assertions |
| **SP** (Service Provider) | Flask + uWSGI / Python | `8000` | Consumes SAML assertions, hosts the web app |

A high-level getting started guide is below. For a more detailed guide covering the app, features, settings, and walkthroughs please check out:

- [Application Overview and Walkthrough](https://jellyparks.com/posts/vulnerable-saml-app/)
- [SAML Refresher](https://jellyparks.com/web-things/saml-overview.html)

The purpose of these applications is to showcase how certain vulnerable configurations can be exploited to allow a user to change their permissions, name, etc. within an application. OneLogin's Python SAML library was utilized for this. In order for some of these vulnerable configurations to work the library was heavily modified.

---

## Quick Start

```bash
docker compose up -d --build
```

The web application will be available at **http://127.0.0.1:8000** and the IDP at **http://127.0.0.1**.

To rebuild a single service after making changes:

```bash
docker compose up -d --build sp    # rebuild SP only
docker compose up -d --build idp   # rebuild IDP only
```

---

## Login Credentials

| User | Username | Password | Role |
|------|----------|----------|------|
| Unprivileged | `yogi` | `bear` | users |
| HR Staff | `cindy` | `$Up3rS3cr3tEmpl0y33P@ssw0rd` | staffs |
| Admin | `admin` | `this-is-the-administrator-pasword-oh-no-is-that-a-typo-in-password` | administrators |
| Instructor | `instructor` | `G0od-LuckGu3ssingThisButHeyItCouldHappenRight?` | PlatformConfiguration |

If you'd like to change user accounts or groups, edit `vulnerableidp/authsources.php`. All user accounts are statically assigned and created within that file.

---

## Features

### SAML Group Validation

The SP validates SAML response attributes against the known user database (`users.json`). If an attacker modifies their group membership in a SAML assertion, the application will detect the mismatch and display a detailed error on the login page (when security settings allow it).

### Instruction Mode (Admin Panel Toggle)

The **Instructor** user (`PlatformConfiguration` role) can control whether the Admin Panel is accessible to admin-role users:

- **Navigate to** Settings → toggle **Admin Panel Enabled**
- When **OFF**: Admin users see a locked "Welcome Admin" screen instead of the management panel
- When **ON**: Admin users have full access to user management (add/edit/delete)

This is controlled via the `adminPanelEnabled` flag in `advanced_settings.json`.

### Staff Panel (HR Group Management)

The **Staffs** role (`cindy` by default) provides an HR-like management interface:

- **Create custom groups** with configurable permission levels (`users` or `staffs`)
- **Assign users** to any non-admin group (users, staffs, or custom groups)
- **Delete custom groups** (affected users are moved back to `users`)
- **Restore groups** to default empty state

Staff users **cannot** manage administrators or PlatformConfiguration users, and **cannot** create groups named `administrators` or `PlatformConfiguration`.

Group changes are synced with the IDP automatically via an internal API. Users must **re-login** for the new group to appear in their SAML assertion. This is key for the CVE-2017-11427 attack scenario.

### User Roles

| Role | Capabilities |
|------|-------------|
| `users` | View profile, file complaints, view learn page |
| `staffs` | All user capabilities + Staff Panel (HR group management) |
| `administrators` | All user capabilities + Admin Panel (when enabled by instructor) |
| `PlatformConfiguration` | Instructor role — can toggle security settings and instruction mode |

### Security Settings

Configurable via the Settings page (Instructor only) or by editing `advanced_settings.json`:

| Setting | Effect |
|---------|--------|
| **wantMessagesSigned** | Checks that a `<Signature>` element **exists** in the SAML Response. Does **NOT** validate the signature. |
| **wantAssertionsSigned** | Checks that a `<Signature>` element **exists** in the Assertion. Does **NOT** validate the signature. |
| **validMessage** | Actually **validates** the Response signature cryptographically. Rejects modified responses. |
| **validAssertion** | Actually **validates** the Assertion signature cryptographically. Rejects modified assertions. |
| **signMetadata** | Sign the SP metadata. |
| **CVE-2017-11427** | Enables the vulnerable XML comment parsing (`element.text` vs `itertext()`). |
| **adminPanelEnabled** | Toggle admin panel access for admin users (Instruction Mode). |

> **Important:** `wantMessagesSigned` / `wantAssertionsSigned` only check for signature **presence**, not validity. Without `validMessage` or `validAssertion`, an attacker can freely modify SAML response content — the existing (now-invalid) signature element still passes the presence check.

---

## Attack Scenarios

### Scenario 1: No Signature Validation (Direct Attribute Tampering)

**Settings:** All security options OFF (default)

1. Log in as `yogi` (password: `bear`)
2. Intercept the SAML Response (e.g., using Burp Suite)
3. Base64-decode the `SAMLResponse` parameter
4. Change the `memberOf` attribute value from `users` to `administrators`
5. Base64-encode and forward — privilege escalation succeeds

**Why it works:** No signature validation means any modification to the SAML response is accepted.

### Scenario 2: Signature Presence Check Bypass

**Settings:** `wantMessagesSigned` ✅ + `wantAssertionsSigned` ✅ (but `validMessage` ❌ and `validAssertion` ❌)

1. Same steps as Scenario 1 — direct attribute tampering **still works**

**Why it works:** These settings only verify that a `<Signature>` XML element exists in the response/assertion. Since the IDP originally signed the response, the signature element is present. Modifying the XML content makes the signature cryptographically invalid, but since `validMessage` / `validAssertion` are OFF, the signature is never actually verified.

### Scenario 3: CVE-2017-11427 — Real-World XML Comment Injection

**Settings:** `wantMessagesSigned` ✅ + `wantAssertionsSigned` ✅ + `validMessage` ✅ and/or `validAssertion` ✅ + `cve-2017-11427` ✅

This is the **realistic** CVE-2017-11427 demo. It requires cryptographic signature validation to be ON.

**Background:** XML Digital Signatures use [Exclusive Canonicalization (C14N)](https://www.w3.org/TR/xml-exc-c14n/) which **strips XML comments** before computing the digest. This means inserting a comment into a signed value does not invalidate the signature — the canonical form is identical.

**Full Attack Flow:**

1. **Instructor Setup:** Log in as `instructor`, enable `wantMessagesSigned`, `wantAssertionsSigned`, `validMessage`/`validAssertion`, and `cve-2017-11427` in SAML Settings
2. **Staffs Preparation:** Log in as `cindy` (password: `$Up3rS3cr3tEmpl0y33P@ssw0rd`, group: `staffs`)
3. **Create Attack Group:** Navigate to Staff Panel → Create custom group named `administratorsnot` (permission level: `staffs`)
4. **Self-Assignment:** Assign yourself (`cindy`) to the `administratorsnot` group
5. **Re-login:** Log out and log back in as `cindy` — the IDP now sends `administratorsnot` in the SAML assertion
6. **Intercept:** Intercept the SAML Response with Burp Suite
7. **Inject Comment:** Base64-decode the `SAMLResponse`, find `<saml:AttributeValue>administratorsnot</saml:AttributeValue>`, change it to `<saml:AttributeValue>administrators<!---->not</saml:AttributeValue>`
8. **Forward:** Base64-encode and forward — privilege escalation succeeds!

**What happens:**

| Step | Detail |
|------|--------|
| Signature Verification | C14N strips the comment → `administratorsnot` → **matches original signed content** → ✅ signature valid |
| Vulnerable Parser (`.text`) | Reads only text before the comment → `administrators` → **privilege escalation!** |

**Comparison:**

| Modification | Signature Valid? | CVE ON (`.text`) | CVE OFF (`itertext()`) |
|-------------|-----------------|------------------|------------------------|
| `administrators<!---->not` | ✅ Yes (C14N strips comment) | `administrators` → **escalation** | `administratorsnot` → no escalation |
| `administrators` (direct) | ❌ No (different from original) | N/A — rejected | N/A — rejected |

**This demonstrates the real CVE:** The signature is cryptographically valid (comments are stripped during C14N), but the vulnerable XML parser misinterprets the value because `.text` only returns text before the first child/comment node.

**Why this is realistic:** In a real organization, an HR staff member (like `cindy`) has the ability to create custom groups. By naming a group `administratorsnot` and assigning themselves to it, they create a legitimate SAML assertion that can be exploited via XML comment injection to appear as `administrators`.

### Scenario 4: Full Signature Validation (Secure Configuration)

**Settings:** `validMessage` ✅ and/or `validAssertion` ✅ + `cve-2017-11427` ❌

1. Log in as `cindy` (after following the Scenario 3 setup to move into `administratorsnot` group)
2. Intercept and try `administrators<!---->not`
3. Signature is valid (C14N strips comment), but **patched parser** (`itertext()`) reads `administratorsnot` → no escalation
4. Direct `administrators` → signature invalid → rejected

**This is the patched configuration.** The CVE fix uses `itertext()` which concatenates all text nodes, making comment injection ineffective.

---

## Splitting the Deployment to Multiple Hosts

Want to set this up on separate servers or point to an address that isn't localhost? **The easiest approach is to run `configure_platform.py` as a privileged user and follow the prompts.** The script will edit the configuration files, build the Docker images, and launch them for you.

### Manual Configuration

#### IDP Configuration

File: `vulnerableidp/saml20-sp-remote.php`

Replace every instance of `127.0.0.1:8000` with the IP/hostname of the SP host.

```bash
cd vulnerableidp
sudo docker build -t idp:1.0 .
sudo docker run -it --rm --name idp -d -p 80:80 idp:1.0
```

#### SP Configuration

File: `vulnerablesp/yogiSP/saml/settings.json`

- In the **SP** section, replace `127.0.0.1:8000` with your web application's address
- In the **IDP** section, replace `127.0.0.1` with the IDP server address

```bash
cd vulnerablesp
sudo docker build -t sp:1.0 .
sudo docker run -it --rm --name sp -d -p 8000:8000 sp:1.0
```

---

## Project Structure

```
├── configure_platform.py          # Auto-configuration script
├── docker-compose.yml             # Docker Compose orchestration
├── vulnerableidp/                 # SimpleSAMLphp IDP container
│   ├── authsources.php            # User accounts & credentials
│   ├── api_update_group.php       # Group sync API for Staff Panel
│   ├── loginuserpass.twig         # Modernized login template (Twig)
│   ├── loginuserpass.php          # Modernized login template (PHP)
│   └── saml20-sp-remote.php       # SP metadata for IDP
├── vulnerablesp/                  # Flask SP container
│   ├── src/onelogin/saml2/        # Modified OneLogin python-saml library
│   └── yogiSP/
│       ├── vulnsp.py              # Main Flask application
│       ├── jsonparse.py           # JSON settings/user/group management
│       ├── saml/                  # SAML settings & certificates
│       │   ├── settings.json
│       │   └── advanced_settings.json
│       ├── templates/             # Jinja2 templates (Bootstrap 5)
│       ├── users/users.json       # User database
│       └── groups/groups.json     # Custom groups database (Staff Panel)
```

---

## User Registration

The IDP now supports open user registration at **http://127.0.0.1/register**. New users can create an account with a username, password, email, first name, and last name. Registered users are assigned the `users` role by default and can immediately log in via the SAML flow.

Registered users are stored in `/var/simplesamlphp/data/registered_users.json` inside the IDP container and are dynamically loaded by `authsources.php` at authentication time. A "Register here" link is also shown on the IDP login page.

> **Note:** Since this is a deliberately vulnerable app, registration data does not persist across container rebuilds.

---

## TODO
- [ ] Implement attack scenarios based on [SAMLRaider](https://github.com/CompassSecurity/SAMLRaider) capabilities (XSW, certificate cloning, SAML message manipulation)

---

Shout out to E.D. for initial dockerization of the IDP.
