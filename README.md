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
| Admin | `admin` | `this-is-the-administrator-pasword-oh-no-is-that-a-typo-in-password` | administrators |
| Regular User | `brubble` | `password` | users |
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

### User Roles

| Role | Capabilities |
|------|-------------|
| `users` | View profile, file complaints, view learn page |
| `administrators` | All user capabilities + admin panel (when enabled) |
| `PlatformConfiguration` | Instructor role — can toggle security settings and instruction mode |

### Security Settings

Configurable via the Settings page (Instructor only) or by editing `advanced_settings.json`:

- **wantNameIdEncrypted** — Require encrypted NameID
- **wantAssertionsSigned** — Require signed assertions
- **wantAssertionsEncrypted** — Require encrypted assertions
- **wantMessagesSigned** — Require signed messages
- **adminPanelEnabled** — Toggle admin panel access for admin users

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
│   ├── loginuserpass.twig         # Modernized login template (Twig)
│   ├── loginuserpass.php          # Modernized login template (PHP)
│   └── saml20-sp-remote.php       # SP metadata for IDP
├── vulnerablesp/                  # Flask SP container
│   ├── src/onelogin/saml2/        # Modified OneLogin python-saml library
│   └── yogiSP/
│       ├── vulnsp.py              # Main Flask application
│       ├── jsonparse.py           # JSON settings/user management
│       ├── saml/                  # SAML settings & certificates
│       │   ├── settings.json
│       │   └── advanced_settings.json
│       ├── templates/             # Jinja2 templates (Bootstrap 5)
│       └── users/users.json       # User database
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
