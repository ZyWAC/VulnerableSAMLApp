<?php
/**
 * User Registration Page for Jellystone IDP
 * 
 * Allows new users to register an account that will be available
 * for SAML authentication via the SimpleSAMLphp IDP.
 * 
 * Registered users are stored in a JSON file and dynamically loaded
 * by authsources.php at authentication time.
 */

$dataDir = '/var/simplesamlphp/data';
$usersFile = $dataDir . '/registered_users.json';

// Ensure data directory exists
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0777, true);
}

$message = '';
$messageType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username   = trim($_POST['username'] ?? '');
    $password   = trim($_POST['password'] ?? '');
    $confirm    = trim($_POST['confirm_password'] ?? '');
    $email      = trim($_POST['email'] ?? '');
    $firstName  = trim($_POST['first_name'] ?? '');
    $lastName   = trim($_POST['last_name'] ?? '');

    // Validation
    if (empty($username) || empty($password) || empty($confirm) || empty($email) || empty($firstName) || empty($lastName)) {
        $message = 'All fields are required.';
        $messageType = 'error';
    } elseif ($password !== $confirm) {
        $message = 'Passwords do not match.';
        $messageType = 'error';
    } elseif (strlen($username) < 3) {
        $message = 'Username must be at least 3 characters.';
        $messageType = 'error';
    } elseif (strlen($password) < 4) {
        $message = 'Password must be at least 4 characters.';
        $messageType = 'error';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = 'Please enter a valid email address.';
        $messageType = 'error';
    } elseif (preg_match('/[^a-zA-Z0-9_.-]/', $username)) {
        $message = 'Username may only contain letters, numbers, underscores, dots, and hyphens.';
        $messageType = 'error';
    } else {
        // Load existing registered users
        $users = [];
        if (file_exists($usersFile)) {
            $users = json_decode(file_get_contents($usersFile), true) ?: [];
        }

        // Also check static users in authsources — load the config
        $staticUsernames = ['yogi', 'admin', 'rsmith', 'brubble', 'instructor'];

        // Check for duplicate username
        $duplicate = in_array(strtolower($username), array_map('strtolower', $staticUsernames));
        if (!$duplicate) {
            foreach ($users as $u) {
                if (strtolower($u['username']) === strtolower($username)) {
                    $duplicate = true;
                    break;
                }
            }
        }

        if ($duplicate) {
            $message = 'Username "' . htmlspecialchars($username) . '" is already taken.';
            $messageType = 'error';
        } else {
            // Add new user
            $users[] = [
                'username'     => $username,
                'password'     => $password,
                'firstName'    => $firstName,
                'lastName'     => $lastName,
                'emailAddress' => $email,
                'memberOf'     => 'users',
                'registeredAt' => date('Y-m-d H:i:s'),
            ];

            // Save to file
            if (file_put_contents($usersFile, json_encode($users, JSON_PRETTY_PRINT)) !== false) {
                $message = 'Registration successful! You can now <a href="http://127.0.0.1:8000/" style="color: #0ea5e9; font-weight: 600;">log in</a> with your credentials.';
                $messageType = 'success';
                // Clear form fields on success
                $username = $email = $firstName = $lastName = '';
            } else {
                $message = 'Failed to save registration. Please try again.';
                $messageType = 'error';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register — Jellystone IDP</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: #f0f9ff;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
        }
        .idp-register-wrapper {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 2rem 1rem;
        }
        .idp-register-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 1rem;
            box-shadow: 0 4px 24px rgba(14, 165, 233, 0.08);
            max-width: 500px;
            width: 100%;
            overflow: hidden;
        }
        .idp-register-header {
            background: linear-gradient(135deg, #0369a1, #38bdf8);
            padding: 2rem 2rem 1.5rem;
            text-align: center;
            color: #fff;
        }
        .idp-register-header img {
            width: 100px;
            height: auto;
            border-radius: 50%;
            border: 3px solid rgba(255,255,255,0.3);
        }
        .idp-register-header h1 {
            margin: 0.75rem 0 0.25rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: #fff;
        }
        .idp-register-header p {
            margin: 0;
            font-size: 0.85rem;
            opacity: 0.85;
        }
        .idp-register-body {
            padding: 2rem;
        }
        .idp-register-body label {
            display: block;
            font-weight: 600;
            font-size: 0.85rem;
            color: #64748b;
            margin-bottom: 0.35rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .idp-register-body input[type="text"],
        .idp-register-body input[type="password"],
        .idp-register-body input[type="email"] {
            width: 100%;
            padding: 0.65rem 0.875rem;
            border: 1px solid #cbd5e1;
            border-radius: 0.5rem;
            font-size: 0.95rem;
            color: #1e293b;
            background: #fff;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .idp-register-body input:focus {
            outline: none;
            border-color: #0ea5e9;
            box-shadow: 0 0 0 3px rgba(14,165,233,0.15);
        }
        .idp-form-group {
            margin-bottom: 1.25rem;
        }
        .idp-form-row {
            display: flex;
            gap: 1rem;
        }
        .idp-form-row .idp-form-group {
            flex: 1;
        }
        .idp-btn-register {
            display: block;
            width: 100%;
            padding: 0.7rem;
            background: linear-gradient(135deg, #0ea5e9, #38bdf8);
            color: #fff;
            border: none;
            border-radius: 0.5rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            margin-top: 0.5rem;
        }
        .idp-btn-register:hover {
            background: linear-gradient(135deg, #0284c7, #0ea5e9);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(14,165,233,0.3);
        }
        .idp-message {
            border-radius: 0.75rem;
            padding: 0.875rem 1rem;
            margin-bottom: 1.25rem;
            font-size: 0.9rem;
        }
        .idp-message.error {
            background: #fee2e2;
            color: #dc2626;
            border: 1px solid #fca5a5;
        }
        .idp-message.success {
            background: #dcfce7;
            color: #16a34a;
            border: 1px solid #86efac;
        }
        .idp-footer {
            text-align: center;
            padding: 1rem 2rem 1.5rem;
            border-top: 1px solid #e2e8f0;
            font-size: 0.85rem;
            color: #94a3b8;
        }
        .idp-footer a {
            color: #0ea5e9;
            text-decoration: none;
            font-weight: 600;
        }
        .idp-footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="idp-register-wrapper">
        <div class="idp-register-card">
            <div class="idp-register-header">
                <img src="/simplesamlphp/resources/welcome.png" alt="Jellystone">
                <h1>Create Account</h1>
                <p>Register a new Jellystone IDP account</p>
            </div>
            <div class="idp-register-body">
                <?php if ($message): ?>
                <div class="idp-message <?php echo $messageType; ?>">
                    <?php echo $message; ?>
                </div>
                <?php endif; ?>

                <form action="/register" method="post">
                    <div class="idp-form-row">
                        <div class="idp-form-group">
                            <label for="first_name">First Name</label>
                            <input type="text" id="first_name" name="first_name"
                                   value="<?php echo htmlspecialchars($firstName ?? ''); ?>"
                                   placeholder="Yogi" required>
                        </div>
                        <div class="idp-form-group">
                            <label for="last_name">Last Name</label>
                            <input type="text" id="last_name" name="last_name"
                                   value="<?php echo htmlspecialchars($lastName ?? ''); ?>"
                                   placeholder="Bear" required>
                        </div>
                    </div>
                    <div class="idp-form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username"
                               value="<?php echo htmlspecialchars($username ?? ''); ?>"
                               placeholder="Choose a username" required>
                    </div>
                    <div class="idp-form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email"
                               value="<?php echo htmlspecialchars($email ?? ''); ?>"
                               placeholder="user@jellystonep.com" required>
                    </div>
                    <div class="idp-form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password"
                               placeholder="Choose a password" required>
                    </div>
                    <div class="idp-form-group">
                        <label for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" name="confirm_password"
                               placeholder="Repeat your password" required>
                    </div>
                    <button type="submit" class="idp-btn-register">Register</button>
                </form>
            </div>
            <div class="idp-footer">
                Already have an account? <a href="http://127.0.0.1:8000/">Log in</a>
                <br><br>
                Jellystone Identity Provider &mdash; Vulnerable SAML App
            </div>
        </div>
    </div>
</body>
</html>
