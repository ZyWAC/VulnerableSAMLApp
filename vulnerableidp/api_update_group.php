<?php
/**
 * IDP API: Update User Group Override
 * 
 * Called by the SP staff management panel to update a user's group assignment.
 * Writes to group_overrides.json which is read by authsources.php to override
 * static user group assignments at authentication time.
 *
 * POST /api/update_group
 *   - username: the target username
 *   - group: the new group name
 *   - action: "set" or "remove"
 */

header('Content-Type: application/json');

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$dataDir = '/var/simplesamlphp/data';
$overridesFile = $dataDir . '/group_overrides.json';

// Ensure data directory exists
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0777, true);
}

// Parse input
$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    // Try form data
    $input = $_POST;
}

$username = trim($input['username'] ?? '');
$group = trim($input['group'] ?? '');
$action = trim($input['action'] ?? 'set');

if (empty($username)) {
    http_response_code(400);
    echo json_encode(['error' => 'Username is required']);
    exit;
}

// Protected users that cannot be overridden via this API
$protectedUsers = ['admin', 'instructor'];
if (in_array(strtolower($username), array_map('strtolower', $protectedUsers))) {
    http_response_code(403);
    echo json_encode(['error' => 'Cannot modify protected user groups']);
    exit;
}

// Protected groups that cannot be assigned via this API
$protectedGroups = ['administrators', 'PlatformConfiguration'];
if ($action === 'set' && in_array($group, $protectedGroups)) {
    http_response_code(403);
    echo json_encode(['error' => 'Cannot assign protected group via API']);
    exit;
}

// Load existing overrides
$overrides = [];
if (file_exists($overridesFile)) {
    $overrides = json_decode(file_get_contents($overridesFile), true) ?? [];
}

if ($action === 'clear_all') {
    // Clear all overrides (used by admin restore)
    $overrides = [];
} elseif ($action === 'remove') {
    unset($overrides[$username]);
} else {
    if (empty($group)) {
        http_response_code(400);
        echo json_encode(['error' => 'Group is required for set action']);
        exit;
    }
    $overrides[$username] = $group;
}

// Write back
file_put_contents($overridesFile, json_encode($overrides, JSON_PRETTY_PRINT));

echo json_encode([
    'success' => true,
    'username' => $username,
    'group' => $action === 'remove' ? null : $group,
    'action' => $action
]);
