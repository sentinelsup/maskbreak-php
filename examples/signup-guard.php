<?php

declare(strict_types=1);

/**
 * Plain-PHP signup guard — no framework.
 *
 * Demonstrates the three-way routing the API is designed around: block the
 * worst band, step up the middle one, let the rest through. Collapsing
 * 'review' into 'block' is the most common way to lose real customers.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Sentinel\Client;
use Sentinel\SentinelException;

$sentinel = new Client();   // reads SENTINEL_KEY

$result = null;
try {
    $result = $sentinel->evaluate([
        'token'              => $_POST['monocle'] ?? '',
        'fingerprintEventId' => $_POST['sentinel_fp'] ?? '',
        'email'              => $_POST['email'] ?? '',   // transient, never stored
    ]);
} catch (SentinelException $e) {
    // Fail open: an unreachable detection API should not stop signups. The
    // exception is an action that is both irreversible and high-value, where
    // queueing for manual review beats auto-approving or auto-refusing.
    error_log('[sentinel] ' . $e->getMessage() . ' (status: ' . var_export($e->getStatus(), true) . ')');
}

// Missing evidence has several causes, including deliberate omission. This
// example opts to fail open on signup; use explicit safeguards for risky actions.
if ($result === null) {
    create_account($_POST['email']);
    exit;
}

switch ($result->decision) {
    case 'block':
        http_response_code(403);
        // Log the reasons; don't return them. Telling a blocked client which
        // signal fired is free tuning feedback for whoever is probing you.
        error_log('[sentinel] blocked: ' . implode(', ', $result->reasons));
        echo 'Signup unavailable.';
        break;

    case 'review':
        // Burner email, a shared exit node, a device seen under other accounts —
        // suspicious enough to verify, not enough to refuse.
        $user = create_account($_POST['email'], ['requires_verification' => true]);
        send_verification_email($user);
        echo 'Check your inbox to finish signing up.';
        break;

    default:
        create_account($_POST['email']);
        echo 'Welcome.';
}
