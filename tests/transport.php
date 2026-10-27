<?php
declare(strict_types=1);

// Exercise the actual transport/parser against a loopback-only PHP server.
// Run `php tests/transport.php` and
// `php -d disable_functions=curl_init tests/transport.php` for cURL
// (when installed) and the stream fallback respectively.
require __DIR__ . '/../src/SentinelException.php';
require __DIR__ . '/../src/EvaluateResult.php';
require __DIR__ . '/../src/Client.php';

$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
if ($socket === false) {
    throw new RuntimeException($error);
}
$address = stream_socket_get_name($socket, false);
fclose($socket);
$process = proc_open([PHP_BINARY, '-S', $address, __DIR__ . '/fixture-router.php'],
    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
if (!is_resource($process)) {
    throw new RuntimeException('Could not start loopback fixture server');
}

try {
    $ready = false;
    for ($i = 0; $i < 100; $i++) {
        $probe = @stream_socket_client('tcp://' . $address, $errno, $error, 0.1);
        if ($probe !== false) {
            fclose($probe);
            $ready = true;
            break;
        }
        usleep(10000);
    }
    if (!$ready) {
        throw new RuntimeException('Loopback fixture server did not start');
    }
    $client = static function (string $case) use ($address): Sentinel\Client {
        // The missing-browser-part warning is tests/run.php's subject, not this file's.
        return new Sentinel\Client('sk_test_fixture', 'http://' . $address . '/' . $case, 2.0, false, false);
    };
    $result = $client('valid')->evaluate(['token' => 'fixture']);
    if ($result->decision !== 'review' || $result->isBlocked() || !$result->raw['future_field']) {
        throw new RuntimeException('Valid/additive response mapping regressed');
    }
    $passed = 1;
    foreach (['empty', 'html', 'null', 'list', 'scalar', 'missing', 'unknown', 'error', 'redirect'] as $case) {
        try {
            $client($case)->evaluate(['token' => 'fixture']);
            throw new RuntimeException($case . ': expected SentinelException, got a successful result');
        } catch (Sentinel\SentinelException $e) {
            if ($case === 'error' && ($e->getStatus() !== 429 || $e->getBody() !== ['error' => 'Try later'])) {
                throw new RuntimeException('HTTP error status/body lost');
            }
            if ($case === 'redirect' && $e->getStatus() !== 302) {
                throw new RuntimeException('Redirect must not be followed');
            }
            $passed++;
        }
    }
    // A User-Agent with bytes that are not UTF-8 (bots send them) still gets a check.
    $echo = $client('echo')->evaluate(['token' => 'fixture', 'fingerprintEventId' => 'evt', 'event' => 'login',
        'accountId' => 'u', 'loginSucceeded' => false, 'userAgent' => "Bot\xff\xfe/1.0"]);
    $received = $echo->raw['received'] ?? null;
    if (!is_array($received) || $received['userAgent'] !== "Bot\u{FFFD}\u{FFFD}/1.0" || $received['loginSucceeded'] !== false
        || $received['event'] !== 'login') {
        throw new RuntimeException('the payload must survive bytes that are not UTF-8: ' . json_encode($received));
    }
    $passed++;
    $setup = $client('setup')->setupStatus();
    if ($setup['status'] !== 'waiting' || $setup['method'] !== 'GET' || $setup['path'] !== '/setup/v1/setup'
        || $setup['auth'] !== 'Bearer sk_test_fixture' || $setup['body'] !== '') {
        throw new RuntimeException('setupStatus must GET /v1/setup with the key and no body: ' . json_encode($setup));
    }
    $passed++;
    echo $passed . ' transport checks passed (' . (function_exists('curl_init') ? 'cURL' : 'stream') . ")\n";
} finally {
    proc_terminate($process);
    foreach ($pipes as $pipe) {
        fclose($pipe);
    }
    proc_close($process);
}
