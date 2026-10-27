<?php
// Local HTTP fixtures only. No credentials or real API calls.
$case = explode('/', trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/'))[0];
header('Content-Type: application/json');
$bodies = [
    'empty' => '', 'html' => '<html>gateway</html>', 'null' => 'null',
    'list' => '[]', 'scalar' => '42', 'missing' => '{}',
    'unknown' => '{"decision":"unexpected"}',
];
if ($case === 'setup') {
    // What the SDK sent, so the test can check the method, path and key header.
    echo json_encode(['status' => 'waiting', 'complete' => false, 'method' => $_SERVER['REQUEST_METHOD'],
        'path' => parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), 'auth' => $_SERVER['HTTP_AUTHORIZATION'] ?? null,
        'body' => file_get_contents('php://input')]);
} elseif ($case === 'echo') {
    // The request body as received, beside a decision so evaluate() accepts the answer.
    echo json_encode(['decision' => 'allow', 'received' => json_decode((string) file_get_contents('php://input'), true)]);
} elseif ($case === 'error') {
    http_response_code(429);
    echo '{"error":"Try later"}';
} elseif ($case === 'redirect') {
    header('Location: /valid/v1/evaluate', true, 302);
    echo '{}';
} elseif (array_key_exists($case, $bodies)) {
    echo $bodies[$case];
} else {
    echo json_encode(['decision' => 'review', 'future_field' => true]);
}
