<?php
// Local HTTP fixtures only. No credentials or real API calls.
$case = explode('/', trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/'))[0];
header('Content-Type: application/json');
$bodies = [
    'empty' => '', 'html' => '<html>gateway</html>', 'null' => 'null',
    'list' => '[]', 'scalar' => '42', 'missing' => '{}',
    'unknown' => '{"decision":"unexpected"}',
];
if ($case === 'error') {
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
