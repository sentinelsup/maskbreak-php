<?php

declare(strict_types=1);

/**
 * Dependency-free test runner — `php tests/run.php`.
 *
 * Deliberately no PHPUnit: the SDK itself has no dependencies, and the suite
 * has to run on any box with a PHP binary (including a bare CI container).
 * Network is stubbed by overriding the protected transport, so nothing here
 * touches the live API.
 */

require __DIR__ . '/../src/SentinelException.php';
require __DIR__ . '/../src/EvaluateResult.php';
require __DIR__ . '/../src/Client.php';

use Sentinel\Client;
use Sentinel\EvaluateResult;
use Sentinel\SentinelException;

$passed = 0;
$failed = 0;

function check(string $name, callable $fn): void
{
    global $passed, $failed;
    try {
        $fn();
        $passed++;
        echo "ok   - {$name}\n";
    } catch (\Throwable $e) {
        $failed++;
        echo "FAIL - {$name}\n       {$e->getMessage()}\n";
    }
}

function assertTrue(bool $cond, string $msg = 'expected true'): void
{
    if (!$cond) {
        throw new \RuntimeException($msg);
    }
}

/**
 * @param mixed $expected
 * @param mixed $actual
 */
function assertSameValue($expected, $actual, string $msg = ''): void
{
    if ($expected !== $actual) {
        throw new \RuntimeException(
            ($msg !== '' ? $msg . ': ' : '')
            . 'expected ' . var_export($expected, true)
            . ', got ' . var_export($actual, true)
        );
    }
}

function assertThrows(string $needle, callable $fn): void
{
    try {
        $fn();
    } catch (SentinelException $e) {
        if (strpos($e->getMessage(), $needle) === false) {
            throw new \RuntimeException("expected message containing '{$needle}', got '{$e->getMessage()}'");
        }
        return;
    }
    throw new \RuntimeException("expected SentinelException containing '{$needle}', nothing thrown");
}

/** Records what the SDK would have sent, and replays a canned response. */
final class StubClient extends Client
{
    /** @var array<string,mixed>|null */
    public $lastPayload;
    /** @var string|null */
    public $lastMethod;
    /** @var string|null */
    public $lastPath;
    /** @var array<string,mixed> */
    private $response;
    /** @var int */
    private $status;

    /**
     * @param array<string,mixed> $response
     */
    public function __construct(array $response, int $status = 200)
    {
        parent::__construct('sk_live_stub');
        $this->response = $response;
        $this->status = $status;
    }

    protected function request(string $method, string $path, ?array $payload): array
    {
        $this->lastMethod = $method;
        $this->lastPath = $path;
        $this->lastPayload = $payload;

        if ($this->status < 200 || $this->status >= 300) {
            $detail = isset($this->response['error']) ? ' — ' . $this->response['error'] : '';
            throw new SentinelException(
                'Sentinel: API returned ' . $this->status . $detail,
                $this->status,
                $this->response
            );
        }

        return $this->response;
    }
}

// ── Construction ────────────────────────────────────────────────────────────

/** Clear every key variable the constructor reads. */
function clearKeyEnv(): void
{
    putenv('MASKBREAK_API_KEY');
    putenv('SENTINEL_KEY');
    putenv('SENTINEL_API_KEY');
}

/** The key a Client resolved, read from its private property. */
function resolvedKey(Client $client): string
{
    $property = new \ReflectionProperty(Client::class, 'apiKey');
    if (PHP_VERSION_ID < 80100) {
        $property->setAccessible(true);   // a no-op from 8.1, deprecated in 8.5
    }
    return $property->getValue($client);
}

check('constructor rejects an empty key', function (): void {
    clearKeyEnv();
    assertThrows('api key is required', function (): void {
        new Client('');
    });
    assertThrows('set MASKBREAK_API_KEY', function (): void {
        new Client();
    });
});

check('constructor reads MASKBREAK_API_KEY from the environment', function (): void {
    clearKeyEnv();
    putenv('MASKBREAK_API_KEY=sk_live_from_env');
    assertSameValue('sk_live_from_env', resolvedKey(new Client()));
    clearKeyEnv();
});

check('constructor still reads the older SENTINEL_KEY', function (): void {
    clearKeyEnv();
    putenv('SENTINEL_KEY=sk_live_old');
    assertSameValue('sk_live_old', resolvedKey(new Client()));
    clearKeyEnv();
});

check('constructor falls back to SENTINEL_API_KEY', function (): void {
    clearKeyEnv();
    putenv('SENTINEL_API_KEY=sk_live_legacy');
    assertSameValue('sk_live_legacy', resolvedKey(new Client()));
    clearKeyEnv();
});

check('MASKBREAK_API_KEY wins over the older names; an explicit key wins over all', function (): void {
    clearKeyEnv();
    putenv('MASKBREAK_API_KEY=sk_live_new');
    putenv('SENTINEL_KEY=sk_live_old');
    putenv('SENTINEL_API_KEY=sk_live_legacy');
    assertSameValue('sk_live_new', resolvedKey(new Client()));
    assertSameValue('sk_live_explicit', resolvedKey(new Client('sk_live_explicit')));
    clearKeyEnv();
});

// ── evaluate() ──────────────────────────────────────────────────────────────

check('evaluate rejects a missing token', function (): void {
    $client = new StubClient(['decision' => 'allow']);
    assertThrows('token (client-side Sentinel token) is required', function () use ($client): void {
        $client->evaluate([]);
    });
});

check('evaluate rejects an empty token', function (): void {
    $client = new StubClient(['decision' => 'allow']);
    assertThrows('token (client-side Sentinel token) is required', function () use ($client): void {
        $client->evaluate(['token' => '']);
    });
});

check('evaluate POSTs to /v1/evaluate with only the supplied fields', function (): void {
    $client = new StubClient(['decision' => 'allow']);
    $client->evaluate(['token' => 'tok_1', 'accountId' => 'u_42', 'email' => '']);

    assertSameValue('POST', $client->lastMethod);
    assertSameValue('/v1/evaluate', $client->lastPath);
    assertSameValue(['token' => 'tok_1', 'accountId' => 'u_42'], $client->lastPayload,
        'empty optional fields must be omitted, not sent as empty strings');
});

check('evaluate forwards fingerprintEventId and email when present', function (): void {
    $client = new StubClient(['decision' => 'allow']);
    $client->evaluate([
        'token' => 'tok_1',
        'fingerprintEventId' => 'evt_9',
        'email' => 'a@b.com',
    ]);
    assertSameValue(
        ['token' => 'tok_1', 'fingerprintEventId' => 'evt_9', 'email' => 'a@b.com'],
        $client->lastPayload
    );
});

// ── EvaluateResult ──────────────────────────────────────────────────────────

check('result maps the documented fields', function (): void {
    $result = new EvaluateResult([
        'decision' => 'review',
        'risk_score' => 62,
        'ip' => '203.0.113.9',
        'country' => 'DE',
        'network' => ['vpn' => true],
        'reasons' => ['vpn_detected', 'disposable_email'],
        'email' => ['disposable' => true],
        'engine_decision' => 'allow',
        'decision_source' => 'rules',
    ]);

    assertSameValue('review', $result->decision);
    assertSameValue(62, $result->riskScore);
    assertSameValue('DE', $result->country);
    assertSameValue(['vpn_detected', 'disposable_email'], $result->reasons);
    assertSameValue('allow', $result->engineDecision);
    assertSameValue('rules', $result->decisionSource);
    assertTrue($result->isDisposableEmail());
});

check('isBlocked is true only for block', function (): void {
    assertSameValue(false, (new EvaluateResult(['decision' => 'allow']))->isBlocked());
    assertSameValue(false, (new EvaluateResult(['decision' => 'review']))->isBlocked());
    assertSameValue(true, (new EvaluateResult(['decision' => 'block']))->isBlocked());
});

check('isSuspicious is true for anything that is not allow', function (): void {
    assertSameValue(false, (new EvaluateResult(['decision' => 'allow']))->isSuspicious());
    assertSameValue(true, (new EvaluateResult(['decision' => 'review']))->isSuspicious());
    assertSameValue(true, (new EvaluateResult(['decision' => 'block']))->isSuspicious());
});

check('a missing decision is neither blocked nor suspicious', function (): void {
    $result = new EvaluateResult([]);
    assertSameValue(false, $result->isBlocked());
    assertSameValue(false, $result->isSuspicious());
    assertSameValue(false, $result->isDisposableEmail());
});

check('raw keeps unknown fields so additive API changes need no upgrade', function (): void {
    $result = new EvaluateResult(['decision' => 'allow', 'future_field' => 'kept']);
    assertSameValue('kept', $result->raw['future_field']);
});

// ── shouldBlock() ───────────────────────────────────────────────────────────

check('shouldBlock defaults to decision === block', function (): void {
    $blocked = new StubClient(['decision' => 'block']);
    assertSameValue(true, $blocked->shouldBlock(['token' => 't']));

    $review = new StubClient(['decision' => 'review']);
    assertSameValue(false, $review->shouldBlock(['token' => 't']),
        'review must not be treated as block by default');
});

check('shouldBlock honours a custom predicate', function (): void {
    $review = new StubClient(['decision' => 'review']);
    $strict = $review->shouldBlock(['token' => 't'], static function (EvaluateResult $r): bool {
        return $r->isSuspicious();
    });
    assertSameValue(true, $strict);
});

// ── lookup() ────────────────────────────────────────────────────────────────

check('lookup rejects an empty ip', function (): void {
    $client = new StubClient([]);
    assertThrows('ip (public IPv4 or IPv6 address) is required', function () use ($client): void {
        $client->lookup('   ');
    });
});

check('lookup GETs the url-encoded address', function (): void {
    $client = new StubClient(['verdict' => 'block', 'known' => true]);
    $out = $client->lookup(' 2001:db8::1 ');

    assertSameValue('GET', $client->lastMethod);
    assertSameValue('/v1/lookup/2001%3Adb8%3A%3A1', $client->lastPath,
        'the address must be trimmed and url-encoded');
    assertSameValue(null, $client->lastPayload, 'lookup must not send a body');
    assertSameValue('block', $out['verdict']);
});

// ── Error mapping ───────────────────────────────────────────────────────────

check('non-2xx raises SentinelException carrying status and body', function (): void {
    $client = new StubClient(['error' => 'Invalid Key.'], 401);
    try {
        $client->evaluate(['token' => 't']);
    } catch (SentinelException $e) {
        assertSameValue(401, $e->getStatus());
        assertSameValue('Invalid Key.', $e->getBody()['error']);
        assertTrue(strpos($e->getMessage(), 'API returned 401') !== false, $e->getMessage());
        return;
    }
    throw new \RuntimeException('expected SentinelException');
});

echo "\n{$passed} passed, {$failed} failed\n";
exit($failed === 0 ? 0 : 1);
