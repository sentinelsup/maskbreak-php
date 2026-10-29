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
    /** @var list<string> What warn() would have written to the error log. */
    public $warnings = [];
    /** @var array<string,mixed> */
    private $response;
    /** @var int */
    private $status;

    /**
     * @param array<string,mixed> $response
     */
    public function __construct(array $response, int $status = 200, bool $warnMissingBrowserPart = true)
    {
        parent::__construct('sk_live_stub', 'https://maskbreak.com', 5.0, false, $warnMissingBrowserPart);
        $this->response = $response;
        $this->status = $status;
    }

    protected function warn(string $message): void
    {
        $this->warnings[] = $message;
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
        'account' => ['seen_before' => true, 'device_accounts_24h' => 3],
    ]);

    assertSameValue('review', $result->decision);
    assertSameValue(62, $result->riskScore);
    assertSameValue('DE', $result->country);
    assertSameValue(['vpn_detected', 'disposable_email'], $result->reasons);
    assertSameValue('allow', $result->engineDecision);
    assertSameValue('rules', $result->decisionSource);
    assertSameValue(['seen_before' => true, 'device_accounts_24h' => 3], $result->account);
    assertSameValue(null, (new EvaluateResult(['decision' => 'allow']))->account, 'no account object unless the API sends one');
    assertTrue($result->isDisposableEmail());
});

check('a test, sandbox or sample answer counts as blocked unless the client allows test results', function (): void {
    foreach (['test', 'sample', 'sandbox'] as $marker) {
        $result = new EvaluateResult(['decision' => 'allow', $marker => true]);
        assertSameValue(true, $result->isFixture(), $marker);
        assertSameValue(true, $result->isBlocked(), $marker . ': a public test token never lets a visitor through');
    }
    assertSameValue(false, (new EvaluateResult(['decision' => 'allow', 'test' => true], true))->isBlocked(), 'opted in for its own tests');
    assertSameValue(false, (new EvaluateResult(['decision' => 'allow']))->isFixture());
});

check('the API key is trimmed, and a key with a break or a space inside is refused without echo', function (): void {
    assertSameValue('sk_live_abc', resolvedKey(new Client("  sk_live_abc\n")));
    foreach (["sk_live_a\r\nX-Injected: 1", "sk_live_a b", "sk_live_a\0b"] as $bad) {
        try {
            new Client($bad);
            throw new RuntimeException('expected a refusal');
        } catch (\Sentinel\SentinelException $e) {
            assertTrue(strpos($e->getMessage(), 'sk_live_a') === false, 'the key is not echoed');
        }
    }
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

// ── 0.3.0: login protection, phone and tz; account events; the warning; setupStatus() ──

/** A process that has not written the missing-browser-part warning yet. */
function resetMissingBrowserPartWarning(): void
{
    $property = new \ReflectionProperty(Client::class, 'missingBrowserPartWarned');
    if (PHP_VERSION_ID < 80100) {
        $property->setAccessible(true);   // a no-op from 8.1, deprecated in 8.5
    }
    $property->setValue(null, false);
}

check('evaluate sends each new field under its API name, only when given', function (): void {
    $full = [
        'token' => 'tok', 'fingerprintEventId' => 'evt', 'accountId' => 'u_42', 'email' => 'a@example.com',
        'tz' => 'Europe/Tallinn', 'phone' => '+44 20 7946 0958', 'userAgent' => 'Mozilla/5.0 (X11)',
        'ip' => '81.20.33.4', 'event' => 'login', 'loginSucceeded' => true, 'succeeded' => false,
        'sessionId' => 'sess_1', 'reason' => 'forgot', 'verificationType' => 'sms', 'verifiedEvent' => 'login',
    ];
    $client = new StubClient(['decision' => 'allow'], 200, false);
    $client->evaluate($full);
    assertSameValue($full, $client->lastPayload, 'every field under the API name');

    $client->evaluate(['token' => 'tok', 'fingerprintEventId' => 'evt', 'tz' => null, 'phone' => '', 'event' => '', 'sessionId' => '',
        'loginSucceeded' => '', 'succeeded' => null]);
    assertSameValue(['token' => 'tok', 'fingerprintEventId' => 'evt'], $client->lastPayload, 'null and empty stay out');

    $client->evaluate(['token' => 'tok', 'fingerprintEventId' => 'evt', 'event' => 'login', 'loginSucceeded' => false, 'sessionId' => 7]);
    assertSameValue(['token' => 'tok', 'fingerprintEventId' => 'evt', 'event' => 'login', 'loginSucceeded' => false, 'sessionId' => 7],
        $client->lastPayload, 'false is an answer, and an int session ID is sent');
});

check('the fixed-list fields are read like the API reads them, and sent in its spelling', function (): void {
    $client = new StubClient(['decision' => 'allow'], 200, false);
    $client->evaluate(['token' => 'tok', 'fingerprintEventId' => 'evt', 'event' => ' Password_Change ', 'reason' => 'FORGOT',
        'verificationType' => 'Security_Key', 'verifiedEvent' => 'SignUp']);
    assertSameValue(['token' => 'tok', 'fingerprintEventId' => 'evt', 'event' => 'password_change', 'reason' => 'forgot',
        'verificationType' => 'security_key', 'verifiedEvent' => 'signup'], $client->lastPayload);
});

check('a value the API would ignore or misread is refused before anything is sent', function (): void {
    $cases = [
        [['event' => 'signin'], 'event must be one of login, signup, password_change, verification, logout, account_change; the API ignores any other value'],
        [['event' => 42], 'event must be one of'],
        [['event' => 'login', 'reason' => 'expired'], 'reason must be one of user, forgot, forced; the API reads any other value as user'],
        [['event' => 'verification', 'verificationType' => 'totp'], 'verificationType must be one of email, sms, phone_call, app, push, security_key, captcha'],
        [['event' => 'verification', 'verifiedEvent' => 'checkout'], 'verifiedEvent must be one of login, signup, password_change, account_change'],
        [['event' => 'login', 'loginSucceeded' => 'true'], 'loginSucceeded must be true or false'],
        [['event' => 'password_change', 'succeeded' => 1], 'succeeded must be true or false'],
        [['tz' => 3], 'tz must be a string'],
        [['phone' => 4420794609], 'phone must be a string'],
        [['event' => 'login', 'userAgent' => ['Mozilla']], 'userAgent must be a string'],
        [['event' => 'login', 'ip' => ['81.20.33.4']], 'ip must be a string'],
        [['event' => 'login', 'sessionId' => str_repeat('x', 257)], 'sessionId must be a string or an int of at most 256 characters'],
        [['event' => 'login', 'sessionId' => 1.5], 'sessionId must be'],
        [['event' => 'login', 'sessionId' => true], 'sessionId must be'],
    ];
    foreach ($cases as [$extra, $message]) {
        $client = new StubClient(['decision' => 'allow'], 200, false);
        assertThrows($message, function () use ($client, $extra): void {
            $client->evaluate(['token' => 'tok', 'fingerprintEventId' => 'evt'] + $extra);
        });
        assertSameValue(null, $client->lastMethod, 'nothing sent for ' . json_encode($extra));
    }
    $client = new StubClient(['decision' => 'allow'], 200, false);
    $client->evaluate(['token' => 'tok', 'fingerprintEventId' => 'evt', 'event' => 'login', 'sessionId' => str_repeat('é', 256)]);
    assertSameValue('POST', $client->lastMethod, '256 characters (not bytes) is still fine');
});

check('the four account events go without a token; a login, a signup and a plain check still need one', function (): void {
    foreach (['password_change', 'verification', 'logout', 'account_change'] as $event) {
        $client = new StubClient(['decision' => 'allow'], 200, false);
        $client->evaluate(['event' => $event, 'accountId' => 'u_42']);
        assertSameValue(['accountId' => 'u_42', 'event' => $event], $client->lastPayload, $event . ': sent without token');
        $client->evaluate(['event' => $event, 'accountId' => 'u_42', 'token' => 'tok']);
        assertSameValue(['token' => 'tok', 'accountId' => 'u_42', 'event' => $event], $client->lastPayload, $event . ': with a token');
        assertThrows('token (client-side Sentinel token) must be a string', function () use ($client, $event): void {
            $client->evaluate(['event' => $event, 'accountId' => 'u_42', 'token' => 12345]);
        });
    }
    foreach ([['event' => 'login', 'accountId' => 'u'], ['event' => 'signup', 'accountId' => 'u'], [], ['accountId' => 'u'], ['event' => 'login', 'token' => '']] as $input) {
        $client = new StubClient(['decision' => 'allow'], 200, false);
        assertThrows('token (client-side Sentinel token) is required (only the account events password_change, verification, logout and account_change can be sent without it)',
            function () use ($client, $input): void {
                $client->evaluate($input);
            });
        assertSameValue(null, $client->lastMethod, 'nothing sent for ' . json_encode($input));
    }
});

check('a check without fingerprintEventId warns once per process, without the key, and the option turns it off', function (): void {
    resetMissingBrowserPartWarning();
    $client = new StubClient(['decision' => 'allow']);
    $client->evaluate(['token' => 'eyJ.live.token', 'email' => 'visitor@example.com', 'ip' => '81.20.33.4']);
    $client->evaluate(['token' => 'eyJ.live.token']);
    $other = new StubClient(['decision' => 'allow']);
    $other->evaluate(['token' => 'eyJ.live.token', 'fingerprintEventId' => '']);
    assertSameValue(1, count($client->warnings), 'one line');
    assertSameValue([], $other->warnings, 'once per process, not per client');
    $line = $client->warnings[0];
    assertTrue(strpos($line, 'sent without fingerprintEventId') !== false, $line);
    assertTrue(strpos($line, 'keep the script on the page with your form and forward its sentinel_fp field (or the fingerprintEventId from Sentinel.collect()) as fingerprintEventId') !== false, $line);
    assertTrue(strpos($line, 'new \Sentinel\Client(warnMissingBrowserPart: false) or $client->warnMissingBrowserPart(false) turns it off') !== false, $line);
    foreach (['sk_live_stub', 'eyJ.live.token', 'visitor@example.com', '81.20.33.4'] as $secret) {
        assertTrue(strpos($line, $secret) === false, 'the warning never carries ' . $secret);
    }

    resetMissingBrowserPartWarning();
    $off = new StubClient(['decision' => 'allow'], 200, false);
    $off->evaluate(['token' => 'eyJ.live.token']);
    $fluent = (new StubClient(['decision' => 'allow']))->warnMissingBrowserPart(false);
    $fluent->evaluate(['token' => 'eyJ.live.token']);
    assertSameValue([], array_merge($off->warnings, $fluent->warnings), 'the constructor and warnMissingBrowserPart(false)');

    $quiet = new StubClient(['decision' => 'allow']);
    $quiet->evaluate(['token' => 'eyJ.live.token', 'fingerprintEventId' => 'evt']);
    $quiet->evaluate(['token' => 'test_vpn']);
    foreach (['password_change', 'verification', 'logout', 'account_change'] as $event) {
        $quiet->evaluate(['event' => $event, 'accountId' => 'u']);
    }
    assertThrows('token', function () use ($quiet): void {
        $quiet->evaluate(['event' => 'login']);
    });
    assertSameValue([], $quiet->warnings, 'the browser part, a test token, account events, a refused call');

    $later = new StubClient(['decision' => 'allow']);
    $later->evaluate(['token' => 'eyJ.live.token', 'event' => 'login', 'accountId' => 'u']);
    assertSameValue(1, count($later->warnings), 'turned off elsewhere, still not used up');
});

check('the warning goes to PHP\'s error log, nowhere else', function (): void {
    resetMissingBrowserPartWarning();
    $log = tempnam(sys_get_temp_dir(), 'sntl');
    $previous = ini_set('error_log', $log);
    $client = new class (['decision' => 'allow']) extends Client {
        /** @var array<string,mixed> */
        private $answer;
        /** @param array<string,mixed> $answer */
        public function __construct(array $answer)
        {
            parent::__construct('sk_live_error_log_key');
            $this->answer = $answer;
        }
        protected function request(string $method, string $path, ?array $payload): array
        {
            return $this->answer;
        }
    };
    ob_start();
    $client->evaluate(['token' => 'eyJ.live.token']);
    $printed = ob_get_clean();
    ini_set('error_log', $previous === false ? '' : $previous);
    $written = (string) file_get_contents($log);
    unlink($log);
    assertSameValue('', $printed, 'nothing printed into the page');
    assertSameValue(1, substr_count($written, 'Sentinel: a check was sent without fingerprintEventId'), $written);
    assertTrue(strpos($written, 'sk_live_error_log_key') === false, 'no key in the log');
});

check('setupStatus GETs /v1/setup with no body and returns the answer as is', function (): void {
    $answer = [
        'status' => 'missing_device', 'complete' => false, 'message' => 'A check arrived, but the browser part is missing.',
        'next_step' => 'Send sentinel_fp as fingerprintEventId.', 'last_check_at' => '2026-10-27T10:00:00.000Z',
        'complete_checks' => 0, 'last_complete_at' => null, 'website' => ['confirmed' => false, 'origin' => null],
        'script_seen' => ['origin' => 'https://shop.example', 'at' => '2026-10-27T09:59:00.000Z'],
        'site_id' => 'site_0123456789abcdef', 'key_type' => 'live', 'docs' => 'https://maskbreak.com/integrate.md', 'future_field' => 1,
    ];
    $client = new StubClient($answer);
    assertSameValue($answer, $client->setupStatus());
    assertSameValue('GET', $client->lastMethod);
    assertSameValue('/v1/setup', $client->lastPath);
    assertSameValue(null, $client->lastPayload);
    $refused = new StubClient(['error' => 'Invalid API Key.'], 401);
    assertThrows('API returned 401', function () use ($refused): void {
        $refused->setupStatus();
    });
});

check('the new answer fields land on the result', function (): void {
    $result = new EvaluateResult([
        'decision' => 'review', 'reasons' => ['account_takeover_risk', 'phone_high_risk'], 'degraded' => true,
        'account_takeover' => ['checked' => true, 'score' => 91, 'risk' => 'high', 'signals' => ['new_location']],
        'email' => ['disposable' => false, 'checked' => false, 'why' => 'quota'],
        'phone' => ['checked' => true, 'score' => 89, 'risk' => 'high', 'signals' => ['invalid']],
        'timezone' => ['reported' => 'Europe/Tallinn', 'country' => 'EE', 'matches_ip' => true, 'checked' => true],
        'device_evidence' => 'not_sent', 'evidence' => ['network_age_s' => 3], 'rule_matched' => ['vpn'], 'evaluated_in_ms' => 28,
    ]);
    assertSameValue(['checked' => true, 'score' => 91, 'risk' => 'high', 'signals' => ['new_location']], $result->accountTakeover);
    assertSameValue(['disposable' => false, 'checked' => false, 'why' => 'quota'], $result->email);
    assertSameValue(89, $result->phone['score']);
    assertSameValue('EE', $result->timezone['country']);
    assertSameValue(true, $result->degraded);
    assertSameValue('not_sent', $result->deviceEvidence);
    assertSameValue(['network_age_s' => 3], $result->evidence);
    assertSameValue(['vpn'], $result->ruleMatched);
    assertSameValue(null, $result->exceptionMatched);
    assertSameValue(28, $result->evaluatedInMs);
    assertSameValue(null, $result->accountEvent);
    $logout = new EvaluateResult(['decision' => 'allow', 'account_event' => ['event' => 'logout', 'recorded' => true]]);
    assertSameValue(['event' => 'logout', 'recorded' => true], $logout->accountEvent);
    assertSameValue([null, null, null, false, false, false], [$logout->accountTakeover, $logout->phone, $logout->timezone,
        $logout->degraded, $logout->sandbox, $logout->sample]);
    $sandbox = new EvaluateResult(['decision' => 'allow', 'sandbox' => true]);
    assertSameValue(true, $sandbox->sandbox);
    assertSameValue(true, $sandbox->isBlocked(), 'a sandbox answer still counts as blocked');
});

check('the client says 0.3.1', function (): void {
    assertSameValue('0.3.1', Client::VERSION);
});

echo "\n{$passed} passed, {$failed} failed\n";
exit($failed === 0 ? 0 : 1);
