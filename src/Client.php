<?php

declare(strict_types=1);

namespace Sentinel;

/**
 * Sentinel PHP SDK — thin, dependency-free wrapper around the Sentinel fraud
 * detection API at https://maskbreak.com/v1/evaluate.
 *
 * Usage:
 *
 *     $sentinel = new \Sentinel\Client();   // reads MASKBREAK_API_KEY from the env
 *     try {
 *         $result = $sentinel->evaluate(['token' => $_POST['monocle'] ?? '']);
 *     } catch (\Sentinel\SentinelException $e) {
 *         $result = null;   // no token, or the call failed: your fallback here
 *     }
 *     if ($result !== null && $result->isBlocked()) {
 *         http_response_code(403);
 *         exit;
 *     }
 *
 * Transport is cURL when the extension is present and a stream context
 * otherwise, so the package installs cleanly on shared hosting with no
 * dependencies of its own.
 */
class Client
{
    public const VERSION = '0.3.0';

    private const DEFAULT_ENDPOINT = 'https://maskbreak.com';
    private const DEFAULT_TIMEOUT = 5.0;

    /**
     * The values `event` takes (login protection, since 23 October 2026). The
     * API reads the name case-insensitively and ignores any other value without
     * a word, so a typo such as "signin" would run the check without login
     * protection: evaluate() refuses it instead (0.3.0).
     */
    private const EVENTS = ['login', 'signup', 'password_change', 'verification', 'logout', 'account_change'];

    /**
     * Account events a server reports on its own, often with no page in front
     * of it: the API records them without the visit's network token. A login
     * and a signup are visits and still need the token.
     */
    private const TOKENLESS_EVENTS = ['password_change', 'verification', 'logout', 'account_change'];

    /** Fields with a fixed list of values: the list, and what the API does with any other value. */
    private const CHOICES = [
        'event' => [self::EVENTS, 'the API ignores any other value, and the check would run without login protection'],
        'reason' => [['user', 'forgot', 'forced'], 'the API reads any other value as user'],
        'verificationType' => [['email', 'sms', 'phone_call', 'app', 'push', 'security_key', 'captcha'], 'the API ignores any other value'],
        'verifiedEvent' => [['login', 'signup', 'password_change', 'account_change'], 'the API ignores any other value'],
    ];

    /** The API reads only a real boolean here; anything else silently becomes "not known". */
    private const BOOLEANS = ['loginSucceeded', 'succeeded'];

    /** The API reads these only when they are strings. */
    private const STRINGS = ['tz', 'phone', 'userAgent', 'ip'];

    /** The API drops a longer session ID without a word (the device stands in for the session). */
    private const MAX_SESSION_ID = 256;

    /**
     * Checks that arrive without the browser part (the dashboard's
     * missing_device) are a broken integration that is easy to miss. Never
     * carries the key or anything about the visitor.
     */
    private const MISSING_BROWSER_PART = 'Sentinel: a check was sent without fingerprintEventId, so Maskbreak checks it '
        . 'without the browser part (bots, fake browsers and emulators go unchecked): keep the script on the page '
        . 'with your form and forward its sentinel_fp field (or the fingerprintEventId from Sentinel.collect()) as '
        . 'fingerprintEventId. Shown once per process; new \Sentinel\Client(warnMissingBrowserPart: false) or '
        . '$client->warnMissingBrowserPart(false) turns it off.';

    /** @var bool Whether this process has written the missing-browser-part warning. */
    private static $missingBrowserPartWarned = false;

    /** @var string */
    private $apiKey;

    /** @var string */
    private $endpoint;

    /** @var float Per-request timeout in seconds. */
    private $timeout;

    /** @var bool Let shouldBlock()/isBlocked() pass test, sandbox and sample answers. */
    private $allowTestResults;

    /** @var bool Write the one-time missing-browser-part warning (0.3.0). */
    private $warnMissingBrowserPart;

    /**
     * @param string|null $apiKey  Your API key (starts with sk_live_). Falls back to
     *                             the MASKBREAK_API_KEY env var, then the older
     *                             SENTINEL_KEY, then SENTINEL_API_KEY.
     * @param string      $endpoint Override the API base URL (for tests).
     * @param float       $timeout  Per-request timeout, seconds.
     * @param bool        $allowTestResults Only for your own test runs: since 0.2.0
     *                             a test, sandbox or sample answer counts as blocked
     *                             (the fixed test tokens are public, so a visitor can
     *                             send one); true lets it through.
     * @param bool        $warnMissingBrowserPart False turns off the one-time line in
     *                             PHP's error log for a check sent without
     *                             fingerprintEventId (since 0.3.0). On PHP 7.4, which
     *                             has no named arguments, warnMissingBrowserPart(false)
     *                             does the same.
     *
     * @throws SentinelException when no key can be resolved, or it holds a space or
     *                           a control character (the key is never echoed).
     */
    public function __construct(
        ?string $apiKey = null,
        string $endpoint = self::DEFAULT_ENDPOINT,
        float $timeout = self::DEFAULT_TIMEOUT,
        bool $allowTestResults = false,
        bool $warnMissingBrowserPart = true
    ) {
        if ($apiKey === null || $apiKey === '') {
            // MASKBREAK_API_KEY is the name every doc surface uses. SENTINEL_KEY
            // and SENTINEL_API_KEY are older names, still read so existing
            // installs keep working; the first non-empty one wins.
            $apiKey = '';
            foreach (['MASKBREAK_API_KEY', 'SENTINEL_KEY', 'SENTINEL_API_KEY'] as $name) {
                $fromEnv = getenv($name);
                if ($fromEnv !== false && $fromEnv !== '') {
                    $apiKey = $fromEnv;
                    break;
                }
            }
        }

        // Trimmed: a key read from a file or a secret often ends in a line break.
        $apiKey = trim($apiKey);
        if ($apiKey === '') {
            throw new SentinelException(
                'Sentinel: api key is required. Pass it explicitly or set MASKBREAK_API_KEY '
                . '(the older SENTINEL_KEY still works). '
                . 'Get one free at https://maskbreak.com/signup'
            );
        }
        // A line break inside would start a header of its own in the stream
        // fallback; never echo the value.
        if (preg_match('/[\s\x00-\x1f\x7f]/', $apiKey)) {
            throw new SentinelException(
                'Sentinel: the API key contains a space, a line break or another control character. '
                . 'Copy it again from the dashboard (Settings, API keys).'
            );
        }

        $this->apiKey = $apiKey;
        $this->endpoint = rtrim($endpoint, '/');
        $this->timeout = $timeout;
        $this->allowTestResults = $allowTestResults;
        $this->warnMissingBrowserPart = $warnMissingBrowserPart;
    }

    /**
     * Turn the one-time missing-browser-part warning on or off (since 0.3.0):
     * the constructor's $warnMissingBrowserPart, for code that does not pass
     * every argument before it (PHP 7.4 has no named arguments).
     *
     *     $sentinel = (new \Sentinel\Client())->warnMissingBrowserPart(false);
     */
    public function warnMissingBrowserPart(bool $on): self
    {
        $this->warnMissingBrowserPart = $on;
        return $this;
    }

    /**
     * Evaluate a visitor session for fraud signals.
     *
     * Every key but `token` is optional and sent only when given (not null or
     * ''), under the same name. A value the API would ignore or misread (an
     * unknown `event`, a `loginSucceeded` that is not a bool, ...) throws a
     * SentinelException before anything is sent.
     *
     * @param array<string,mixed> $input {
     *     @var string      $token              Client-side token from the frontend SDK. Required, except
     *                                          for the account events password_change, verification,
     *                                          logout and account_change (0.3.0).
     *     @var string      $fingerprintEventId Optional device event id for device signals. Without it
     *                                          the check has no browser part, and the SDK writes one
     *                                          line to PHP's error log (see warnMissingBrowserPart).
     *     @var string|int  $accountId          Optional account id, from your server-side session — enables
     *                                          multi-accounting detection and, with a live key, the
     *                                          `account` object (account network). Login protection
     *                                          needs it with `event`.
     *     @var string      $email              Optional signup email. Adds `email.disposable`; with email
     *                                          and phone intelligence on, also checked, score, risk and
     *                                          signals. Never stored or logged.
     *     @var string      $tz                 The visitor's IANA time zone (`tz` from Sentinel.collect(),
     *                                          or the form's sentinel_tz field). Adds `timezone` (0.3.0).
     *     @var string      $phone              The visitor's phone number in international format; with
     *                                          email and phone intelligence on, adds `phone` (0.3.0).
     *     @var string      $event              Login protection (0.3.0): login, signup, password_change,
     *                                          verification, logout or account_change.
     *     @var bool        $loginSucceeded     With event login: whether the credential was right.
     *     @var bool        $succeeded          With password_change or verification: whether it
     *                                          succeeded (absent means pending).
     *     @var string|int  $sessionId          With an event: your session ID, at most 256 characters.
     *                                          Only a keyed hash of it leaves Maskbreak.
     *     @var string      $userAgent          With an event: the User-Agent header your server received.
     *     @var string      $ip                 With an event: the visitor's address as your server saw
     *                                          it, used only when the network token gave none.
     *     @var string      $reason             With password_change: user, forgot or forced.
     *     @var string      $verificationType   With verification: email, sms, phone_call, app, push,
     *                                          security_key or captcha.
     *     @var string      $verifiedEvent      With verification: login, signup, password_change or
     *                                          account_change.
     * }
     *
     * @throws SentinelException on a missing token (outside the four account events), a value
     *                           the API would ignore or misread, network failure, timeout, or non-2xx.
     */
    public function evaluate(array $input): EvaluateResult
    {
        // Fixed lists first: the event decides whether the token may be left out.
        $picked = [];
        foreach (self::CHOICES as $name => [$allowed, $otherwise]) {
            if (!self::given($input[$name] ?? null)) {
                continue;
            }
            $value = is_string($input[$name]) ? strtolower(trim($input[$name])) : null;
            if ($value === null || !in_array($value, $allowed, true)) {
                throw new SentinelException(
                    'Sentinel::evaluate: ' . $name . ' must be one of ' . implode(', ', $allowed) . '; ' . $otherwise . '.'
                );
            }
            $picked[$name] = $value;
        }

        $accountEvent = isset($picked['event']) && in_array($picked['event'], self::TOKENLESS_EVENTS, true);
        $token = $input['token'] ?? null;
        if (!self::given($token) && !$accountEvent) {
            throw new SentinelException(
                'Sentinel::evaluate: token (client-side Sentinel token) is required (only the account events '
                . 'password_change, verification, logout and account_change can be sent without it)'
            );
        }
        if (self::given($token) && !is_string($token)) {
            throw new SentinelException('Sentinel::evaluate: token (client-side Sentinel token) must be a string');
        }

        $payload = [];
        if (self::given($token)) {
            $payload['token'] = $token;
        }
        foreach (['fingerprintEventId', 'accountId', 'email'] as $key) {
            if (isset($input[$key]) && $input[$key] !== '') {
                $payload[$key] = $input[$key];
            }
        }
        foreach (self::STRINGS as $key) {
            if (!self::given($input[$key] ?? null)) {
                continue;
            }
            if (!is_string($input[$key])) {
                throw new SentinelException('Sentinel::evaluate: ' . $key . ' must be a string.');
            }
            $payload[$key] = $input[$key];
        }
        if (isset($picked['event'])) {
            $payload['event'] = $picked['event'];
        }
        foreach (self::BOOLEANS as $key) {
            if (!self::given($input[$key] ?? null)) {
                continue;
            }
            if (!is_bool($input[$key])) {
                throw new SentinelException('Sentinel::evaluate: ' . $key . ' must be true or false.');
            }
            $payload[$key] = $input[$key];
        }
        if (self::given($input['sessionId'] ?? null)) {
            $id = $input['sessionId'];
            if (!(is_string($id) || is_int($id)) || self::charCount(trim((string) $id)) > self::MAX_SESSION_ID) {
                throw new SentinelException(
                    'Sentinel::evaluate: sessionId must be a string or an int of at most ' . self::MAX_SESSION_ID
                    . ' characters; for a longer session value, send a shorter ID for the session (a hash of it, for example).'
                );
            }
            $payload['sessionId'] = $id;
        }
        foreach (['reason', 'verificationType', 'verifiedEvent'] as $key) {
            if (isset($picked[$key])) {
                $payload[$key] = $picked[$key];
            }
        }

        // Account events may come from server code with no page in front of
        // them, and the fixed test_* tokens never carry a browser part;
        // anything else without it is a broken integration, said once.
        if ($this->warnMissingBrowserPart && !$accountEvent && !self::given($input['fingerprintEventId'] ?? null)
            && !(is_string($token) && strncmp($token, 'test_', 5) === 0)) {
            $this->warnMissingBrowserPartOnce();
        }

        $data = $this->request('POST', '/v1/evaluate', $payload);
        if (!isset($data['decision']) || !in_array($data['decision'], ['allow', 'review', 'block'], true)) {
            throw new SentinelException('Sentinel: invalid or missing evaluation decision', null, $data);
        }
        return new EvaluateResult($data, $this->allowTestResults);
    }

    /**
     * Look up an arbitrary public IP address — no browser token needed.
     *
     * Useful for log enrichment, batch scoring, and screening server-to-server
     * callers. Shares the hourly quota with evaluate() (one per account for the
     * live keys; the test key has its own) and has its own monthly allowance.
     *
     * Note: `known === false` means our feeds hold no data for the address. It
     * is NOT a clean bill of health.
     *
     * @return array<string,mixed> verdict, risk_score, known, signals, network, latency_ms.
     *
     * @throws SentinelException on a missing ip, network failure, timeout, or non-2xx.
     */
    public function lookup(string $ip): array
    {
        $ip = trim($ip);
        if ($ip === '') {
            throw new SentinelException(
                'Sentinel::lookup: ip (public IPv4 or IPv6 address) is required'
            );
        }

        return $this->request('GET', '/v1/lookup/' . rawurlencode($ip), null);
    }

    /**
     * Whether your integration's checks arrive complete, and what to fix next
     * (GET /v1/setup, since 0.3.0).
     *
     * Submit your form once, then call it: it says whether that check arrived
     * with both parts and, when not, what to change. Works with the live key
     * and the test key. The answer is returned as the API sends it.
     *
     * `status` is what the latest check showed: waiting (no check in the last 7 days, and none complete before),
     * complete (both parts, live key), missing_network (no network token),
     * network_unavailable (a token that could not be read), missing_device (no
     * browser event id), device_unavailable (a browser event that could not be
     * verified), test_mode (a test token, or the test key without both parts),
     * test_complete (the test key with both parts: swap in the live key),
     * ip_restricted, rate_limited or request_failed.
     *
     * @return array{status: string, complete: bool, message: string, next_step: string|null,
     *               last_check_at: string|null, complete_checks: int, last_complete_at: string|null,
     *               website: array{confirmed: bool, origin: string|null},
     *               script_seen: array{origin: string, at: string}|null, site_id: string|null,
     *               key_type: string, docs: string}
     *
     * @throws SentinelException on network failure, timeout, or non-2xx.
     */
    public function setupStatus(): array
    {
        return $this->request('GET', '/v1/setup', null);
    }

    /**
     * Convenience helper: true when the session should be refused.
     *
     * Defaults to the API's own `decision === 'block'`, which honors dashboard
     * rules and allow-pins. Pass a predicate to apply your own policy, e.g.
     * `fn($r) => $r->isSuspicious()` on a withdrawal route.
     *
     * @param array<string,mixed>              $input     Same shape as evaluate().
     * @param callable(EvaluateResult):bool|null $predicate
     *
     * @throws SentinelException
     */
    public function shouldBlock(array $input, ?callable $predicate = null): bool
    {
        $result = $this->evaluate($input);
        // A test, sandbox or sample answer is never a real visitor's verdict.
        if (!$this->allowTestResults && $result->isFixture()) {
            return true;
        }

        return $predicate === null ? $result->isBlocked() : (bool) $predicate($result);
    }

    /**
     * Where the SDK's one warning goes: PHP's error log, through error_log().
     *
     * Not trigger_error(): an E_USER_NOTICE runs through the application's
     * error handler, which Laravel and Symfony (in debug) turn into an
     * exception and WordPress with WP_DEBUG_DISPLAY prints into the page, so a
     * warning could break the very request it is about. error_log() only
     * writes the line to the configured log (stderr from the command line).
     *
     * Protected so tests can capture it.
     */
    protected function warn(string $message): void
    {
        error_log($message);
    }

    /**
     * The missing-browser-part warning, the first time in this process only
     * (PHP-FPM and mod_php start every request afresh, so there it is once per
     * request).
     */
    private function warnMissingBrowserPartOnce(): void
    {
        if (self::$missingBrowserPartWarned) {
            return;
        }
        self::$missingBrowserPartWarned = true;
        $this->warn(self::MISSING_BROWSER_PART);
    }

    /**
     * A key counts as given unless it is missing, null or ''.
     *
     * @param mixed $value
     */
    private static function given($value): bool
    {
        return $value !== null && $value !== '';
    }

    /** Characters (code points) of a UTF-8 string, bytes when it is not valid UTF-8. */
    private static function charCount(string $value): int
    {
        $count = @preg_match_all('/./su', $value);
        return is_int($count) ? $count : strlen($value);
    }

    /**
     * Shared transport: auth header, timeout, JSON handling, error mapping.
     *
     * Protected so tests can stub the network without a live endpoint.
     *
     * @param array<string,mixed>|null $payload Null sends a GET.
     *
     * @return array<string,mixed>
     *
     * @throws SentinelException
     */
    protected function request(string $method, string $path, ?array $payload): array
    {
        $url = $this->endpoint . $path;
        $body = null;

        if ($payload !== null) {
            // A visitor's User-Agent (or a typed email or phone) can hold bytes
            // that are not UTF-8, and plain json_encode() refuses the whole
            // payload then: such a request would answer an exception instead
            // of a check (0.3.0). Those bytes become U+FFFD instead.
            $body = json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE);
            if ($body === false) {
                throw new SentinelException('Sentinel: could not encode request payload as JSON');
            }
        }

        $headers = [
            'Authorization: Bearer ' . $this->apiKey,
            'Accept: application/json',
            'User-Agent: sentinel-php/' . self::VERSION,
        ];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }

        if (function_exists('curl_init')) {
            [$status, $raw] = $this->sendWithCurl($method, $url, $headers, $body);
        } else {
            [$status, $raw] = $this->sendWithStream($method, $url, $headers, $body);
        }

        $isObject = is_object(json_decode($raw));
        $decoded = $isObject ? json_decode($raw, true) : [];

        if ($status < 200 || $status >= 300) {
            $detail = isset($decoded['error']) && is_string($decoded['error'])
                ? ' — ' . $decoded['error']
                : '';
            throw new SentinelException(
                'Sentinel: API returned ' . $status . $detail,
                $status,
                $decoded
            );
        }

        if (!$isObject) {
            throw new SentinelException('Sentinel: expected a valid JSON object', $status);
        }

        return $decoded;
    }

    /**
     * @param list<string> $headers
     *
     * @return array{0:int,1:string}
     *
     * @throws SentinelException
     */
    private function sendWithCurl(string $method, string $url, array $headers, ?string $body): array
    {
        $ch = curl_init();
        if ($ch === false) {
            throw new SentinelException('Sentinel: could not initialise cURL');
        }

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        // Whole-request budget, plus a connect ceiling so a black-holed TCP
        // handshake cannot sit on the full timeout on its own.
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, (int) round($this->timeout * 1000));
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, (int) round($this->timeout * 1000));
        // Never negotiate these down. An API key travels in the header.
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $raw = curl_exec($ch);
        if ($raw === false) {
            $error = curl_error($ch);
            $errno = curl_errno($ch);
            $this->closeCurl($ch);
            if ($errno === CURLE_OPERATION_TIMEOUTED) {
                throw new SentinelException(
                    'Sentinel: request timed out after ' . $this->timeout . 's'
                );
            }
            throw new SentinelException('Sentinel: network error — ' . $error);
        }

        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $this->closeCurl($ch);

        return [$status, (string) $raw];
    }

    /**
     * Release a cURL handle without tripping a deprecation on modern PHP.
     *
     * curl_close() has been a no-op since 8.0 (the handle is freed when the
     * object goes out of scope) and emits a deprecation notice from 8.5. On 7.4
     * the handle is a resource and the call still matters, so it stays there —
     * without this guard the SDK writes a notice to the host's error log on
     * every single request.
     *
     * @param mixed $ch
     */
    private function closeCurl($ch): void
    {
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
    }

    /**
     * cURL-free fallback for hosts that ship without the extension.
     *
     * @param list<string> $headers
     *
     * @return array{0:int,1:string}
     *
     * @throws SentinelException
     */
    private function sendWithStream(string $method, string $url, array $headers, ?string $body): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'content' => $body ?? '',
                'timeout' => $this->timeout,
                'ignore_errors' => true,   // read the body on 4xx/5xx instead of failing
                'follow_location' => 0,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);

        $stream = @fopen($url, 'rb', false, $context);
        if ($stream === false) {
            throw new SentinelException('Sentinel: network error — request to ' . $url . ' failed');
        }

        try {
            $raw = @stream_get_contents($stream);
            $metadata = stream_get_meta_data($stream);
            if (!empty($metadata['timed_out'])) {
                throw new SentinelException('Sentinel: request timed out after ' . $this->timeout . 's');
            }
            if ($raw === false) {
                throw new SentinelException('Sentinel: could not read HTTP response body');
            }
            // Per-stream headers work on PHP 7.4 through 8.5 without the
            // deprecated, scope-sensitive $http_response_header variable.
            $responseHeaders = $metadata['wrapper_data'] ?? null;
        } finally {
            fclose($stream);
        }

        $status = 0;
        if (is_array($responseHeaders)) {
            foreach ($responseHeaders as $line) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string) $line, $m) === 1) {
                    $status = (int) $m[1];   // last wins, so redirects report the final hop
                }
            }
        }
        if ($status === 0) {
            throw new SentinelException('Sentinel: could not read HTTP status from response');
        }

        return [$status, (string) $raw];
    }
}
