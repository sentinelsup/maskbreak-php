<?php

declare(strict_types=1);

namespace Sentinel;

/**
 * Sentinel PHP SDK — thin, dependency-free wrapper around the Sentinel fraud
 * detection API at https://maskbreak.com/v1/evaluate.
 *
 * Usage:
 *
 *     $sentinel = new \Sentinel\Client();   // reads SENTINEL_KEY from the env
 *     $result = $sentinel->evaluate(['token' => $_POST['monocle']]);
 *     if ($result->isBlocked()) {
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
    public const VERSION = '0.1.2';

    private const DEFAULT_ENDPOINT = 'https://maskbreak.com';
    private const DEFAULT_TIMEOUT = 5.0;

    /** @var string */
    private $apiKey;

    /** @var string */
    private $endpoint;

    /** @var float Per-request timeout in seconds. */
    private $timeout;

    /**
     * @param string|null $apiKey  Your API key (starts with sk_live_). Falls back to
     *                             the SENTINEL_KEY env var, then SENTINEL_API_KEY.
     * @param string      $endpoint Override the API base URL (for tests).
     * @param float       $timeout  Per-request timeout, seconds.
     *
     * @throws SentinelException when no key can be resolved.
     */
    public function __construct(
        ?string $apiKey = null,
        string $endpoint = self::DEFAULT_ENDPOINT,
        float $timeout = self::DEFAULT_TIMEOUT
    ) {
        if ($apiKey === null || $apiKey === '') {
            // SENTINEL_KEY is the name every doc surface uses; SENTINEL_API_KEY
            // is kept for installs that already adopted it.
            $fromEnv = getenv('SENTINEL_KEY');
            if ($fromEnv === false || $fromEnv === '') {
                $fromEnv = getenv('SENTINEL_API_KEY');
            }
            $apiKey = ($fromEnv === false) ? '' : $fromEnv;
        }

        if ($apiKey === '') {
            throw new SentinelException(
                'Sentinel: api key is required. Pass it explicitly or set SENTINEL_KEY. '
                . 'Get one free at https://maskbreak.com/signup'
            );
        }

        $this->apiKey = $apiKey;
        $this->endpoint = rtrim($endpoint, '/');
        $this->timeout = $timeout;
    }

    /**
     * Evaluate a visitor session for fraud signals.
     *
     * @param array<string,mixed> $input {
     *     @var string $token               Required. Client-side token from the frontend SDK.
     *     @var string $fingerprintEventId  Optional Fingerprint event id for device signals.
     *     @var string $accountId           Optional account id — enables multi-accounting detection.
     *     @var string $email               Optional signup email. Adds `email.disposable`;
     *                                      checked transiently, never stored or logged.
     * }
     *
     * @throws SentinelException on a missing token, network failure, timeout, or non-2xx.
     */
    public function evaluate(array $input): EvaluateResult
    {
        $token = isset($input['token']) ? $input['token'] : null;
        if (!is_string($token) || $token === '') {
            throw new SentinelException(
                'Sentinel::evaluate: token (client-side Sentinel token) is required'
            );
        }

        $payload = ['token' => $token];
        foreach (['fingerprintEventId', 'accountId', 'email'] as $key) {
            if (isset($input[$key]) && $input[$key] !== '') {
                $payload[$key] = $input[$key];
            }
        }

        $data = $this->request('POST', '/v1/evaluate', $payload);
        if (!isset($data['decision']) || !in_array($data['decision'], ['allow', 'review', 'block'], true)) {
            throw new SentinelException('Sentinel: invalid or missing evaluation decision', null, $data);
        }
        return new EvaluateResult($data);
    }

    /**
     * Look up an arbitrary public IP address — no browser token needed.
     *
     * Useful for log enrichment, batch scoring, and screening server-to-server
     * callers. Shares the per-key hourly quota with evaluate().
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

        return $predicate === null ? $result->isBlocked() : (bool) $predicate($result);
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
            $body = json_encode($payload);
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

        $raw = @file_get_contents($url, false, $context);
        if ($raw === false) {
            throw new SentinelException('Sentinel: network error — request to ' . $url . ' failed');
        }

        if (function_exists('http_get_last_response_headers')) {
            // PHP 8.5+.
            $responseHeaders = http_get_last_response_headers();
        } else {
            // PHP < 8.5: the stream wrapper populates $http_response_header in
            // this function's local scope. Reached indirectly on purpose —
            // naming that variable directly emits a compile-time deprecation on
            // 8.5, which fires even inside a branch that never runs there.
            $legacy = 'http_response_header';
            $responseHeaders = isset($$legacy) ? $$legacy : null;
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
