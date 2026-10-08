# sentinelsup/sdk — Maskbreak PHP SDK

Fraud detection for PHP: evaluate SDK-backed visits for network and browser
risk signals, or look up bare IPs for cloud-range and Tor evidence. VPN/proxy
service names are returned when known. A VPN alone routes to review under the
default policy, not automatic blocking.

Zero dependencies. cURL when the extension is available, a stream context when
it is not, so it installs cleanly on shared hosting.

## Install

```bash
composer require sentinelsup/sdk
```

Requires PHP 7.4 or newer.

## Quick start

Three steps give you the first complete check, one that carries both the
network token and the browser check. The Maskbreak dashboard's setup uses the
same names.

**1. Add the script to the page with your form**, and `class="monocle-enriched"`
to the `<form>` element itself (never to an input):

```html
<script async src="https://maskbreak.com/assets/sentinel.js"></script>

<form class="monocle-enriched" method="post" action="/signup.php">
  <!-- your fields; the script adds monocle, sentinel_fp and sentinel_tz -->
</form>
```

Your site sends a Content-Security-Policy header? A policy that does not list
Maskbreak's hosts blocks the script: helmet's default policy in Express does,
and so does any `default-src 'self'` policy. Add
[the list](https://maskbreak.com/integrate.md#content-security-policy) to it.
The hidden fields fill in a second or two after the page loads.

**2. Send the check from your server.** One field mapping, whichever way the
browser part sends it:

| Form field | `Sentinel.collect()` returns | Send to the API as |
| --- | --- | --- |
| `monocle` (network token) | `token` | `token` |
| `sentinel_fp` (browser check) | `fingerprintEventId` | `fingerprintEventId` |
| `sentinel_tz` (time zone) | `tz` | `tz` (optional; plain HTTP only, see below) |

Start in watch mode: every submission is checked and logged, a submission with
a missing field included (the dashboard then says which half did not arrive),
and nobody is blocked. `evaluate()` will not send a request without the network
token, so the quick start reports those submissions over plain HTTP:

```php
<?php
require 'vendor/autoload.php';

$sentinel = new \Sentinel\Client();   // reads MASKBREAK_API_KEY from the environment

// Start in watch mode: log Maskbreak's answer and let everyone through.
// When Events look right, set MASKBREAK_MODE=enforce and redeploy.
$mode = getenv('MASKBREAK_MODE') ?: 'watch';

// evaluate() refuses to send without the network token. In watch mode a
// submission without it is reported anyway, so the dashboard can say so.
function maskbreak_report_without_token(array $fields): ?array
{
    $context = stream_context_create(['http' => [
        'method' => 'POST',
        'timeout' => 5,
        'ignore_errors' => true,
        'header' => 'Authorization: Bearer ' . getenv('MASKBREAK_API_KEY') . "\r\n"
            . "Content-Type: application/json\r\n",
        'content' => json_encode((object) array_filter($fields)),
    ]]);
    $body = @file_get_contents('https://maskbreak.com/v1/evaluate', false, $context);
    $data = is_string($body) ? json_decode($body, true) : null;
    return is_array($data) ? $data : null;
}

// Form fields -> API names. Sentinel.collect() sends JSON with the API names.
$in = json_decode(file_get_contents('php://input') ?: '', true);
$in = is_array($in) ? $in : $_POST;
$token = $in['token'] ?? $in['monocle'] ?? '';
$eventId = $in['fingerprintEventId'] ?? $in['sentinel_fp'] ?? '';
$tz = $in['tz'] ?? $in['sentinel_tz'] ?? '';

$decision = null;
try {
    if ($token !== '') {
        $decision = $sentinel->evaluate(['token' => $token, 'fingerprintEventId' => $eventId])->decision;
    } elseif ($mode !== 'enforce') {
        $decision = maskbreak_report_without_token(['fingerprintEventId' => $eventId, 'tz' => $tz])['decision'] ?? null;
    }
} catch (\Sentinel\SentinelException $e) {
    error_log('[maskbreak] check unavailable: ' . $e->getMessage());
}
error_log('[maskbreak] ' . $mode . ' ' . ($decision ?? 'no answer'));
if ($mode === 'enforce' && $decision !== 'allow') {
    http_response_code($decision === 'block' ? 403 : 409);
    exit;
}
// Watch mode, or an allow: continue with your existing handler.
```

**3. Submit your form once.** Deploy, open the page and submit the form. The
first check then appears in the dashboard (Integration tab and Events).

This is a handler fragment. Route `review` to an explicit verification/review
flow; only `allow` is approval. Keep the API key server-only. Missing device
evidence is not a clean browser result, and `raw['degraded']` describes network
degradation only. The full enforce policy (review, missing evidence, test and
degraded answers) is in [integrate.md](https://maskbreak.com/integrate.md).

Get a key free at [maskbreak.com/signup](https://maskbreak.com/signup) — the Free
plan includes 10,000 visitor checks a month, no card. Keys start with `sk_live_`.

Since v0.1.3, `new \Sentinel\Client()` without a key reads `MASKBREAK_API_KEY`;
the older `SENTINEL_KEY` and `SENTINEL_API_KEY` names are still read as fallbacks.

## What you get back

`evaluate()` returns an `EvaluateResult`:

```php
$result->decision;            // 'allow' | 'review' | 'block' — route on this
$result->riskScore;           // 0-100
$result->reasons;             // ['vpn_detected', 'disposable_email', ...]
$result->network;             // ['vpn' => true, 'proxy' => false, 'tor' => false, ...]
$result->device;              // populated when fingerprintEventId was sent
$result->country;             // 'DE'
$result->raw;                 // the untouched response body

$result->isBlocked();         // decision === 'block'
$result->isSuspicious();      // decision !== 'allow'
$result->isDisposableEmail(); // burner domain, when an email was supplied
```

The API contract is additive, so `raw` always holds the full payload — new
server-side fields are reachable without upgrading the package.

## Routing on the decision

`block` and `review` are different answers and should go to different places.
Collapsing them into one refusal is the most common integration mistake:

```php
switch ($result->decision) {
    case 'block':
        return $this->refuse();
    case 'review':
        return $this->stepUp();     // OTP, card check, manual queue
    case 'allow':
        return $this->proceed();
    default:
        return $this->holdForReview(); // defensive fallback, not approval
}
```

## Examples

### Guard a signup, with the burner-email signal

```php
// $token and $eventId come from the quick start's field mapping.
try {
    $result = $sentinel->evaluate([
        'token' => $token,
        'fingerprintEventId' => $eventId,
        'email' => $in['email'] ?? '',   // transient — never stored or logged
    ]);
} catch (\Sentinel\SentinelException $e) {
    $result = null;   // no token, or the call failed: see "Failing open"
}

if ($result !== null && $result->isBlocked()) {
    return $this->reject('Signup unavailable.');
}

// A burner domain escalates allow to review on its own. Step up, don't refuse:
// masked-email relays (iCloud Hide My Email, Firefox Relay) look identical.
if ($result !== null && $result->decision === 'review') {
    $this->requireEmailVerification($user);
}
```

### Multi-accounting detection

Pass the account id once the user is known and device-to-account linking turns
on when browser device evidence is also supplied. Account linking is
per-customer and hash-only (`linked_accounts`); device `first_seen`/`times_seen`
history is not customer-scoped.

```php
$result = $sentinel->evaluate([
    'token'              => $token,     // the quick start's field mapping
    'fingerprintEventId' => $eventId,
    'accountId'          => (string) $user->id,
]);
```

### Custom policy with `shouldBlock`

Defaults to `decision === 'block'`. Pass a predicate for stricter routes —
withdrawals and transfers usually want to refuse anything that is not clean:

```php
$refuse = $sentinel->shouldBlock(
    ['token' => $token],
    static fn(\Sentinel\EvaluateResult $r): bool => $r->isSuspicious()
);
```

### Look up an arbitrary IP — no browser token needed

For log enrichment, batch review, and screening server-to-server callers:

```php
$out = $sentinel->lookup('185.220.101.34');

$out['verdict'];      // 'allow' | 'review' | 'block'
$out['risk_score'];   // 0-100
$out['signals'];      // ['vpn' => ..., 'proxied' => ..., 'tor' => ..., 'dch' => ...]
$out['network'];      // ['asn' => ..., 'org' => ..., 'country' => ...]
```

`known === false` means our feeds hold no data for that address. It is **not** a
clean bill of health — treating it as one turns every unlisted IP into a
trusted one.

Production bare-IP lookup checks cloud ranges and Tor exits, not live-visit
VPN/proxy evidence. The legacy `vpn`/`proxied` keys do not prove those checks
ran. Use browser-backed `evaluate()` for VPN/proxy checks. Parse client IPs
through explicitly trusted proxies; never trust arbitrary forwarded headers.

## Failing open

Choose fallback behavior per endpoint. The fragment below explicitly opts to
fail open; it is not a recommendation for withdrawals, transfers, or other
sensitive mutations. On those routes, pause/step up/queue the action instead.
Do not treat a timeout as an allow decision or blindly replay a mutation.

```php
use Sentinel\SentinelException;

try {
    $result = $sentinel->evaluate(['token' => $token]);
} catch (SentinelException $e) {
    error_log('sentinel unavailable: ' . $e->getMessage());
    $result = null;              // fail open; rate limits and review still apply
}

if ($result !== null && $result->isBlocked()) {
    return $this->refuse();
}
```

`SentinelException::getStatus()` returns the HTTP status (null on transport
failures) and `getBody()` the decoded error payload. A `503` whose body has
`"code": "storage_unavailable"` means the key could not be checked at that
moment; it is not an invalid key (that is `401`), so retry later and apply your
outage policy meanwhile.

## Frontend setup

The server call needs the evidence the browser collector adds. One script on
the page with your form loads both detection layers:

```html
<script async src="https://maskbreak.com/assets/sentinel.js"></script>
```

Mark the forms you want enriched, with the class on the `<form>` itself (never
on an input); unrelated forms are not automatically enrolled:

```html
<form class="monocle-enriched" method="post">
  <!-- your fields -->
</form>
```

The collector adds these hidden inputs to marked forms:

| Field | Layer | Send as |
| --- | --- | --- |
| `monocle` | Network (VPN, proxy, Tor, datacenter) | `token` |
| `sentinel_fp` | Device (antidetect, automation, tampering) | `fingerprintEventId` |
| `sentinel_tz` | Browser time zone | `tz` (optional) |

The device layer degrades to null rather than failing, so a blocked
fingerprinting request evaluates network-only instead of erroring. A form your
JavaScript submits (fetch, React, Next.js, Vue) sends `Sentinel.collect()`'s
result with its own data instead; the quick start reads that JSON too. Check
that the script is there, and never hold the form because of it:

```js
const evidence = window.Sentinel ? await window.Sentinel.collect() : {};
await fetch('/signup.php', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  // evidence = { token, fingerprintEventId, tz }, already the API's names
  body: JSON.stringify({ email: form.email.value, ...evidence })
});
```

The integration guide has the same flow as a
[Next.js App Router example](https://maskbreak.com/integrate.md) (client
component and Route Handler), and the
[Content-Security-Policy sources](https://maskbreak.com/integrate.md#content-security-policy)
the script needs.

This synchronous client forwards only `token`, `fingerprintEventId`, `accountId`
and `email`. It does not expose a timezone input or every REST operation and
does not provide automatic retries or a circuit breaker. Full additive response
fields remain in `raw`. An empty or missing `token`, invalid JSON, missing/invalid
evaluation decisions, transport failures and non-2xx responses raise
`SentinelException`; redirects are not followed.

## Testing

Deterministic fixture tokens exercise response handling, not detection quality.
SDK fixture calls use authentication and quota but do not increment usage or
fire webhooks. Console-originated live-key fixtures can be stored as test events.
Responses carry `"test": true`; rules and exception pins can override decisions:

```php
$sentinel->evaluate(['token' => 'test_vpn']);     // → review under default policy
$sentinel->evaluate(['token' => 'test_clean']);   // → allow path
// also: test_proxy, test_datacenter, test_tor
```

- **No account yet?** The public sandbox key `sk_test_sandbox` answers the same
  supported `test_*` tokens only — no signup or stored events. It has a separate
  rate limit, never runs live detection, and is not a production allowance.
- **CI / staging with real traffic:** every account also has a personal
  `sk_test_…` key (Settings → API keys) that runs the complete live pipeline.
  Its events are stored flagged as test, kept out of your stats and never fire
  webhooks; its checks count toward the monthly allowance (the fixed `test_*`
  tokens do not). Test keys still have rate limits.

The package's own suite has no library dependencies. Unit tests stub requests;
transport tests use a loopback fixture server and never call the live API:

```bash
php tests/run.php
php tests/transport.php
php -d disable_functions=curl_init tests/transport.php
composer validate --strict
composer install --no-interaction --no-scripts --no-plugins
composer lint
```

The CI matrix targets PHP 7.4–8.5 without raising the 7.4 minimum. A configured
matrix is not a claim that every interpreter was tested locally; inspect its run.

## Rate limits

Visitor checks (`evaluate()`) are counted per calendar month in UTC, with an hourly cap: **Free — 10,000 a month, up to 1,000 an hour, no credit card**; paid plans from €29 a month ([pricing](https://maskbreak.com/pricing)). IP lookups (`lookup()`) have their own monthly allowance, 10× the plan's checks (100,000 on Free). A used-up month answers `429` with `code: "monthly_quota_exceeded"` and `Retry-After` until the 1st; there are no overage charges.

## Related

- [API reference](https://maskbreak.com/api) — reason codes, response fields, stability policy
- [Node SDK](https://github.com/sentinelsup/maskbreak-node) · [Python SDK](https://pypi.org/project/sentinelsup/)
- [Disposable email detection: flag it, don't block on it](https://maskbreak.com/blog/disposable-email-detection)

## License

MIT
