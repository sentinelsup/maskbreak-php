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

```php
<?php
require 'vendor/autoload.php';

$sentinel = new \Sentinel\Client();   // reads SENTINEL_KEY from the environment

$result = $sentinel->evaluate([
    'token' => $_POST['monocle'],
    'fingerprintEventId' => $_POST['sentinel_fp'] ?? '',
]);

if ($result->isBlocked()) {
    http_response_code(403);
    exit;
}
```

This is a handler fragment. Route `review` to an explicit verification/review
flow; only `allow` is approval. Keep the API key server-only. Missing device
evidence is not a clean browser result, and `raw['degraded']` describes network
degradation only.

Get a key free at [maskbreak.com/signup](https://maskbreak.com/signup) — 1,000
requests/hour, no card. Keys start with `sk_live_`.

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
$result = $sentinel->evaluate([
    'token' => $_POST['monocle'],
    'email' => $_POST['email'],   // transient — never stored or logged
]);

if ($result->isBlocked()) {
    return $this->reject('Signup unavailable.');
}

// A burner domain escalates allow to review on its own. Step up, don't refuse:
// masked-email relays (iCloud Hide My Email, Firefox Relay) look identical.
if ($result->decision === 'review') {
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
    'token'     => $_POST['monocle'],
    'fingerprintEventId' => $_POST['sentinel_fp'] ?? '',
    'accountId' => (string) $user->id,
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
failures) and `getBody()` the decoded error payload.

## Frontend setup

The server call needs a token from the browser collector. One script loads both
detection layers:

```html
<script src="https://maskbreak.com/assets/sentinel.js"></script>
```

Mark the forms you want enriched; unrelated forms are not automatically enrolled:

```html
<form class="monocle-enriched" method="post">
  <!-- your fields -->
</form>
```

The collector injects these hidden inputs into marked forms:

| Field | Layer | Send as |
| --- | --- | --- |
| `monocle` | Network (VPN, proxy, Tor, datacenter) | `token` |
| `sentinel_fp` | Device (antidetect, automation, tampering) | `fingerprintEventId` |

```php
$result = $sentinel->evaluate([
    'token'              => $_POST['monocle'] ?? '',
    'fingerprintEventId' => $_POST['sentinel_fp'] ?? '',
]);
```

The device layer degrades to null rather than failing, so a blocked
fingerprinting request evaluates network-only instead of erroring. For SPAs and
XHR, `await Sentinel.collect()` resolves `{ token, fingerprintEventId }`
directly.

This synchronous client forwards only `token`, `fingerprintEventId`, `accountId`
and `email`. It does not expose a timezone input or every REST operation and
does not provide automatic retries or a circuit breaker. Full additive response
fields remain in `raw`. Invalid JSON, missing/invalid evaluation decisions,
transport failures and non-2xx responses raise `SentinelException`; redirects
are not followed.

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
  `sk_test_…` key (Settings → API Key) that runs the complete live pipeline but
  can store events flagged as test, excludes them from usage, and never fires
  webhooks. Test keys still have rate limits.

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

Free tier: **1,000 requests/hour** per API key. No monthly cap, no credit card.

## Related

- [API reference](https://maskbreak.com/api) — reason codes, response fields, stability policy
- [Node SDK](https://github.com/sentinelsup/maskbreak-node) · [Python SDK](https://pypi.org/project/sentinelsup/)
- [Disposable email detection: flag it, don't block on it](https://maskbreak.com/blog/disposable-email-detection)

## License

MIT
