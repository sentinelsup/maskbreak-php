# sentinelsup/sdk — Sentinel PHP SDK

Real-time fraud detection for PHP: VPN, residential proxy, Tor, datacenter,
antidetect browser and automation signals in a single call, typically under
40 ms server-side.

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
]);

if ($result->isBlocked()) {
    http_response_code(403);
    exit;
}
```

Get a key free at [sntlhq.com/signup](https://sntlhq.com/signup) — 1,000
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
    default:
        return $this->proceed();
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
on. Linking is per-merchant and hash-only; devices are never linked across
customers.

```php
$result = $sentinel->evaluate([
    'token'     => $_POST['monocle'],
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

## Failing open

A detection outage should not become a checkout outage. Catch
`SentinelException` and let the request through on anything that is not both
irreversible and high-value:

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
<script src="https://sntlhq.com/assets/sentinel.js"></script>
```

It auto-injects two hidden inputs into your forms:

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

## Testing

Deterministic test tokens exercise every decision path — authenticated and
rate-limited like real calls, but never billed, stored, or webhooked
(responses carry `"test": true`):

```php
$sentinel->evaluate(['token' => 'test_vpn']);     // → review/block path
$sentinel->evaluate(['token' => 'test_clean']);   // → allow path
// also: test_proxy, test_datacenter, test_tor
```

- **No account yet?** The public sandbox key `sk_test_sandbox` answers the same
  `test_*` tokens with the same shapes — no signup, nothing stored.
- **CI / staging with real traffic:** every account also has a personal
  `sk_test_…` key (Settings → API Key) that runs the complete live pipeline but
  flags events as test, excludes them from usage, and never fires webhooks.

The package's own suite has no dependencies and stubs the network:

```bash
php tests/run.php
```

## Rate limits

Free tier: **1,000 requests/hour** per API key. No monthly cap, no credit card.
Upgrade at [sntlhq.com](https://sntlhq.com) when you need more.

## Related

- [API reference](https://sntlhq.com/api) — reason codes, response fields, stability policy
- [Node SDK](https://github.com/sentinelsup/sentinel-node) · [Python SDK](https://pypi.org/project/sentinelsup/)
- [Disposable email detection: flag it, don't block on it](https://sntlhq.com/blog/disposable-email-detection)

## License

MIT
