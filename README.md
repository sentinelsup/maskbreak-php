# Maskbreak PHP SDK

Check a form submission or a WooCommerce checkout from PHP. The client uses cURL when available and supports PHP streams on shared hosting.

**PHP 7.4+ · Composer** · [Packagist package](https://packagist.org/packages/sentinelsup/sdk) · [API reference](https://maskbreak.com/api)

## Install

```sh
composer require sentinelsup/sdk
```

[First visitor check](#quick-start) · [WooCommerce checkout](examples/woocommerce-checkout.php) · [Test your integration](#testing) · [Integration guide](https://maskbreak.com/integrate.md)

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
| `sentinel_tz` (time zone) | `tz` | `tz` (optional; `evaluate()` sends it since 0.3.0) |

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
        $result = $sentinel->evaluate(['token' => $token, 'fingerprintEventId' => $eventId, 'tz' => $tz]);
        // A test or sample answer is never a real visitor's verdict: anyone can send a test token.
        // A degraded answer is one the network check could not run for: no verdict either.
        $decision = ($result->isFixture() || $result->degraded) ? null : $result->decision;
    } elseif ($mode !== 'enforce') {
        $decision = maskbreak_report_without_token(['fingerprintEventId' => $eventId, 'tz' => $tz])['decision'] ?? null;
    }
} catch (\Sentinel\SentinelException $e) {
    error_log('[maskbreak] check unavailable: ' . $e->getMessage());
    if ($e->getStatus() === 429 && ($e->getBody()['code'] ?? null) === 'monthly_quota_exceeded') {
        $verify = array_map('trim', explode(',', (string) getenv('MASKBREAK_QUOTA_VERIFY_ACTIONS')));
        $decision = in_array('signup', $verify, true) ? 'review' : 'unchecked';
    }
}
error_log('[maskbreak] ' . $mode . ' ' . ($decision ?? 'no answer'));
if ($mode === 'enforce' && $decision !== 'allow' && $decision !== 'unchecked') {
    http_response_code($decision === 'block' ? 403 : 409);
    exit;
}
// Watch mode, or an allow: continue with your existing handler.
```

**3. Submit your form once.** Run your app where you can open the page, on
your computer or on your site, and submit the form once. The first check then
appears in the dashboard (Integration tab and Events), and
[`$sentinel->setupStatus()`](#check-your-setup) says whether it arrived
complete and what to fix.

This is a handler fragment. Route `review` to an explicit verification/review
flow; only `allow` is approval. Keep the API key server-only. Missing device
evidence is not a clean browser result, and `raw['degraded']` describes network
degradation only. The full enforce policy (review, missing evidence, test and
degraded answers) is in [integrate.md](https://maskbreak.com/integrate.md).

Get a key free at [maskbreak.com/signup](https://maskbreak.com/signup) — the Free
plan includes 10,000 visitor checks a month, no card. Keys start with `sk_live_`.

Since v0.1.3, `new \Sentinel\Client()` without a key reads `MASKBREAK_API_KEY`;
the older `SENTINEL_KEY` and `SENTINEL_API_KEY` names are still read as fallbacks.

## What's new

### 0.3.2

- A `token` that is only whitespace (a space, a tab, a line break, U+00A0,
  U+FEFF) counts as missing: `evaluate()` and `shouldBlock()` throw a
  `SentinelException`, as for no token, and nothing is sent. The API reads such
  a token as no token and answers a degraded allow, so a visitor who typed a
  space into the token field turned the refusal of a missing token into an
  allow. A real token is sent unchanged.
- The quick start and the login example hold a degraded answer
  (`$result->degraded`) in enforce mode, as
  [integrate.md](https://maskbreak.com/integrate.md) does: it had no network
  check.
- `$result->isSuspicious()` is `true` for a test, sandbox or sample answer, as
  `isBlocked()` and `shouldBlock()` have been since 0.2.0. A visitor could type
  a public test token such as `test_clean` into your form field and get an
  allow, and `isSuspicious()`, called on the result of `evaluate()`, read that
  answer as clean. A client made with `$allowTestResults = true` lets the
  decision decide, for your own test runs.

### 0.3.0 (2026-10-27)

- Added time zone and contact fields, plus sign-in outcomes for account linking.
- A value the API would ignore or misread (an `event` such as `'signin'`, a
  `loginSucceeded` that is not `true` or `false`) throws a
  `SentinelException` before anything is sent, instead of a check that quietly
  runs without it.
- A check sent without `fingerprintEventId` writes one line to PHP's error
  log: such checks have no browser part.
  `new \Sentinel\Client(warnMissingBrowserPart: false)` or
  `$sentinel->warnMissingBrowserPart(false)` turns it off.
- New `$sentinel->setupStatus()` (`GET /v1/setup`) says whether your checks
  arrive complete and what to fix.
- `EvaluateResult` gains `phone`,
  `timezone`, `degraded`, `sandbox`, `sample`, `deviceEvidence`, `evidence`,
  `ruleMatched`, `exceptionMatched` and `evaluatedInMs`.

## What you get back

`evaluate()` returns an `EvaluateResult`:

```php
$result->decision;            // 'allow' | 'review' | 'block' — route on this
$result->riskScore;           // 0-100
$result->reasons;             // ['vpn_detected', 'disposable_email', ...]
$result->network;             // ['vpn' => true, 'proxy' => false, 'tor' => false, ...]
$result->device;              // populated when fingerprintEventId was sent
$result->country;             // 'DE'
$result->account;             // the account network (since 0.2.1), when accountId was sent with a live key
$result->raw;                 // the untouched response body

// Since 0.3.0:
$result->phone;               // phone sent: ['checked' => true, 'score' => 12, 'risk' => 'low', ...]
$result->timezone;            // tz sent: ['reported' => 'Europe/Tallinn', 'country' => 'EE', 'matches_ip' => true, 'checked' => true]
$result->degraded;            // true when the network part was unavailable (no or an unreadable token)
$result->sandbox;             // true when the public sk_test_sandbox key answered
$result->sample;              // true on GET /v1/evaluate/sample answers
$result->deviceEvidence;      // 'ok' | 'unavailable' | 'not_sent'
$result->evidence;            // ['network_age_s' => ..., 'device_age_s' => ..., 'device_replayed' => ...]
$result->ruleMatched;         // signals your rules matched, or null
$result->exceptionMatched;    // pins that matched, or null
$result->evaluatedInMs;

$result->isBlocked();         // decision === 'block', or (since 0.2.0) a test/sandbox/sample answer
$result->isFixture();         // true for a test-token, test-key, sandbox or sample answer
$result->isSuspicious();      // decision !== 'allow', or (since 0.3.2) a test/sandbox/sample answer
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
        'email' => $in['email'] ?? '',   // never stored or logged by Maskbreak; scored by the
                                          // email- and phone-intelligence provider while that is on
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

Pass the account id once the user is known (from your server-side session, never
a form field) and device-to-account linking turns on when browser device evidence
is also supplied. Account linking is per-customer and stored as keyed hashes
(`linked_accounts`); device `first_seen`/`times_seen` history is not
customer-scoped. With a live key the response also carries `$result->account`
(the account network, since 18 October 2026): devices per account, your accounts
per device and per address in 24 hours, `new_device`, and the accounts it shares
a device or an address with; `device_many_accounts` (3+ of your accounts on one
device within 24 hours) raises an allow to review. Maskbreak also keeps the
account id encrypted so your console can show which accounts are linked. At
sign-in, send it once the credential was accepted, or with `'event' => 'login'`
and `loginSucceeded`: since 5 November 2026 a check with `event` `login`,
`verification` or `password_change` whose `loginSucceeded` (or `succeeded`) is
not `true` counts as a sign-in attempt, which adds nothing to the account's own
devices or addresses.

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

## Check a sign-in

Use the account ID from your server and the credential result from your existing sign-in handler. The visitor check can prompt a second factor when your policy calls for review. A failed credential check never establishes a device link.

```php
$user = find_user_by_email($in['email'] ?? '');                       // your database
$passwordOk = $user !== null && password_verify($in['password'] ?? '', $user->password_hash);

$result = null;
$monthUsedUp = false;
try {
    $result = $sentinel->evaluate([
        'token'              => $token,                                 // the quick start's field mapping
        'fingerprintEventId' => $eventId,
        'tz'                 => $tz,
        'event'              => 'login',
        'accountId'          => $user !== null ? (string) $user->id : null, // your own id for the account
        'loginSucceeded'     => $passwordOk,                            // send failed attempts too
    ]);
} catch (\Sentinel\SentinelException $e) {
    error_log('[maskbreak] check unavailable: ' . $e->getMessage());   // also: no token from the browser
    $monthUsedUp = $e->getStatus() === 429 && ($e->getBody()['code'] ?? null) === 'monthly_quota_exceeded';
}
error_log('[maskbreak] ' . $mode . ' ' . ($result !== null ? $result->decision : 'no answer'));

if (!$passwordOk) {
    http_response_code(401);
    exit;
}
$verify = array_map('trim', explode(',', (string) getenv('MASKBREAK_QUOTA_VERIFY_ACTIONS')));
if ($mode === 'enforce' && (!$monthUsedUp || in_array('login', $verify, true))) {
    if ($result !== null && $result->decision === 'block') {
        http_response_code(403);
        exit;
    }
    // Review, no answer, a degraded or a test answer: a second factor, not a refusal.
    if ($result === null || $result->decision !== 'allow' || $result->degraded || $result->isFixture()) {
        send_second_factor($user);
        exit;
    }
}
sign_in($user);   // your existing session code
```

## Email and phone at signup

With contact intelligence enabled, a visitor check can also evaluate an email address or phone number submitted with the signup. Inspect the returned contact fields and the overall decision in watch mode before enabling enforcement.

[Contact fields and examples](https://maskbreak.com/api#email-phone-intelligence)

## Check your setup

After you submit your form once, `setupStatus()` (`GET /v1/setup`) tells you
whether the check arrived complete and what to fix:

```php
$setup = $sentinel->setupStatus();
echo $setup['status'], ' - ', $setup['message'], PHP_EOL;
if ($setup['next_step'] !== null) {
    echo 'Next: ', $setup['next_step'], PHP_EOL;
}
```

| Key | What it says |
| --- | --- |
| `status` | What the latest check showed: `waiting` (no check in the last 7 days, and none complete before), `complete` (both parts, live key), `missing_network` (no network token), `network_unavailable` (a token that could not be read), `missing_device` (no browser event id), `device_unavailable` (a browser event that could not be verified), `test_mode` (a test token, or the test key without both parts), `test_complete` (the test key with both parts: swap in the live key), `ip_restricted`, `rate_limited` (an hourly limit; no account has one since 29 October 2026), `monthly_quota_exceeded` (this month's checks are used up: `next_step` links to the plan that raises the allowance) or `request_failed` |
| `complete` | At least one complete live-key check has arrived |
| `message` / `next_step` | What the latest check showed, and what to do next (`null` when nothing is left) |
| `last_check_at`, `complete_checks`, `last_complete_at` | When the latest check arrived, how many complete ones did, and when the latest of those did |
| `website` | `['confirmed', 'origin']`: the website the first complete check came from |
| `script_seen` | `['origin', 'at']` where and when the page script last reported in, or `null` |
| `site_id`, `key_type`, `docs` | Your site ID, which key made the call (`live` or `test`), and a link to the guide |

It works with the live key and the test key, and returns the answer as the API
sends it, an associative array.

## Client options

`new \Sentinel\Client($apiKey, $endpoint, $timeout, $allowTestResults, $warnMissingBrowserPart)`,
every argument optional (on PHP 8, by name):

| Argument | Default | Description |
| --- | --- | --- |
| `$apiKey` | `MASKBREAK_API_KEY` (then `SENTINEL_KEY`, `SENTINEL_API_KEY`) | Your key starting with `sk_live_` |
| `$endpoint` | `https://maskbreak.com` | Override the base URL (for tests) |
| `$timeout` | `5.0` | Per-request timeout in seconds |
| `$allowTestResults` | `false` | Only for your own test runs: `isBlocked()`, `isSuspicious()` and `shouldBlock()` treat test, sandbox and sample answers as a normal decision |
| `$warnMissingBrowserPart` | `true` | `false` turns off the one-time error-log line for a check sent without `fingerprintEventId` (since 0.3.0); `$sentinel->warnMissingBrowserPart(false)` does the same on any PHP version |

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

This synchronous client forwards `token`, `fingerprintEventId`, `accountId`,
`email` and, since 0.3.0, `tz`, `phone` and sign-in outcome fields. It does not expose
every REST operation and does not provide automatic retries or a circuit
breaker. Full additive response fields remain in `raw`. An empty or missing
`token` (outside the four account events), an input the API would ignore or
misread, invalid JSON, missing/invalid evaluation decisions, transport failures
and non-2xx responses raise `SentinelException`; redirects are not followed.

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

- **Email and phone:** Test keys and test tokens skip contact scoring and consume no daily contact checks.
- **No account yet?** The public sandbox key `sk_test_sandbox` answers the same
  supported `test_*` tokens only — no signup or stored events. It has a separate
  rate limit, never runs live detection, and is not a production allowance.
- **CI / staging with real traffic:** every account also has a personal
  `sk_test_…` key (Settings → API keys) that runs the live detection (email and phone intelligence and the account network do not run
  for it, and it adds nothing to `times_seen` or `linked_accounts`, which its
  answers leave out). Its events are stored flagged as test, kept out of your stats and never fire
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

Visitor checks (`evaluate()`) are counted per calendar month in UTC, with no hourly cap: **Free — 10,000 a month, no credit card**; paid plans from €29 a month ([pricing](https://maskbreak.com/pricing)). IP lookups (`lookup()`) have their own monthly allowance, 30× the plan's checks (300,000 on Free). A used-up month answers `429` with `code: "monthly_quota_exceeded"` and `Retry-After` until the 1st; there are no overage charges. At this limit, the examples log the refusal. Set `MASKBREAK_QUOTA_VERIFY_ACTIONS=checkout,account_recovery` on your server to require verification for those actions in enforce mode. Other actions continue unchecked.

## Related

- [API reference](https://maskbreak.com/api) — reason codes, response fields, stability policy
- [Node SDK](https://github.com/sentinelsup/maskbreak-node) · [Python SDK](https://pypi.org/project/sentinelsup/)
- [Disposable email detection: flag it, don't block on it](https://maskbreak.com/blog/disposable-email-detection)

## License

MIT
