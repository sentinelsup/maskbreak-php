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
        $decision = $result->isFixture() ? null : $result->decision;
    } elseif ($mode !== 'enforce') {
        $decision = maskbreak_report_without_token(['fingerprintEventId' => $eventId, 'tz' => $tz])['decision'] ?? null;
    }
} catch (\Sentinel\SentinelException $e) {
    error_log('[maskbreak] check unavailable: ' . $e->getMessage());
    // The month's checks are used up: let the action through, logged, until the 1st.
    if ($e->getStatus() === 429 && ($e->getBody()['code'] ?? null) === 'monthly_quota_exceeded') $decision = 'unchecked';
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

### 0.3.0 (2026-10-27)

- `evaluate()` sends the fields the API has read since 23 October 2026: `tz`,
  `phone`, and for login protection `event`, `loginSucceeded`, `succeeded`,
  `sessionId`, `userAgent`, `ip`, `reason`, `verificationType` and
  `verifiedEvent`. See [Logins, signups and account events](#logins-signups-and-account-events).
- The account events `password_change`, `verification`, `logout` and
  `account_change` can be sent without the browser's token. A login, a signup
  and a plain check still need it.
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
- `EvaluateResult` gains `accountTakeover`, `accountEvent`, `phone`,
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
$result->accountTakeover;     // event 'login': ['checked' => true, 'score' => 91, 'risk' => 'high', 'signals' => [...]]
$result->accountEvent;        // other events: ['event' => 'logout', 'recorded' => true]
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
account id encrypted so your console can show which accounts are linked.

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

## Logins, signups and account events

Since 0.3.0 `evaluate()` sends the fields the API reads for login protection
and for email and phone intelligence, so the call your login, signup and
account handlers already make carries them. The examples use the quick start's
`$token`, `$eventId` and `$tz`.

### A login

Make the check after your own password check, so it can say whether the
password was right. `accountId` is the account being signed in to, as your
database knows it (never a form field). Each call is a check: on your login
route this one is the check, not one more.

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
        'sessionId'          => session_id(),                           // only a keyed hash leaves Maskbreak
        'userAgent'          => $_SERVER['HTTP_USER_AGENT'] ?? null,    // as your server received it
        'ip'                 => $_SERVER['REMOTE_ADDR'] ?? null,        // as your server saw it
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
if ($mode === 'enforce' && !$monthUsedUp) {
    if ($result !== null && $result->decision === 'block') {
        http_response_code(403);
        exit;
    }
    // Review, no answer or a test answer: a second factor, not a refusal.
    if ($result === null || $result->decision !== 'allow' || $result->isFixture()) {
        send_second_factor($user);
        exit;
    }
}
sign_in($user);   // your existing session code
```

- `ip` is used only when the network token gave no address, and never changes
  the network verdict. Behind a proxy, take the visitor's address from the
  header only your own proxy sets; never trust an arbitrary `X-Forwarded-For`.
- `$result->accountTakeover` is `['checked' => true, 'score', 'risk', 'signals']`
  with a score from 0 to 100 (higher is riskier; `risk` is `low` below 50,
  `medium` from 50, `high` from 80). A score of 80 or more adds the reason
  `account_takeover_risk` and raises `allow` to `review`, never to `block`:
  answer it with a second factor or an emailed code.
- `'checked' => false` comes with `why`: `not_enabled` (switched off in
  Settings), `no_account_id`, `test`, `busy`, `unavailable` or
  `not_available`. Treat it as no opinion; the rest of the answer is
  unaffected.
- Login protection is on for every account until a workspace admin switches
  it off in Settings, and it acts only when you send `event` with
  `accountId`. Its score learns from the logins of every Maskbreak customer
  who uses login protection; say so in your own privacy notice. A login
  counts as a normal check.

### A signup with email and phone

Send `'event' => 'signup'` once your database has the new account's id, with
the address and the number the person gave:

```php
try {
    $result = $sentinel->evaluate([
        'token'              => $token,
        'fingerprintEventId' => $eventId,
        'tz'                 => $tz,
        'event'              => 'signup',               // the account was created
        'accountId'          => (string) $user->id,     // the new account's id, from your database
        'email'              => $in['email'] ?? '',
        'phone'              => $in['phone'] ?? '',     // international format, such as +44 20 7946 0958
    ]);
} catch (\Sentinel\SentinelException $e) {
    $result = null;
}
// A review: keep the new account waiting until it confirms its email or phone.
```

- With email and phone intelligence on, `$result->email` gains `checked`,
  `score`, `risk`, `signals` and a few facts, and `$result->phone` has the same
  shape. A score of 80 or more adds `email_high_risk` or `phone_high_risk` and
  raises `allow` to `review`, never to `block`.
- Email and phone intelligence is on by default for accounts created from 23
  October 2026; an older account switches it on in Settings, and any account
  can switch it off there. Each address or number scored uses one of the
  plan's daily email-and-phone checks: Free 3, Starter 20, Growth 50, Scale
  150 a day.
- `'checked' => false` comes with `why`: `not_enabled`, `quota` (the day's
  checks are used up), `invalid`, `test`, `busy`, `unavailable` or
  `not_available`; `invalid`, `busy` and `unavailable` use no daily check.
  Treat it as no opinion. Maskbreak never stores or logs the address or the
  number.
- `$result->accountEvent` says whether login protection took the signup:
  `['event' => 'signup', 'recorded' => true]`.

### Account events

A password change, a second factor, a logout and an account change go to login
protection too: no score comes back, and they teach it what is normal for each
account, so its login scores get sharper. These four may go without the
browser's token (since 0.3.0), for handlers with no page in front of them:

```php
function maskbreak_event(\Sentinel\Client $sentinel, array $fields): ?\Sentinel\EvaluateResult
{
    try {
        return $sentinel->evaluate($fields);
    } catch (\Sentinel\SentinelException $e) {
        error_log('[maskbreak] check unavailable: ' . $e->getMessage());
        return null;
    }
}

// After your password-change handler has saved the new password:
maskbreak_event($sentinel, [
    'event'     => 'password_change',
    'accountId' => (string) $_SESSION['user_id'],         // from your server-side session
    'succeeded' => true,
    'reason'    => 'user',                                // 'forgot' after a reset link, 'forced' for a reset you required
    'sessionId' => session_id(),
    'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
    'ip'        => $_SERVER['REMOTE_ADDR'] ?? null,
]);

// A second factor, with how it was checked and what it was for:
maskbreak_event($sentinel, ['event' => 'verification', 'accountId' => (string) $user->id,
    'succeeded' => $codeOk, 'verificationType' => 'sms', 'verifiedEvent' => 'login']);

maskbreak_event($sentinel, ['event' => 'logout', 'accountId' => (string) $_SESSION['user_id'], 'sessionId' => session_id()]);
maskbreak_event($sentinel, ['event' => 'account_change', 'accountId' => (string) $_SESSION['user_id'], 'email' => $newEmail]);
```

- The answer's `accountEvent` is `['event' => ..., 'recorded' => true]`, or
  `'recorded' => false` with the same `why` values as a login.
- Sent with the browser's `token` and `fingerprintEventId` from a form that
  carries the script, it is a full check. Without the token it is a degraded
  one (`$result->degraded` is true): its `decision` says nothing about the
  visitor's network, so read `accountEvent`. A recorded event counts as a
  check.
- A login and a signup are visits, so they still need the token:
  `evaluate()` throws without it, as before.

### The visitor's time zone

`tz` comes with the browser's evidence (`Sentinel.collect()` returns it, a form
carries `sentinel_tz`), and the quick start already sends it. With a
recognised zone, `$result->timezone` is
`['reported' => 'Europe/Tallinn', 'country' => 'EE', 'matches_ip' => true, 'checked' => true]`.
A zone whose country disagrees with an ordinary-looking address adds
`timezone_mismatch` and raises `allow` to `review`; it never blocks. On a VPN,
proxy, Tor or datacenter exit, where a mismatch is expected, nothing is raised
(`'checked' => false`).

### Refused before sending

A value the API would ignore or misread throws a `SentinelException`, and
nothing is sent: an `event` other than `login`, `signup`, `password_change`,
`verification`, `logout` and `account_change` (read case-insensitively, so
`'signin'` is refused), a `reason`, `verificationType` or `verifiedEvent`
outside its list, a `loginSucceeded` or `succeeded` that is not `true` or
`false`, a `tz`, `phone`, `userAgent` or `ip` that is not a string, and a
`sessionId` that is not a string or an int or is longer than 256 characters.
A key that is missing, `null` or `''` is left out of the request.

### The missing-browser-part warning

A check sent without `fingerprintEventId` has no browser part, so bots, fake
browsers and emulators go unchecked (the dashboard says the browser part is
missing). The first such call in a PHP process writes one line to PHP's error
log with `error_log()` (the command line prints it on stderr), saying so and
how to fix it; it never contains your key or anything about the visitor.
PHP-FPM and mod_php start every request afresh, so there it is one line per
request that sends such a check. The fixed `test_*` tokens and the four
account events never trigger it.

It is a log line rather than `trigger_error()` on purpose: Laravel, and
Symfony in debug mode, turn a notice into an exception, and WordPress with
`WP_DEBUG_DISPLAY` prints it into the page, so a notice could break the very
request it is about. Turn it off with
`new \Sentinel\Client(warnMissingBrowserPart: false)` (PHP 8) or
`$sentinel->warnMissingBrowserPart(false)` (any version).

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
| `status` | What the latest check showed: `waiting` (no check in the last 7 days, and none complete before), `complete` (both parts, live key), `missing_network` (no network token), `network_unavailable` (a token that could not be read), `missing_device` (no browser event id), `device_unavailable` (a browser event that could not be verified), `test_mode` (a test token, or the test key without both parts), `test_complete` (the test key with both parts: swap in the live key), `ip_restricted`, `rate_limited` or `request_failed` |
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
| `$allowTestResults` | `false` | Only for your own test runs: `isBlocked()` and `shouldBlock()` treat test, sandbox and sample answers as a normal decision |
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
`email` and, since 0.3.0, `tz`, `phone` and the login-protection fields above
(the GPU and browser consistency betas stay raw HTTP). It does not expose
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

- **Login protection, email and phone:** test keys, test tokens and the
  sandbox never reach those providers. `accountTakeover`, `email` and `phone`
  answer `'checked' => false, 'why' => 'test'`, and `accountEvent` answers
  `'recorded' => false, 'why' => 'test'`, so you can test the shape without
  using the day's email-and-phone checks.
- **No account yet?** The public sandbox key `sk_test_sandbox` answers the same
  supported `test_*` tokens only — no signup or stored events. It has a separate
  rate limit, never runs live detection, and is not a production allowance.
- **CI / staging with real traffic:** every account also has a personal
  `sk_test_…` key (Settings → API keys) that runs the live detection (login
  protection, email and phone intelligence and the account network do not run
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

Visitor checks (`evaluate()`) are counted per calendar month in UTC, with no hourly cap: **Free — 10,000 a month, no credit card**; paid plans from €29 a month ([pricing](https://maskbreak.com/pricing)). IP lookups (`lookup()`) have their own monthly allowance, 10× the plan's checks (100,000 on Free). A used-up month answers `429` with `code: "monthly_quota_exceeded"` and `Retry-After` until the 1st; there are no overage charges. The quick start lets the action through on that answer and logs it, in enforce mode too, so running out never takes your form offline.

## Related

- [API reference](https://maskbreak.com/api) — reason codes, response fields, stability policy
- [Node SDK](https://github.com/sentinelsup/maskbreak-node) · [Python SDK](https://pypi.org/project/sentinelsup/)
- [Disposable email detection: flag it, don't block on it](https://maskbreak.com/blog/disposable-email-detection)

## License

MIT
