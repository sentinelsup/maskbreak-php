<?php

declare(strict_types=1);

namespace Sentinel;

/**
 * Structured response from POST /v1/evaluate.
 *
 * Field names mirror the JSON exactly so the raw payload stays readable, and
 * `$raw` always holds the untouched response — the API contract is additive,
 * so anything added server-side is reachable without an SDK upgrade.
 */
final class EvaluateResult
{
    /** @var string|null 'allow' | 'review' | 'block' — route on this. */
    public $decision;

    /** @var int|null 0-100 weighted risk score. */
    public $riskScore;

    /** @var string|null */
    public $ip;

    /** @var string|null 2-letter country code. */
    public $country;

    /** @var array<string,mixed> vpn, proxy, privacy_relay, datacenter, anonymous, tor, residential, service. */
    public $network;

    /** @var array<string,mixed> Device signals, populated when fingerprintEventId was sent. */
    public $device;

    /** @var list<string> Machine-readable reason codes (vpn_detected, disposable_email, ...). */
    public $reasons;

    /**
     * @var array<string,mixed>|null {disposable: bool} — present only when an email was sent. With
     *      email and phone intelligence on (since 23 October 2026) also checked, score, risk (low,
     *      medium, high), signals and a few facts, or checked: false with why.
     */
    public $email;

    /** @var array<string,mixed>|null The account network (since 0.2.1): present when accountId was sent with a live key. */
    public $account;

    /** @var string|null 'rules' | 'exception' when something other than the engine authored the decision. */
    public $decisionSource;

    /** @var string|null The engine's own answer, when custom rules or pins overrode `decision`. */
    public $engineDecision;

    /** @var bool True on test-token / test-key responses. Test-key checks count toward the monthly allowance; the fixed test_* tokens never count. */
    public $test;

    /** @var array<string,mixed> The untouched response body. */
    public $raw;

    /**
     * @var array<string,mixed>|null Login protection (since 0.3.0): present when event was 'login'.
     *      {checked: true, score: 0-100, risk, signals} or {checked: false, why}. A score of 80 or
     *      more adds account_takeover_risk and raises allow to review, never to block.
     */
    public $accountTakeover;

    /**
     * @var array<string,mixed>|null Login protection (since 0.3.0): present when another event was
     *      sent. {event, recorded: true} or {event, recorded: false, why}; no score comes back.
     */
    public $accountEvent;

    /**
     * @var array<string,mixed>|null Email and phone intelligence (since 0.3.0): present when a phone
     *      was sent. {checked: true, score, risk, signals, valid, line_type, carrier, country, ...}
     *      or {checked: false, why}.
     */
    public $phone;

    /** @var array<string,mixed>|null {reported, country, matches_ip, checked} when a recognised tz was sent (0.3.0). */
    public $timezone;

    /** @var bool True when the network part was unavailable (no or an unreadable token): the decision then says nothing about the visitor's network (0.3.0). */
    public $degraded;

    /** @var bool True when the public sk_test_sandbox key answered (0.3.0). */
    public $sandbox;

    /** @var bool True on GET /v1/evaluate/sample answers (0.3.0). */
    public $sample;

    /** @var string|null 'ok' | 'unavailable' | 'not_sent': whether the browser part was usable (0.3.0). */
    public $deviceEvidence;

    /** @var array<string,mixed>|null How old the evidence was: network_age_s, device_age_s, device_replayed (0.3.0). */
    public $evidence;

    /** @var list<string>|null Signals your rules matched, when they did (0.3.0). */
    public $ruleMatched;

    /** @var list<string>|null Pins that matched, when one did (0.3.0). */
    public $exceptionMatched;

    /** @var int|null Server-side processing time of the base verdict (0.3.0). */
    public $evaluatedInMs;

    /** @var bool */
    private $allowTestResults;

    /**
     * @param array<string,mixed> $data
     */
    public function __construct(array $data, bool $allowTestResults = false)
    {
        $this->allowTestResults = $allowTestResults;
        $this->decision = isset($data['decision']) ? (string) $data['decision'] : null;
        $this->riskScore = isset($data['risk_score']) ? (int) $data['risk_score'] : null;
        $this->ip = isset($data['ip']) ? (string) $data['ip'] : null;
        $this->country = isset($data['country']) ? (string) $data['country'] : null;
        $this->network = isset($data['network']) && is_array($data['network']) ? $data['network'] : [];
        $this->device = isset($data['device']) && is_array($data['device']) ? $data['device'] : [];
        $this->reasons = isset($data['reasons']) && is_array($data['reasons']) ? array_values($data['reasons']) : [];
        $this->email = isset($data['email']) && is_array($data['email']) ? $data['email'] : null;
        $this->account = isset($data['account']) && is_array($data['account']) ? $data['account'] : null;
        $this->decisionSource = isset($data['decision_source']) ? (string) $data['decision_source'] : null;
        $this->engineDecision = isset($data['engine_decision']) ? (string) $data['engine_decision'] : null;
        $this->test = !empty($data['test']);
        $this->raw = $data;
        $this->accountTakeover = isset($data['account_takeover']) && is_array($data['account_takeover']) ? $data['account_takeover'] : null;
        $this->accountEvent = isset($data['account_event']) && is_array($data['account_event']) ? $data['account_event'] : null;
        $this->phone = isset($data['phone']) && is_array($data['phone']) ? $data['phone'] : null;
        $this->timezone = isset($data['timezone']) && is_array($data['timezone']) ? $data['timezone'] : null;
        $this->degraded = !empty($data['degraded']);
        $this->sandbox = !empty($data['sandbox']);
        $this->sample = !empty($data['sample']);
        $this->deviceEvidence = isset($data['device_evidence']) && is_string($data['device_evidence']) ? $data['device_evidence'] : null;
        $this->evidence = isset($data['evidence']) && is_array($data['evidence']) ? $data['evidence'] : null;
        $this->ruleMatched = isset($data['rule_matched']) && is_array($data['rule_matched']) ? array_values($data['rule_matched']) : null;
        $this->exceptionMatched = isset($data['exception_matched']) && is_array($data['exception_matched']) ? array_values($data['exception_matched']) : null;
        $this->evaluatedInMs = isset($data['evaluated_in_ms']) && is_numeric($data['evaluated_in_ms']) ? (int) $data['evaluated_in_ms'] : null;
    }

    /**
     * True only for the worst band. This is what you want on signup: it honors
     * your dashboard rules and allow-pins, and leaves 'review' free to route to
     * a step-up rather than a refusal.
     */
    public function isBlocked(): bool
    {
        // Since 0.2.0 a test, sandbox or sample answer counts as blocked: the
        // fixed test tokens are public, so a visitor can type one into your
        // form field. A client made with $allowTestResults = true lets it pass.
        if ($this->isFixture() && !$this->allowTestResults) {
            return true;
        }
        return $this->decision === 'block';
    }

    /**
     * True for a test-token, test-key, sandbox or sample answer: a pretend
     * visitor, never this one. Never let it authorize a real action.
     */
    public function isFixture(): bool
    {
        return $this->test || $this->sample || $this->sandbox;
    }

    /**
     * True for anything that is not a clean allow. Appropriate on irreversible,
     * high-value actions (withdrawal, transfer, promotion redemption) — not on
     * ordinary signup, where it refuses everything you meant to step up.
     */
    public function isSuspicious(): bool
    {
        return $this->decision !== null && $this->decision !== 'allow';
    }

    /**
     * True when the optional email input landed on a known burner domain.
     *
     * This escalates allow to review on its own and nothing more — see
     * https://maskbreak.com/blog/disposable-email-detection for why blocking on it
     * refuses masked-email relays (iCloud Hide My Email, Firefox Relay).
     */
    public function isDisposableEmail(): bool
    {
        return is_array($this->email) && !empty($this->email['disposable']);
    }
}
