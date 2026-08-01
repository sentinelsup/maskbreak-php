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

    /** @var array<string,mixed> vpn, proxy, datacenter, anonymous, tor, residential, service. */
    public $network;

    /** @var array<string,mixed> Device signals, populated when fingerprintEventId was sent. */
    public $device;

    /** @var list<string> Machine-readable reason codes (vpn_detected, disposable_email, ...). */
    public $reasons;

    /** @var array<string,mixed>|null {disposable: bool} — present only when an email was sent. */
    public $email;

    /** @var string|null 'rules' | 'exception' when something other than the engine authored the decision. */
    public $decisionSource;

    /** @var string|null The engine's own answer, when custom rules or pins overrode `decision`. */
    public $engineDecision;

    /** @var bool True on test-token / test-key responses. Never billed. */
    public $test;

    /** @var array<string,mixed> The untouched response body. */
    public $raw;

    /**
     * @param array<string,mixed> $data
     */
    public function __construct(array $data)
    {
        $this->decision = isset($data['decision']) ? (string) $data['decision'] : null;
        $this->riskScore = isset($data['risk_score']) ? (int) $data['risk_score'] : null;
        $this->ip = isset($data['ip']) ? (string) $data['ip'] : null;
        $this->country = isset($data['country']) ? (string) $data['country'] : null;
        $this->network = isset($data['network']) && is_array($data['network']) ? $data['network'] : [];
        $this->device = isset($data['device']) && is_array($data['device']) ? $data['device'] : [];
        $this->reasons = isset($data['reasons']) && is_array($data['reasons']) ? array_values($data['reasons']) : [];
        $this->email = isset($data['email']) && is_array($data['email']) ? $data['email'] : null;
        $this->decisionSource = isset($data['decision_source']) ? (string) $data['decision_source'] : null;
        $this->engineDecision = isset($data['engine_decision']) ? (string) $data['engine_decision'] : null;
        $this->test = !empty($data['test']);
        $this->raw = $data;
    }

    /**
     * True only for the worst band. This is what you want on signup: it honors
     * your dashboard rules and allow-pins, and leaves 'review' free to route to
     * a step-up rather than a refusal.
     */
    public function isBlocked(): bool
    {
        return $this->decision === 'block';
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
     * https://sntlhq.com/blog/disposable-email-detection for why blocking on it
     * refuses masked-email relays (iCloud Hide My Email, Firefox Relay).
     */
    public function isDisposableEmail(): bool
    {
        return is_array($this->email) && !empty($this->email['disposable']);
    }
}
