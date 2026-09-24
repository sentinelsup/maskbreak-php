<?php

declare(strict_types=1);

/**
 * WooCommerce checkout guard — screen orders for VPN, residential proxy,
 * antidetect browser and automation signals before the payment gateway is hit.
 *
 * Classic shortcode checkout only, not WooCommerce Checkout Blocks/Store API.
 * Drop this in a small site plugin (or your theme's functions.php) and set
 * MASKBREAK_API_KEY in wp-config.php:
 *
 *     define('MASKBREAK_API_KEY', 'sk_live_...');
 *
 * Card testing is the abuse this stops: an attacker runs stolen card numbers
 * through your checkout in bulk, and each declined authorisation costs you a
 * gateway fee plus fraud-ratio damage. Refusing the session before the gateway
 * call is the difference between a blocked bot and a chargeback.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Sentinel\Client;
use Sentinel\SentinelException;

/**
 * Load the collector on checkout only — it has no business on product pages.
 *
 * Mark the classic checkout form before the collector's DOMContentLoaded
 * handler runs; unmarked forms do not receive the hidden device input.
 */
add_action('wp_enqueue_scripts', static function (): void {
    if (function_exists('is_checkout') && is_checkout()) {
        wp_enqueue_script(
            'sentinel',
            'https://maskbreak.com/assets/sentinel.js',
            [],
            null,
            false          // header, not footer: it needs time to resolve before submit
        );
        wp_add_inline_script('sentinel', <<<'JS'
document.addEventListener('DOMContentLoaded', function () {
    var form = document.querySelector('form.checkout');
    if (form) form.classList.add('monocle-enriched');
});
JS
        , 'before');
    }
});

/**
 * Validate before the order is created and before the gateway is charged.
 *
 * Caching plugins are the thing to watch here. If a page cache serves a stale
 * checkout HTML snapshot, the injected token can be missing or expired — which
 * is exactly why a missing token is treated as degraded rather than hostile.
 */
add_action('woocommerce_after_checkout_validation', static function ($data, $errors): void {
    if (!defined('MASKBREAK_API_KEY') || MASKBREAK_API_KEY === '') {
        return;                                     // not configured: do nothing
    }

    $token = isset($_POST['monocle']) ? sanitize_text_field(wp_unslash($_POST['monocle'])) : '';
    if ($token === '') {
        // An ad blocker, a CSP failure or a cached page can legitimately stop
        // the collector. Refusing these blocks real customers.
        return;
    }

    $fingerprint = isset($_POST['sentinel_fp'])
        ? sanitize_text_field(wp_unslash($_POST['sentinel_fp']))
        : '';

    try {
        $sentinel = new Client(MASKBREAK_API_KEY);
        $result = $sentinel->evaluate([
            'token'              => $token,
            'fingerprintEventId' => $fingerprint,
            // Links repeat devices to accounts for this merchant only.
            'accountId'          => is_user_logged_in() ? (string) get_current_user_id() : '',
            'email'              => isset($data['billing_email']) ? (string) $data['billing_email'] : '',
        ]);
    } catch (SentinelException $e) {
        // Fail open. A detection outage must not become a checkout outage —
        // your gateway's own fraud rules and post-hoc review still apply.
        error_log('[sentinel] evaluate failed: ' . $e->getMessage());
        return;
    }

    if ($result->isBlocked()) {
        $errors->add(
            'sentinel_blocked',
            __('We could not complete verification. Please contact support.', 'sentinel')
        );
        return;
    }

    // 'review' is not 'block'. Let the order through and flag it for a human
    // instead of refusing a customer who may be entirely legitimate.
    if ($result->decision === 'review') {
        add_action('woocommerce_checkout_update_order_meta', static function (int $orderId) use ($result): void {
            $order = wc_get_order($orderId);
            if (!$order) {
                return;
            }
            $order->update_meta_data('_sentinel_decision', 'review');
            $order->update_meta_data('_sentinel_risk_score', (string) $result->riskScore);
            $order->update_meta_data('_sentinel_reasons', implode(',', $result->reasons));
            $order->add_order_note(sprintf(
                /* translators: 1: risk score, 2: comma-separated reason codes */
                __('Sentinel flagged this order for review (score %1$d): %2$s', 'sentinel'),
                (int) $result->riskScore,
                implode(', ', $result->reasons)
            ));
            $order->save();
        }, 10, 1);
    }
}, 10, 2);
