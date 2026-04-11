/**
 * Payment Service Secret Patterns (V2)
 *
 * 15 patterns covering Stripe, PayPal, Square, and Braintree.
 * Based on patterns from TruffleHog, GitHub Secret Scanning, and GitLeaks.
 */

import type { SecretPattern } from '../../types.js';

/**
 * Payment service secret patterns
 * Total: 15 patterns
 * - Stripe: 6 patterns
 * - PayPal: 4 patterns
 * - Square: 3 patterns
 * - Braintree: 2 patterns
 */
export const PAYMENT_PATTERNS: SecretPattern[] = [
  // ============================================================================
  // Stripe (6 patterns)
  // ============================================================================

  {
    name: 'stripe_live_secret_key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/,
    category: 'api_key',
    description: 'Stripe Live Secret Key starting with sk_live_',
    severity: 'critical',
    example: 'sk_live_abcdefghijklmnopqrstuvwxyz1234',
  },

  {
    name: 'stripe_test_secret_key',
    regex: /sk_test_[0-9a-zA-Z]{24,}/,
    category: 'api_key',
    description: 'Stripe Test Secret Key starting with sk_test_',
    severity: 'high',
    example: 'sk_test_abcdefghijklmnopqrstuvwxyz1234',
  },

  {
    name: 'stripe_live_publishable_key',
    regex: /pk_live_[0-9a-zA-Z]{24,}/,
    category: 'api_key',
    description: 'Stripe Live Publishable Key starting with pk_live_',
    severity: 'high',
    example: 'pk_live_abcdefghijklmnopqrstuvwxyz1234',
  },

  {
    name: 'stripe_test_publishable_key',
    regex: /pk_test_[0-9a-zA-Z]{24,}/,
    category: 'api_key',
    description: 'Stripe Test Publishable Key starting with pk_test_',
    severity: 'medium',
    example: 'pk_test_abcdefghijklmnopqrstuvwxyz1234',
  },

  {
    name: 'stripe_restricted_api_key',
    regex: /rk_live_[0-9a-zA-Z]{24,}/,
    category: 'api_key',
    description: 'Stripe Restricted API Key starting with rk_live_',
    severity: 'critical',
    example: 'rk_live_abcdefghijklmnopqrstuvwxyz1234',
  },

  {
    name: 'stripe_webhook_secret',
    regex: /whsec_[0-9a-zA-Z]{24,}/,
    category: 'credential',
    description: 'Stripe Webhook Endpoint Secret starting with whsec_',
    severity: 'high',
    example: 'whsec_abcdefghijklmnopqrstuvwxyz1234',
  },

  // ============================================================================
  // PayPal (4 patterns)
  // ============================================================================

  {
    name: 'paypal_client_id',
    regex: /[A-Za-z0-9_-]{80,}/,
    category: 'credential',
    description: 'PayPal REST API Client ID (long alphanumeric string)',
    severity: 'high',
    example: 'AWkKic7C3vT2bLJi8kMxA7C-3vT2bLJi8kMxA7C3vT2bLJi8kMxA7C3vT2bLJi8kMxA7C3vT2bLJi8kMx',
  },

  {
    name: 'paypal_client_secret',
    regex: /[A-Za-z0-9_-]{40,80}/,
    category: 'credential',
    description: 'PayPal REST API Client Secret',
    severity: 'critical',
    example: 'EOkKic7C3vT2bLJi8kMxA7C-3vT2bLJi8kMxA7C3vT2bLJi8k',
  },

  {
    name: 'paypal_access_token',
    regex: /A21[A-Za-z0-9_-]{50,}/,
    category: 'token',
    description: 'PayPal OAuth Access Token starting with A21',
    severity: 'critical',
    example: 'A21AAFsafafafafafafafafafafafafafafafafafafafafafafafafafafafaf',
  },

  {
    name: 'paypal_sandbox_key',
    regex: /sb-[a-z0-9]{20,}/,
    category: 'api_key',
    description: 'PayPal Sandbox API Key',
    severity: 'medium',
    example: 'sb-a1b2c3d4e5f6g7h8i9j0',
  },

  // ============================================================================
  // Square (3 patterns)
  // ============================================================================

  {
    name: 'square_access_token',
    regex: /EAAA[a-zA-Z0-9_-]{60,}/,
    category: 'token',
    description: 'Square API Access Token starting with EAAA',
    severity: 'critical',
    example: 'EAAAabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  },

  {
    name: 'square_application_secret',
    regex: /sq0csp-[0-9a-zA-Z_-]{40,}/,
    category: 'credential',
    description: 'Square Application Secret starting with sq0csp-',
    severity: 'critical',
    example: 'sq0csp-abcdefghijklmnopqrstuvwxyz12345678',
  },

  {
    name: 'square_webhook_signature',
    regex: /[a-f0-9]{64}/,
    category: 'credential',
    description: 'Square Webhook Signature Key (64-character hex)',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8',
  },

  // ============================================================================
  // Braintree (2 patterns)
  // ============================================================================

  {
    name: 'braintree_private_key',
    regex: /[a-f0-9]{32}/,
    category: 'private_key',
    description: 'Braintree API Private Key (32-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'braintree_merchant_key',
    regex: /[a-z0-9]{16}/,
    category: 'credential',
    description: 'Braintree Merchant ID/Account Key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8',
  },
];

export default PAYMENT_PATTERNS;
