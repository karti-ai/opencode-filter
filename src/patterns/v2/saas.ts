/**
 * SaaS Platform Secret Patterns (V2)
 *
 * 50 patterns covering Twilio, SendGrid, Mailgun, PagerDuty, Datadog, and other SaaS platforms.
 * Based on patterns from TruffleHog, GitHub Secret Scanning, and GitLeaks.
 */

import type { SecretPattern } from '../../types.js';

/**
 * SaaS platform secret patterns
 * Total: 50 patterns across various platforms
 */
export const SAAS_PATTERNS: SecretPattern[] = [
  // ============================================================================
  // Twilio (5 patterns)
  // ============================================================================

  {
    name: 'twilio_account_sid',
    regex: /AC[a-f0-9]{32}/,
    category: 'credential',
    description: 'Twilio Account SID starting with AC',
    severity: 'critical',
    example: 'ACa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'twilio_auth_token',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'Twilio Auth Token (32-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'twilio_api_key',
    regex: /SK[a-f0-9]{32}/,
    category: 'api_key',
    description: 'Twilio API Key starting with SK',
    severity: 'critical',
    example: 'SKa1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'twilio_api_secret',
    regex: /[a-zA-Z0-9]{32}/,
    category: 'credential',
    description: 'Twilio API Secret',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'twilio_flex_token',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'Twilio Flex JWT Token',
    severity: 'high',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0',
  },

  // ============================================================================
  // SendGrid / Brevo (4 patterns)
  // ============================================================================

  {
    name: 'sendgrid_api_key',
    regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,
    category: 'api_key',
    description: 'SendGrid API Key (SG.xxx.xxx format)',
    severity: 'critical',
    example: 'SG.a1b2c3d4e5f6g7h8i9j0k1.SaBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  {
    name: 'sendgrid_webhook_key',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'SendGrid Webhook Verification Key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'brevo_api_key',
    regex: /xkeysib-[a-f0-9-]{64,}/,
    category: 'api_key',
    description: 'Brevo (formerly Sendinblue) API Key',
    severity: 'critical',
    example: 'xkeysib-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
  },

  {
    name: 'brevo_smtp_key',
    regex: /xsmtpsib-[a-f0-9-]{64,}/,
    category: 'api_key',
    description: 'Brevo SMTP Key',
    severity: 'critical',
    example: 'xsmtpsib-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
  },

  // ============================================================================
  // Mailgun (3 patterns)
  // ============================================================================

  {
    name: 'mailgun_api_key',
    regex: /key-[a-f0-9]{32}/,
    category: 'api_key',
    description: 'Mailgun API Key starting with key-',
    severity: 'critical',
    example: 'key-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'mailgun_webhook_key',
    regex: /[a-zA-Z0-9]{32}/,
    category: 'credential',
    description: 'Mailgun Webhook Signing Key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'mailgun_smtp_password',
    regex: /postmaster@[a-z0-9.-]+\s+[a-f0-9]{32}/,
    category: 'password',
    description: 'Mailgun SMTP credentials with postmaster',
    severity: 'high',
    example: 'postmaster@mg.example.com a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  // ============================================================================
  // PagerDuty (3 patterns)
  // ============================================================================

  {
    name: 'pagerduty_api_key',
    regex: /[a-z0-9]{32}/,
    category: 'api_key',
    description: 'PagerDuty API Key (32-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'pagerduty_integration_key',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'PagerDuty Integration Key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'pagerduty_routing_key',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'PagerDuty Events API V2 Routing Key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  // ============================================================================
  // Datadog (3 patterns)
  // ============================================================================

  {
    name: 'datadog_api_key',
    regex: /[a-f0-9]{32}/,
    category: 'api_key',
    description: 'Datadog API Key (32-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'datadog_app_key',
    regex: /[a-f0-9]{40}/,
    category: 'api_key',
    description: 'Datadog Application Key (40-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'datadog_rcm_token',
    regex: /pub[a-f0-9]{32}/,
    category: 'token',
    description: 'Datadog Remote Configuration Management Token',
    severity: 'critical',
    example: 'puba1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  // ============================================================================
  // New Relic (2 patterns)
  // ============================================================================

  {
    name: 'newrelic_license_key',
    regex: /[a-f0-9]{40}/,
    category: 'api_key',
    description: 'New Relic License Key (40-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'newrelic_api_key',
    regex: /NRAK-[A-Z0-9]{27}/,
    category: 'api_key',
    description: 'New Relic API Key starting with NRAK-',
    severity: 'critical',
    example: 'NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ123',
  },

  // ============================================================================
  // Sentry (2 patterns)
  // ============================================================================

  {
    name: 'sentry_auth_token',
    regex: /[a-f0-9]{64}/,
    category: 'token',
    description: 'Sentry Auth Token (64-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
  },

  {
    name: 'sentry_dsn',
    regex: /https:\/\/[a-f0-9]{32}@[a-z0-9.-]+\.sentry\.io\/\d+/,
    category: 'credential',
    description: 'Sentry DSN with embedded secret',
    severity: 'high',
    example: 'https://a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6@myapp.sentry.io/123456',
  },

  // ============================================================================
  // Segment (2 patterns)
  // ============================================================================

  {
    name: 'segment_write_key',
    regex: /[a-zA-Z0-9]{32}/,
    category: 'api_key',
    description: 'Segment Write Key (32-character alphanumeric)',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'segment_source_id',
    regex: /[a-zA-Z0-9]{16}/,
    category: 'credential',
    description: 'Segment Source ID',
    severity: 'medium',
    example: 'a1b2c3d4e5f6g7h8',
  },

  // ============================================================================
  // Mixpanel (2 patterns)
  // ============================================================================

  {
    name: 'mixpanel_token',
    regex: /[a-f0-9]{32}/,
    category: 'api_key',
    description: 'Mixpanel Project Token (32-character hex)',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'mixpanel_api_secret',
    regex: /[a-zA-Z0-9]{32}\.[a-zA-Z0-9]{32}/,
    category: 'api_key',
    description: 'Mixpanel API Secret (two 32-char parts)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6',
  },

  // ============================================================================
  // Auth0 (3 patterns)
  // ============================================================================

  {
    name: 'auth0_api_token',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'Auth0 Management API Token',
    severity: 'critical',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0',
  },

  {
    name: 'auth0_client_secret',
    regex: /[a-zA-Z0-9_-]{64}/,
    category: 'credential',
    description: 'Auth0 Application Client Secret (64 characters)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
  },

  {
    name: 'auth0_signing_secret',
    regex: /[a-f0-9]{64}/,
    category: 'credential',
    description: 'Auth0 Signing Secret (64-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
  },

  // ============================================================================
  // Okta (2 patterns)
  // ============================================================================

  {
    name: 'okta_api_token',
    regex: /00[a-zA-Z0-9_-]{40,}/,
    category: 'api_key',
    description: 'Okta API Token starting with 00',
    severity: 'critical',
    example: '00a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
  },

  {
    name: 'okta_ssws_token',
    regex: /SSWS\s+[a-zA-Z0-9_-]{40,}/,
    category: 'token',
    description: 'Okta SSWS (Static API Token)',
    severity: 'critical',
    example: 'SSWS a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
  },

  // ============================================================================
  // Postman (2 patterns)
  // ============================================================================

  {
    name: 'postman_api_key',
    regex: /PMAK-[a-f0-9]{24}-[a-f0-9]{24}/,
    category: 'api_key',
    description: 'Postman API Key (PMAK-xxx-xxx format)',
    severity: 'critical',
    example: 'PMAK-a1b2c3d4e5f6g7h8i9j0k1l2-b1c2d3e4f5g6h7i8j9k0l1m2',
  },

  {
    name: 'postman_environment',
    regex: /https:\/\/go\.postman\.co\/workspaces\/[a-f0-9-]+\/environments\/[a-f0-9-]+/,
    category: 'credential',
    description: 'Postman Environment URL',
    severity: 'medium',
    example: 'https://go.postman.co/workspaces/a1b2c3d4-e5f6/environments/b1c2d3e4-f5g6',
  },

  // ============================================================================
  // Intercom (2 patterns)
  // ============================================================================

  {
    name: 'intercom_api_key',
    regex: /[a-z0-9]{24}/,
    category: 'api_key',
    description: 'Intercom API Key (24-character lowercase)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2',
  },

  {
    name: 'intercom_access_token',
    regex: /dG9r[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'Intercom Access Token (base64 encoded)',
    severity: 'critical',
    example: 'dG9rOjE2OjEzOjE2OjE2OjE2OjE2OjE2',
  },

  // ============================================================================
  // HubSpot (2 patterns)
  // ============================================================================

  {
    name: 'hubspot_api_key',
    regex: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/,
    category: 'api_key',
    description: 'HubSpot API Key (UUID format)',
    severity: 'critical',
    example: 'a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6',
  },

  {
    name: 'hubspot_private_app_token',
    regex: /pat-[a-z]{2}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/,
    category: 'api_key',
    description: 'HubSpot Private App Token',
    severity: 'critical',
    example: 'pat-na-a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6',
  },

  // ============================================================================
  // Zendesk (2 patterns)
  // ============================================================================

  {
    name: 'zendesk_api_token',
    regex: /[a-zA-Z0-9]{40}/,
    category: 'api_key',
    description: 'Zendesk API Token (40 characters)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'zendesk_webhook_secret',
    regex: /[a-zA-Z0-9]{32}/,
    category: 'credential',
    description: 'Zendesk Webhook Signing Secret',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  // ============================================================================
  // Shopify (3 patterns)
  // ============================================================================

  {
    name: 'shopify_api_key',
    regex: /[a-f0-9]{32}/,
    category: 'api_key',
    description: 'Shopify API Key (32-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'shopify_api_secret',
    regex: /shpss_[a-f0-9]{32}/,
    category: 'credential',
    description: 'Shopify API Secret Key starting with shpss_',
    severity: 'critical',
    example: 'shpss_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'shopify_access_token',
    regex: /shpat_[a-f0-9]{32}/,
    category: 'token',
    description: 'Shopify Admin API Access Token starting with shpat_',
    severity: 'critical',
    example: 'shpat_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  // ============================================================================
  // Contentful (2 patterns)
  // ============================================================================

  {
    name: 'contentful_delivery_token',
    regex: /[a-zA-Z0-9_-]{43}/,
    category: 'token',
    description: 'Contentful Content Delivery API Token',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2',
  },

  {
    name: 'contentful_management_token',
    regex: /CFPAT-[a-zA-Z0-9_-]{43}/,
    category: 'token',
    description: 'Contentful Personal Access Token (CFPAT)',
    severity: 'critical',
    example: 'CFPAT-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2',
  },

  // ============================================================================
  // Algolia (2 patterns)
  // ============================================================================

  {
    name: 'algolia_search_key',
    regex: /[a-f0-9]{32}/,
    category: 'api_key',
    description: 'Algolia Search-Only API Key (32-character hex)',
    severity: 'medium',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'algolia_admin_key',
    regex: /[a-f0-9]{32}/,
    category: 'api_key',
    description: 'Algolia Admin API Key (32-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  // ============================================================================
  // Cloudflare (2 patterns)
  // ============================================================================

  {
    name: 'cloudflare_api_token',
    regex: /[a-zA-Z0-9_-]{40}/,
    category: 'token',
    description: 'Cloudflare API Token (40-character alphanumeric)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'cloudflare_api_key',
    regex: /[a-f0-9]{37}/,
    category: 'api_key',
    description: 'Cloudflare Global API Key (37-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s',
  },

  // ============================================================================
  // CircleCI (2 patterns)
  // ============================================================================

  {
    name: 'circleci_api_token',
    regex: /[a-f0-9]{40}/,
    category: 'token',
    description: 'CircleCI API Token (40-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'circleci_project_token',
    regex: /[a-f0-9]{40}/,
    category: 'token',
    description: 'CircleCI Project API Token',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  // ============================================================================
  // Travis CI (1 pattern)
  // ============================================================================

  {
    name: 'travis_token',
    regex: /[a-zA-Z0-9]{22}/,
    category: 'token',
    description: 'Travis CI Access Token (22 characters)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1',
  },

  // ============================================================================
  // Netlify (2 patterns)
  // ============================================================================

  {
    name: 'netlify_access_token',
    regex: /[a-f0-9]{64}/,
    category: 'token',
    description: 'Netlify Personal Access Token (64-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
  },

  {
    name: 'netlify_site_id',
    regex: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/,
    category: 'credential',
    description: 'Netlify Site ID (UUID format)',
    severity: 'medium',
    example: 'a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6',
  },

  // ============================================================================
  // Heroku (2 patterns)
  // ============================================================================

  {
    name: 'heroku_api_key',
    regex: /[a-f0-9]{36}/,
    category: 'api_key',
    description: 'Heroku API Key (36-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6',
  },

  {
    name: 'heroku_oauth_token',
    regex: /[a-f0-9]{40}/,
    category: 'token',
    description: 'Heroku OAuth Token (40-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  // ============================================================================
  // Firebase (3 patterns)
  // ============================================================================

  {
    name: 'firebase_api_key',
    regex: /AIza[0-9A-Za-z_-]{35}/,
    category: 'api_key',
    description: 'Firebase API Key (Google Cloud)',
    severity: 'high',
    example: 'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
  },

  {
    name: 'firebase_server_key',
    regex: /[a-zA-Z0-9:_-]{152}/,
    category: 'credential',
    description: 'Firebase Cloud Messaging Server Key',
    severity: 'critical',
    example: 'AAAAa1b2c3d:APA91bE5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g5h6i7j8k9l0m1n2o3',
  },

  {
    name: 'firebase_service_account',
    regex: /"type":\s*"service_account"/,
    category: 'private_key',
    description: 'Firebase Service Account JSON',
    severity: 'critical',
    example: '{"type": "service_account", "project_id": "my-project"}',
  },

  // ============================================================================
  // Mapbox (2 patterns)
  // ============================================================================

  {
    name: 'mapbox_access_token',
    regex: /pk\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'Mapbox Public Access Token starting with pk.',
    severity: 'high',
    example: 'pk.eyJ1IjoidXNlciIsImEiOiJhOGQifQ.aBcDeFgHiJkLmNoPqRsTu',
  },

  {
    name: 'mapbox_secret_token',
    regex: /sk\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'Mapbox Secret Token starting with sk.',
    severity: 'critical',
    example: 'sk.eyJ1IjoidXNlciIsImEiOiJhOGQifQ.aBcDeFgHiJkLmNoPqRsTu',
  },
];

export default SAAS_PATTERNS;
