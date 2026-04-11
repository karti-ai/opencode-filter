/**
 * Built-in Secret Patterns
 *
 * Comprehensive collection of 220+ built-in secret patterns covering common services.
 * These patterns are designed based on real-world formats from TruffleHog,
 * GitHub Secret Scanning, and GitLeaks patterns.
 *
 * V1: 20 patterns (original built-in set)
 * V2: 200+ patterns organized by category
 */

import type { SecretPattern } from '../types.js';

// Import V2 patterns
import { V2_PATTERNS, V2_PATTERN_COUNTS } from './v2/index.js';

/**
 * Legacy V1 patterns for backward compatibility
 * Original 20 patterns
 */
export const BUILTIN_PATTERNS_V1: SecretPattern[] = [
  // ============================================================================
  // CLOUD PROVIDERS (5 patterns)
  // ============================================================================

  {
    name: 'aws_access_key_id',
    regex: /AKIA[0-9A-Z]{16}/,
    category: 'credential',
    description: 'AWS Access Key ID starting with AKIA',
    severity: 'critical',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },

  {
    name: 'aws_secret_access_key',
    regex: /[0-9a-zA-Z/+]{40}/,
    category: 'credential',
    description: 'AWS Secret Access Key (40-character base64-like string)',
    severity: 'critical',
    example: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },

  {
    name: 'azure_subscription_key',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'Azure Subscription Key (32-character hex string)',
    severity: 'high',
    example: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  },

  {
    name: 'gcp_api_key',
    regex: /AIza[0-9A-Za-z_-]{35}/,
    category: 'api_key',
    description: 'Google Cloud Platform API Key starting with AIza',
    severity: 'high',
    example: 'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
  },

  {
    name: 'gcp_oauth_token',
    regex: /ya29\.[0-9A-Za-z_-]+/,
    category: 'token',
    description: 'Google OAuth 2.0 Access Token starting with ya29',
    severity: 'critical',
    example: 'ya29.a0Aa4b16C3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0',
  },

  // ============================================================================
  // CODE HOSTING (3 patterns)
  // ============================================================================

  {
    name: 'github_personal_token',
    regex: /ghp_[a-zA-Z0-9]{36}/,
    category: 'token',
    description: 'GitHub Personal Access Token starting with ghp_',
    severity: 'critical',
    example: 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  {
    name: 'gitlab_personal_token',
    regex: /glpat-[a-zA-Z0-9\-]{20}/,
    category: 'token',
    description: 'GitLab Personal Access Token starting with glpat-',
    severity: 'critical',
    example: 'glpat-abcdefghij12345678',
  },

  {
    name: 'bitbucket_app_password',
    regex: /[a-zA-Z0-9]{32}@[a-zA-Z0-9_-]+/,
    category: 'password',
    description: 'Bitbucket App Password with username suffix',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6@username',
  },

  // ============================================================================
  // COMMUNICATION (2 patterns)
  // ============================================================================

  {
    name: 'slack_bot_token',
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/,
    category: 'token',
    description: 'Slack Bot Token (OAuth bot access token)',
    severity: 'critical',
    example: 'xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX',
  },

  {
    name: 'slack_user_token',
    regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}/,
    category: 'token',
    description: 'Slack User Token (OAuth user access token)',
    severity: 'critical',
    example: 'xoxp-1234567890123-1234567890123-1234567890123-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  // ============================================================================
  // PAYMENT SERVICES (2 patterns)
  // ============================================================================

  {
    name: 'stripe_live_key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/,
    category: 'api_key',
    description: 'Stripe Live Secret Key starting with sk_live_',
    severity: 'critical',
    example: 'sk_live_abcdefghijklmnopqrstuvwxyz1234',
  },

  {
    name: 'stripe_test_key',
    regex: /sk_test_[0-9a-zA-Z]{24,}/,
    category: 'api_key',
    description: 'Stripe Test Secret Key starting with sk_test_',
    severity: 'high',
    example: 'sk_test_abcdefghijklmnopqrstuvwxyz1234',
  },

  // ============================================================================
  // AUTHENTICATION (4 patterns)
  // ============================================================================

  {
    name: 'jwt_token',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'JSON Web Token (JWT) with three base64url-encoded parts',
    severity: 'high',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  },

  {
    name: 'bearer_token',
    regex: /bearer [a-zA-Z0-9_\-\.]+/i,
    category: 'token',
    description: 'Bearer token used in Authorization headers',
    severity: 'high',
    example: 'Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'oauth_access_token',
    regex: /[a-f0-9]{64}/,
    category: 'token',
    description: 'OAuth Access Token (64-character hex string)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
  },

  {
    name: 'basic_auth',
    regex: /Basic [a-zA-Z0-9+\/]{20,}={0,2}/,
    category: 'credential',
    description: 'Basic Authentication header with base64 credentials',
    severity: 'critical',
    example: 'Basic YWRtaW46cGFzc3dvcmQxMjM=',
  },

  // ============================================================================
  // GENERIC SECRETS (4 patterns)
  // ============================================================================

  {
    name: 'generic_api_key',
    regex: /[a-zA-Z0-9_-]*(?:api[_-]?key|apikey)[a-zA-Z0-9_-]*[:=\s]+['"]?[a-zA-Z0-9_-]{16,}['"]?/i,
    category: 'api_key',
    description: 'Generic API key pattern with common naming conventions',
    severity: 'medium',
    example: 'api_key=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'private_key',
    regex: /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/,
    category: 'private_key',
    description: 'Private key file header (RSA, DSA, EC, OpenSSH)',
    severity: 'critical',
    example: '-----BEGIN RSA PRIVATE KEY-----',
  },

  {
    name: 'database_connection_string',
    regex: /(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'Database connection string with embedded credentials',
    severity: 'critical',
    example: 'postgres://user:password123@localhost:5432/mydb',
  },

  {
    name: 'password_in_code',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    category: 'password',
    description: 'Hardcoded password in code or configuration',
    severity: 'high',
    example: 'password = "MySecretPassword123!"',
  },
] as const;

/**
 * All built-in patterns (V1 + V2 combined)
 * Total: 220+ patterns
 */
export const BUILTIN_PATTERNS: SecretPattern[] = [
  ...BUILTIN_PATTERNS_V1,
  ...V2_PATTERNS,
];

/**
 * Pattern statistics
 */
export const PATTERN_STATS = {
  v1: BUILTIN_PATTERNS_V1.length,
  v2: V2_PATTERNS.length,
  total: BUILTIN_PATTERNS.length,
  v2Breakdown: V2_PATTERN_COUNTS,
} as const;

/**
 * Get all built-in patterns
 * @returns Array of built-in secret patterns (V1 + V2 combined)
 */
export function getBuiltinPatterns(): readonly SecretPattern[] {
  return BUILTIN_PATTERNS;
}

/**
 * Get V2 patterns only
 * @returns Array of V2 secret patterns
 */
export function getV2Patterns(): readonly SecretPattern[] {
  return V2_PATTERNS;
}

/**
 * Get V1 patterns only (legacy)
 * @returns Array of V1 secret patterns (original 20)
 */
export function getV1Patterns(): readonly SecretPattern[] {
  return BUILTIN_PATTERNS_V1;
}

/**
 * Get patterns by category
 * @param category - Category to filter by
 * @returns Array of patterns matching the category
 */
export function getPatternsByCategory(
  category: SecretPattern['category']
): SecretPattern[] {
  return BUILTIN_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns by severity level
 * @param severity - Severity level to filter by
 * @returns Array of patterns matching the severity
 */
export function getPatternsBySeverity(
  severity: SecretPattern['severity']
): SecretPattern[] {
  return BUILTIN_PATTERNS.filter((p) => p.severity === severity);
}

/**
 * Find a pattern by name
 * @param name - Pattern name to search for
 * @returns Pattern if found, undefined otherwise
 */
export function findPatternByName(name: string): SecretPattern | undefined {
  return BUILTIN_PATTERNS.find((p) => p.name === name);
}

export { V2_PATTERNS, V2_PATTERN_COUNTS };

export default BUILTIN_PATTERNS;
