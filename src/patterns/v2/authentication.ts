/**
 * Authentication Secret Patterns (V2)
 *
 * 25 patterns covering JWT variants, OAuth, and API keys.
 * Based on patterns from TruffleHog, GitHub Secret Scanning, and GitLeaks.
 */

import type { SecretPattern } from '../../types.js';

/**
 * Authentication secret patterns
 * Total: 25 patterns
 * - JWT variants: 8 patterns
 * - OAuth: 8 patterns
 * - API keys: 9 patterns
 */
export const AUTHENTICATION_PATTERNS: SecretPattern[] = [
  // ============================================================================
  // JWT Variants (8 patterns)
  // ============================================================================

  {
    name: 'jwt_token_standard',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'Standard JSON Web Token (JWT) with three base64url parts',
    severity: 'high',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  },

  {
    name: 'jwt_token_hs256',
    regex: /eyJhbGciOiJIUzI1Ni[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'JWT signed with HMAC SHA-256 (HS256)',
    severity: 'high',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  },

  {
    name: 'jwt_token_rs256',
    regex: /eyJhbGciOiJSUzI1Ni[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'JWT signed with RSA SHA-256 (RS256)',
    severity: 'high',
    example: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.aBcDeFgHiJkLmNoPqRsTuVwXyZ',
  },

  {
    name: 'jwt_token_es256',
    regex: /eyJhbGciOiJFUzI1Ni[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'JWT signed with ECDSA SHA-256 (ES256)',
    severity: 'high',
    example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.aBcDeFgHiJkLmNoPqRsTuVwXyZ',
  },

  {
    name: 'jwt_bearer_token',
    regex: /Bearer\s+eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/i,
    category: 'token',
    description: 'JWT Bearer token in Authorization header',
    severity: 'high',
    example: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMe',
  },

  {
    name: 'jwt_refresh_token',
    regex: /eyJhbGciOiJIUzI1Ni[a-zA-Z0-9_-]{50,}\.eyJ[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'JWT Refresh Token (typically longer)',
    severity: 'critical',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicmVmcmVzaCI6dHJ1ZX0',
  },

  {
    name: 'jwt_with_claims',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*eyJzdWIi[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'JWT containing subject claim (common in auth tokens)',
    severity: 'high',
    example: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.aBcDeFgHiJkLmNoPqRsTuVwXyZ',
  },

  {
    name: 'jwe_encrypted_token',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'JSON Web Encryption (JWE) token with 5 parts',
    severity: 'high',
    example: 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ0MifQ.a.b.c.d',
  },

  // ============================================================================
  // OAuth (8 patterns)
  // ============================================================================

  {
    name: 'oauth_access_token',
    regex: /[a-f0-9]{64}/,
    category: 'token',
    description: 'OAuth 2.0 Access Token (64-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
  },

  {
    name: 'oauth_refresh_token',
    regex: /[a-f0-9]{32,64}/,
    category: 'token',
    description: 'OAuth 2.0 Refresh Token (32-64 character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'oauth_client_credentials',
    regex: /client_id\s*[=:]\s*['"][a-zA-Z0-9_-]+['"]\s*,?\s*client_secret\s*[=:]\s*['"][a-zA-Z0-9_-]+['"]/i,
    category: 'credential',
    description: 'OAuth Client ID and Client Secret pair',
    severity: 'critical',
    example: 'client_id="abc123", client_secret="xyz789"',
  },

  {
    name: 'oauth_authorization_code',
    regex: /code\s*[=:]\s*['"][a-zA-Z0-9_-]{20,}['"]/i,
    category: 'token',
    description: 'OAuth Authorization Code (temporary)',
    severity: 'high',
    example: 'code="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
  },

  {
    name: 'oauth_pkce_verifier',
    regex: /code_verifier\s*[=:]\s*['"][a-zA-Z0-9_-]{43,128}['"]/i,
    category: 'credential',
    description: 'OAuth PKCE Code Verifier',
    severity: 'high',
    example: 'code_verifier="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"',
  },

  {
    name: 'oauth_state_param',
    regex: /state\s*[=:]\s*['"][a-zA-Z0-9_-]{10,50}['"]/i,
    category: 'token',
    description: 'OAuth State Parameter (CSRF protection)',
    severity: 'medium',
    example: 'state="a1b2c3d4e5f6g7h8i9j0"',
  },

  {
    name: 'oauth_token_in_url',
    regex: /[?&]access_token=[a-zA-Z0-9_-]{20,}/,
    category: 'token',
    description: 'OAuth Access Token in URL query parameter',
    severity: 'critical',
    example: '?access_token=a1b2c3d4e5f6g7h8i9j0',
  },

  {
    name: 'oauth_google_token',
    regex: /ya29\.[0-9A-Za-z_-]+/,
    category: 'token',
    description: 'Google OAuth 2.0 Token starting with ya29',
    severity: 'critical',
    example: 'ya29.a0Aa4b16C3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0',
  },

  // ============================================================================
  // API Keys (9 patterns)
  // ============================================================================

  {
    name: 'generic_api_key_header',
    regex: /[Xx]-[Aa][Pp][Ii]-[Kk][Ee][Yy]\s*:\s*[a-zA-Z0-9_-]{16,}/,
    category: 'api_key',
    description: 'Generic X-Api-Key header with key value',
    severity: 'high',
    example: 'X-Api-Key: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'generic_api_key_param',
    regex: /[?&]api[_-]?key\s*=\s*[a-zA-Z0-9_-]{16,}/i,
    category: 'api_key',
    description: 'Generic API key in URL query parameter',
    severity: 'high',
    example: '?api_key=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'bearer_token_generic',
    regex: /[Bb][Ee][Aa][Rr][Ee][Rr]\s+[a-zA-Z0-9_\-\.]{20,}/,
    category: 'token',
    description: 'Generic Bearer token in Authorization header',
    severity: 'high',
    example: 'Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'basic_auth_header',
    regex: /[Bb][Aa][Ss][Ii][Cc]\s+[a-zA-Z0-9+/]{20,}={0,2}/,
    category: 'credential',
    description: 'HTTP Basic Authentication header with base64 credentials',
    severity: 'critical',
    example: 'Basic YWRtaW46cGFzc3dvcmQxMjM=',
  },

  {
    name: 'api_key_env_var',
    regex: /[A-Z_]*API[_-]?KEY[A-Z_]*\s*=\s*['"][a-zA-Z0-9_-]{16,}['"]/i,
    category: 'api_key',
    description: 'API Key in environment variable format',
    severity: 'high',
    example: 'MY_SERVICE_API_KEY="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
  },

  {
    name: 'api_key_json_format',
    regex: /"api[_-]?key"\s*:\s*"[a-zA-Z0-9_-]{16,}"/i,
    category: 'api_key',
    description: 'API Key in JSON configuration',
    severity: 'high',
    example: '"api_key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
  },

  {
    name: 'api_key_yaml_format',
    regex: /api[_-]?key\s*:\s*[a-zA-Z0-9_-]{16,}/i,
    category: 'api_key',
    description: 'API Key in YAML configuration',
    severity: 'high',
    example: 'api_key: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'api_token_env_var',
    regex: /[A-Z_]*API[_-]?TOKEN[A-Z_]*\s*=\s*['"][a-zA-Z0-9_-]{16,}['"]/i,
    category: 'token',
    description: 'API Token in environment variable format',
    severity: 'high',
    example: 'SERVICE_API_TOKEN="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
  },

  {
    name: 'api_secret_env_var',
    regex: /[A-Z_]*API[_-]?SECRET[A-Z_]*\s*=\s*['"][a-zA-Z0-9_-]{16,}['"]/i,
    category: 'credential',
    description: 'API Secret in environment variable format',
    severity: 'critical',
    example: 'SERVICE_API_SECRET="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
  },
];

export default AUTHENTICATION_PATTERNS;
