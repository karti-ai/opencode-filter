/**
 * Generic Secret Patterns (V2)
 *
 * 15 patterns for generic passwords, secrets, and tokens commonly found in code.
 * Based on patterns from TruffleHog, GitHub Secret Scanning, and GitLeaks.
 */

import type { SecretPattern } from '../../types.js';

/**
 * Generic secret patterns
 * Total: 15 patterns for common secret formats
 */
export const GENERIC_PATTERNS: SecretPattern[] = [
  // ============================================================================
  // Password Patterns (5 patterns)
  // ============================================================================

  {
    name: 'generic_password_assignment',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    category: 'password',
    description: 'Hardcoded password in variable assignment',
    severity: 'high',
    example: 'password = "MySecretPassword123!"',
  },

  {
    name: 'generic_password_env',
    regex: /(?:PASSWORD|PASSWD|PWD)\s*=\s*['"][^'"]{8,}['"]/,
    category: 'password',
    description: 'Hardcoded password in environment variable',
    severity: 'high',
    example: 'DB_PASSWORD="secretpass123"',
  },

  {
    name: 'generic_password_json',
    regex: /"password"\s*:\s*"[^"]{8,}"/i,
    category: 'password',
    description: 'Password in JSON format',
    severity: 'high',
    example: '"password": "securePass123!"',
  },

  {
    name: 'generic_password_yaml',
    regex: /password\s*:\s*[^\s]{8,}/i,
    category: 'password',
    description: 'Password in YAML format',
    severity: 'high',
    example: 'password: mySecretPass123',
  },

  {
    name: 'generic_password_url_encoded',
    regex: /(?:password|passwd|pwd)=[^&\s]{8,}/i,
    category: 'password',
    description: 'Password in URL-encoded format',
    severity: 'high',
    example: 'password=mypassword123',
  },

  // ============================================================================
  // Generic Secrets (5 patterns)
  // ============================================================================

  {
    name: 'generic_secret_assignment',
    regex: /(?:secret|token|key)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/i,
    category: 'credential',
    description: 'Generic secret in variable assignment',
    severity: 'medium',
    example: 'secret = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
  },

  {
    name: 'generic_api_key_pattern',
    regex: /[a-zA-Z0-9_-]*(?:api[_-]?key|apikey)[a-zA-Z0-9_-]*[:=\s]+['"]?[a-zA-Z0-9_-]{16,}['"]?/i,
    category: 'api_key',
    description: 'Generic API key with common naming conventions',
    severity: 'medium',
    example: 'my_api_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
  },

  {
    name: 'generic_access_token',
    regex: /(?:access_token|accessToken)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/i,
    category: 'token',
    description: 'Generic access token pattern',
    severity: 'high',
    example: 'access_token: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
  },

  {
    name: 'generic_bearer_token',
    regex: /[Bb][Ee][Aa][Rr][Ee][Rr]\s+[a-zA-Z0-9_\-]{20,}/,
    category: 'token',
    description: 'Generic Bearer token authorization header',
    severity: 'high',
    example: 'Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'generic_auth_token',
    regex: /(?:auth_token|authToken|authentication_token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/i,
    category: 'token',
    description: 'Generic authentication token pattern',
    severity: 'high',
    example: 'auth_token = "xyz789abc123def456ghi789"',
  },

  // ============================================================================
  // Environment & Config (5 patterns)
  // ============================================================================

  {
    name: 'env_file_secret',
    regex: /^[A-Z_]+(?:SECRET|KEY|TOKEN|PASSWORD)\s*=\s*.+$/m,
    category: 'environment_variable',
    description: 'Secret in .env file format',
    severity: 'high',
    example: 'API_SECRET_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'config_file_secret',
    regex: /(?:secret|password|token|key)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    category: 'credential',
    description: 'Secret in configuration file',
    severity: 'medium',
    example: 'secret = "my-config-secret-123"',
  },

  {
    name: 'ini_file_secret',
    regex: /\[\w+\]\s*\n[^\[]*(?:password|secret|key)\s*=\s*[^\s]+/i,
    category: 'credential',
    description: 'Secret in INI file format',
    severity: 'medium',
    example: '[database]\npassword = secret123',
  },

  {
    name: 'xml_secret',
    regex: /<(?:password|secret|token|key)[^>]*>[^<]{8,}<\/(?:password|secret|token|key)>/i,
    category: 'credential',
    description: 'Secret in XML format',
    severity: 'high',
    example: '<password>mySecretPass123</password>',
  },

  {
    name: 'base64_encoded_secret',
    regex: /[A-Za-z0-9+/]{40,}={0,2}/,
    category: 'credential',
    description: 'Base64 encoded secret (potential)',
    severity: 'low',
    example: 'YWRtaW46cGFzc3dvcmQxMjMhQCMkJQ==',
  },
];

export default GENERIC_PATTERNS;
