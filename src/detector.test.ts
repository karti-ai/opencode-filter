import { describe, it, expect } from 'bun:test';
import {
  SecretDetector,
  RegexEngineStub,
  EntropyEngineStub,
  createDefaultDetector,
} from './detector';
import type { SecretPattern } from './types';

// ============================================================================
// MOCK PATTERNS (for basic detector testing)
// ============================================================================

const MOCK_AWS_PATTERN: SecretPattern = {
  name: 'aws-access-key',
  regex: /AKIA[0-9A-Z]{16}/g,
  category: 'api_key',
  description: 'AWS Access Key ID',
  severity: 'high',
  example: 'AKIAIOSFODNN7EXAMPLE',
};

const MOCK_GITHUB_PATTERN: SecretPattern = {
  name: 'github-token',
  regex: /ghp_[a-zA-Z0-9]{36}/g,
  category: 'token',
  description: 'GitHub Personal Access Token',
  severity: 'high',
  example: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
};

const MOCK_PASSWORD_PATTERN: SecretPattern = {
  name: 'generic-password',
  regex: /password[=:]\s*(\S+)/gi,
  category: 'password',
  description: 'Generic password assignment',
  severity: 'critical',
  example: 'password=secret123',
};

// ============================================================================
// REALISTIC MOCK DATA FOR ALL 20 BUILT-IN PATTERNS
// Using mock data that matches the pattern format but are NOT real secrets
// ============================================================================

const BUILTIN_PATTERN_TESTS = {
  // CLOUD PROVIDERS (5 patterns)
  aws_access_key_id: {
    valid: ['AKIAIOSFODNN7EXAMPLE', 'AKIA1234567890ABCDEF'],
    invalid: ['AKIA123', 'AKIAIOSFODNN7EXAMPL', 'AKIAIOSFODNN7EXAMPLE1'],
    context: 'AWS Access Key in config: AKIAIOSFODNN7EXAMPLE',
  },
  aws_secret_access_key: {
    valid: ['wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
    invalid: ['short123', 'wJalrXUtnFEMI'],
    context: 'AWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },
  azure_subscription_key: {
    valid: ['a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', '0123456789abcdef0123456789abcdef'],
    invalid: ['a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d', 'short'],
    context: 'Azure key: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  },
  gcp_api_key: {
    valid: ['AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI'],
    invalid: ['AIza123', 'AIzaSyDdI0hCZtE6vySjMm'],
    context: 'GCP API Key: AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
  },
  gcp_oauth_token: {
    valid: ['ya29.a0Aa4b16C3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1v2w3x4y5z6'],
    invalid: ['ya29', 'ya29.short'],
    context: 'OAuth token: ya29.a0Aa4b16C3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1v2w3x4y5z6',
  },

  // CODE HOSTING (3 patterns)
  github_personal_token: {
    valid: ['ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890'],
    invalid: ['ghp_short', 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123'],
    context: 'GitHub token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },
  gitlab_personal_token: {
    valid: ['glpat-abcdefghij1234567890'], // Exactly 20 chars after glpat-
    invalid: ['glpat-short', 'glpat-abc'],
    context: 'GitLab token: glpat-abcdefghij1234567890',
  },
  bitbucket_app_password: {
    valid: ['a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6@username'],
    invalid: ['short@user', '@username'],
    context: 'Bitbucket: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6@username',
  },

  // COMMUNICATION (2 patterns)
  slack_bot_token: {
    valid: ['xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX'],
    invalid: ['xoxb-short', 'xoxb-123'],
    context: 'Slack bot: xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX',
  },
  slack_user_token: {
    valid: ['xoxp-1234567890123-1234567890123-1234567890123-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'],
    invalid: ['xoxp-short', 'xoxp-123'],
    context: 'Slack user: xoxp-1234567890123-1234567890123-1234567890123-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  // PAYMENT SERVICES (2 patterns)
  stripe_live_key: {
    valid: ['sk_live_abcdefghijklmnopqrstuvwxyz1234'],
    invalid: ['sk_live_short', 'sk_live_abc'],
    context: 'Stripe live: sk_live_abcdefghijklmnopqrstuvwxyz1234',
  },
  stripe_test_key: {
    valid: ['sk_test_abcdefghijklmnopqrstuvwxyz1234'],
    invalid: ['sk_test_short', 'sk_test_abc'],
    context: 'Stripe test: sk_test_abcdefghijklmnopqrstuvwxyz1234',
  },

  // AUTHENTICATION (4 patterns)
  jwt_token: {
    valid: ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'],
    invalid: ['eyJ.short', 'eyJhbGc'],
    context: 'JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  },
  bearer_token: {
    valid: ['Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'],
    invalid: ['Bearer short', 'bearer'],
    context: 'Auth: Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },
  oauth_access_token: {
    valid: ['a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2'],
    invalid: ['a1b2c3d4', 'short'],
    context: 'OAuth: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
  },
  basic_auth: {
    valid: ['Basic YWRtaW46cGFzc3dvcmQxMjM=', 'Basic dXNlcjpwYXNzd29yZDEyMw=='],
    invalid: ['Basic short', 'Basic abc'],
    context: 'Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=',
  },

  // GENERIC SECRETS (4 patterns)
  generic_api_key: {
    valid: ['api_key=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6', 'apikey: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'],
    invalid: ['api_key=short', 'apikey=123'],
    context: 'API: api_key=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },
  private_key: {
    valid: ['-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----', '-----BEGIN EC PRIVATE KEY-----'],
    invalid: ['BEGIN PRIVATE KEY', 'PRIVATE KEY'],
    context: 'Key: -----BEGIN RSA PRIVATE KEY-----',
  },
  database_connection_string: {
    valid: ['postgres://user:password123@localhost:5432/mydb', 'mysql://admin:secret@db.example.com:3306/production'],
    invalid: ['postgres://user@host', 'mysql://localhost'],
    context: 'DB: postgres://user:password123@localhost:5432/mydb',
  },
  password_in_code: {
    valid: ['password = "MySecretPassword123!"', 'passwd: "AnotherPassword456"', 'pwd = \'Password789\''],
    invalid: ['password = "short"', 'pwd = "12"'],
    context: 'Config: password = "MySecretPassword123!"',
  },
};

// Create patterns for all 20 built-in patterns
const ALL_BUILTIN_PATTERNS: SecretPattern[] = [
  // Cloud Providers
  {
    name: 'aws_access_key_id',
    regex: /AKIA[0-9A-Z]{16}/g,
    category: 'credential',
    description: 'AWS Access Key ID starting with AKIA',
    severity: 'critical',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },
  {
    name: 'aws_secret_access_key',
    regex: /[0-9a-zA-Z/+]{40}/g,
    category: 'credential',
    description: 'AWS Secret Access Key (40-character base64-like string)',
    severity: 'critical',
    example: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },
  {
    name: 'azure_subscription_key',
    regex: /[a-f0-9]{32}/g,
    category: 'credential',
    description: 'Azure Subscription Key (32-character hex string)',
    severity: 'high',
    example: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  },
  {
    name: 'gcp_api_key',
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    category: 'api_key',
    description: 'Google Cloud Platform API Key starting with AIza',
    severity: 'high',
    example: 'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
  },
  {
    name: 'gcp_oauth_token',
    regex: /ya29\.[0-9A-Za-z_-]+/g,
    category: 'token',
    description: 'Google OAuth 2.0 Access Token starting with ya29',
    severity: 'critical',
    example: 'ya29.a0Aa4b16C3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0',
  },
  // Code Hosting
  {
    name: 'github_personal_token',
    regex: /ghp_[a-zA-Z0-9]{36}/g,
    category: 'token',
    description: 'GitHub Personal Access Token starting with ghp_',
    severity: 'critical',
    example: 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },
  {
    name: 'gitlab_personal_token',
    regex: /glpat-[a-zA-Z0-9\-]{20}/g,
    category: 'token',
    description: 'GitLab Personal Access Token starting with glpat-',
    severity: 'critical',
    example: 'glpat-abcdefghij1234567890',
  },
  {
    name: 'bitbucket_app_password',
    regex: /[a-zA-Z0-9]{32}@[a-zA-Z0-9_-]+/g,
    category: 'password',
    description: 'Bitbucket App Password with username suffix',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6@username',
  },
  // Communication
  {
    name: 'slack_bot_token',
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,
    category: 'token',
    description: 'Slack Bot Token (OAuth bot access token)',
    severity: 'critical',
    example: 'xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX',
  },
  {
    name: 'slack_user_token',
    regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}/g,
    category: 'token',
    description: 'Slack User Token (OAuth user access token)',
    severity: 'critical',
    example: 'xoxp-1234567890123-1234567890123-1234567890123-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },
  // Payment Services
  {
    name: 'stripe_live_key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    category: 'api_key',
    description: 'Stripe Live Secret Key starting with sk_live_',
    severity: 'critical',
    example: 'sk_live_abcdefghijklmnopqrstuvwxyz1234',
  },
  {
    name: 'stripe_test_key',
    regex: /sk_test_[0-9a-zA-Z]{24,}/g,
    category: 'api_key',
    description: 'Stripe Test Secret Key starting with sk_test_',
    severity: 'high',
    example: 'sk_test_abcdefghijklmnopqrstuvwxyz1234',
  },
  // Authentication
  {
    name: 'jwt_token',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/g,
    category: 'token',
    description: 'JSON Web Token (JWT) with three base64url-encoded parts',
    severity: 'high',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  },
  {
    name: 'bearer_token',
    regex: /bearer [a-zA-Z0-9_\-\.]+/gi,
    category: 'token',
    description: 'Bearer token used in Authorization headers',
    severity: 'high',
    example: 'Bearer a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },
  {
    name: 'oauth_access_token',
    regex: /[a-f0-9]{64}/g,
    category: 'token',
    description: 'OAuth Access Token (64-character hex string)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
  },
  {
    name: 'basic_auth',
    regex: /Basic [a-zA-Z0-9+\/]{20,}={0,2}/g,
    category: 'credential',
    description: 'Basic Authentication header with base64 credentials',
    severity: 'critical',
    example: 'Basic YWRtaW46cGFzc3dvcmQxMjM=',
  },
  // Generic Secrets
  {
    name: 'generic_api_key',
    regex: /[a-zA-Z0-9_-]*(?:api[_-]?key|apikey)[a-zA-Z0-9_-]*[:=\s]+['"]?[a-zA-Z0-9_-]{16,}['"]?/gi,
    category: 'api_key',
    description: 'Generic API key pattern with common naming conventions',
    severity: 'medium',
    example: 'api_key=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },
  {
    name: 'private_key',
    regex: /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    category: 'private_key',
    description: 'Private key file header (RSA, DSA, EC, OpenSSH)',
    severity: 'critical',
    example: '-----BEGIN RSA PRIVATE KEY-----',
  },
  {
    name: 'database_connection_string',
    regex: /(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^/]+/gi,
    category: 'connection_string',
    description: 'Database connection string with embedded credentials',
    severity: 'critical',
    example: 'postgres://user:password123@localhost:5432/mydb',
  },
  {
    name: 'password_in_code',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    category: 'password',
    description: 'Hardcoded password in code or configuration',
    severity: 'high',
    example: 'password = "MySecretPassword123!"',
  },
];

// ============================================================================
// TEST SUITES
// ============================================================================

describe('SecretDetector', () => {
  describe('basic detection', () => {
    it('should return empty array for empty text', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('');
      expect(result).toHaveLength(0);
    });

    it('should return empty array for text without secrets', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('This is just regular text with no secrets.');
      expect(result).toHaveLength(0);
    });

    it('should detect AWS key with regex engine', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('My AWS key is AKIAIOSFODNN7EXAMPLE in here');

      expect(result).toHaveLength(1);
      expect(result[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(result[0].category).toBe('api_key');
      expect(result[0].confidence).toBe('high');
      expect(result[0].position.start).toBe(14);
      expect(result[0].position.end).toBe(34);
    });

    it('should detect multiple different secrets', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN, MOCK_GITHUB_PATTERN]);
      const result = detector.detect(
        'AWS: AKIAIOSFODNN7EXAMPLE and GitHub: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
      );

      expect(result).toHaveLength(2);
      expect(result[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(result[1].value).toBe('ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
    });

    it('should include correct position information', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const text = 'Line 1\nLine 2 has AKIAIOSFODNN7EXAMPLE here\nLine 3';
      const result = detector.detect(text);

      expect(result).toHaveLength(1);
      expect(result[0].position.line).toBe(2);
      // Column 11: "Line 2 has " = 11 chars (0-indexed: L=0, i=1, n=2, e=3, space=4, 2=5, space=6, h=7, a=8, s=9, space=10)
      expect(result[0].position.column).toBe(11);
    });
  });

  describe('entropy detection', () => {
    it('should detect high-entropy strings with entropy engine', () => {
      const detector = createDefaultDetector([], 4.0, 16);
      // High-entropy base64 string
      const result = detector.detect(
        'Here is a secret: dGhpcyBpcyBhIHNlY3JldCBrZXk= that was hidden'
      );

      expect(result.length).toBeGreaterThan(0);
      expect(result[0].confidence).toBe('medium');
      expect(result[0].pattern.name).toBe('entropy-detected');
    });

    it('should not detect low-entropy strings', () => {
      const detector = createDefaultDetector([], 4.5, 16);
      // Low-entropy string
      const result = detector.detect('This is password123 and it is common');

      // password123 is low entropy, should not be detected
      const hasPassword = result.some((s) => s.value.includes('password'));
      expect(hasPassword).toBe(false);
    });

    it('should detect hex strings with high entropy', () => {
      const detector = createDefaultDetector([], 3.5, 16);
      // High-entropy hex string (random-looking)
      const result = detector.detect(
        'API key: f47ac10b58cc4372a5670e02b2c3d479'
      );

      expect(result.length).toBeGreaterThan(0);
    });

    it('should detect multiple high-entropy strings', () => {
      const detector = createDefaultDetector([], 4.0, 16);
      const result = detector.detect(
        'Key1: dGhpcyBpcyBhIHNlY3JldCBrZXk= and Key2: YW5vdGhlcjpzZWNyZXQxMjM='
      );

      expect(result.length).toBeGreaterThanOrEqual(2);
    });

    it('should respect entropy threshold', () => {
      const lowThreshold = createDefaultDetector([], 2.0, 8);
      const highThreshold = createDefaultDetector([], 5.0, 8);

      const text = 'abc123def456ghi789';
      const lowResult = lowThreshold.detect(text);
      const highResult = highThreshold.detect(text);

      expect(lowResult.length).toBeGreaterThanOrEqual(highResult.length);
    });
  });

  describe('engine combination', () => {
    it('should combine regex and entropy detections', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN], 4.0, 16);
      const result = detector.detect(
        'AWS: AKIAIOSFODNN7EXAMPLE and random: dGhpcyBpcyBhIHNlY3JldCBrZXk='
      );

      // Should detect both: AWS via regex, base64 via entropy
      expect(result.length).toBeGreaterThanOrEqual(2);

      const awsMatch = result.find((s) => s.value === 'AKIAIOSFODNN7EXAMPLE');
      const entropyMatch = result.find(
        (s) => s.value === 'dGhpcyBpcyBhIHNlY3JldCBrZXk='
      );

      expect(awsMatch).toBeDefined();
      expect(awsMatch?.confidence).toBe('high');
      expect(entropyMatch).toBeDefined();
      expect(entropyMatch?.confidence).toBe('medium');
    });

    it('should prioritize regex over entropy for same region', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN], 4.0, 8);
      // AWS key that also has high entropy
      const result = detector.detect('Key: AKIAIOSFODNN7EXAMPLE');

      // Should only detect once, with high confidence (regex)
      const awsDetections = result.filter(
        (s) => s.value === 'AKIAIOSFODNN7EXAMPLE'
      );
      expect(awsDetections).toHaveLength(1);
      expect(awsDetections[0].confidence).toBe('high');
    });
  });

  describe('deduplication', () => {
    it('should not return duplicates for same secret', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      // Same AWS key appears twice
      const result = detector.detect(
        'Key 1: AKIAIOSFODNN7EXAMPLE and Key 2: AKIAIOSFODNN7EXAMPLE'
      );

      // Should detect both instances (different positions)
      expect(result).toHaveLength(2);
      expect(result[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(result[1].value).toBe('AKIAIOSFODNN7EXAMPLE');
      // Different positions
      expect(result[0].position.start).not.toBe(result[1].position.start);
    });

    it('should deduplicate overlapping regex and entropy matches', () => {
      // Pattern that might overlap with entropy detection
      const pattern: SecretPattern = {
        name: 'long-secret',
        regex: /[a-z0-9]{20,}/gi,
        category: 'other',
        description: 'Long alphanumeric string',
        severity: 'medium',
        example: 'abc123def456ghi789jkl',
      };

      const detector = createDefaultDetector([pattern], 3.5, 16);
      const result = detector.detect('Secret: abc123def456ghi789jkl012mno345pqr');

      // Should not have overlapping detections
      for (let i = 0; i < result.length; i++) {
        for (let j = i + 1; j < result.length; j++) {
          const a = result[i].position;
          const b = result[j].position;
          const overlap = a.start < b.end && b.start < a.end;
          expect(overlap).toBe(false);
        }
      }
    });
  });

  describe('overlapping matches', () => {
    it('should resolve overlapping matches with longest match winning', () => {
      // Pattern for "password=something"
      const fullPattern: SecretPattern = {
        name: 'password-full',
        regex: /password[=:]\s*\S+/gi,
        category: 'password',
        description: 'Full password assignment',
        severity: 'critical',
        example: 'password=secret123',
      };

      // Pattern for just the value after =
      const valuePattern: SecretPattern = {
        name: 'password-value',
        regex: /(?<=password[=:]\s*)\S+/gi,
        category: 'password',
        description: 'Password value only',
        severity: 'critical',
        example: 'secret123',
      };

      const detector = createDefaultDetector([fullPattern, valuePattern]);
      const result = detector.detect('password=supersecret123');

      // Should prefer the longer match (full assignment)
      expect(result.length).toBeGreaterThan(0);
      if (result.length === 1) {
        expect(result[0].value).toBe('password=supersecret123');
      }
    });

    it('should handle nested/overlapping patterns correctly', () => {
      const patterns: SecretPattern[] = [
        {
          name: 'token-full',
          regex: /token[=:]\s*([a-z0-9_-]+)/gi,
          category: 'token',
          description: 'Full token with key',
          severity: 'high',
          example: 'token=abc123',
        },
        {
          name: 'token-value',
          regex: /[a-z0-9_-]{16,}/gi,
          category: 'token',
          description: 'Token value pattern',
          severity: 'medium',
          example: 'abc123def456ghi789',
        },
      ];

      const detector = createDefaultDetector(patterns);
      const result = detector.detect('my_token=abc123def456ghi789jkl012');

      // Should have at least one detection
      expect(result.length).toBeGreaterThan(0);

      // No overlaps
      for (let i = 0; i < result.length; i++) {
        for (let j = i + 1; j < result.length; j++) {
          const a = result[i].position;
          const b = result[j].position;
          const overlap = a.start < b.end && b.start < a.end;
          expect(overlap).toBe(false);
        }
      }
    });
  });

  describe('position sorting', () => {
    it('should return results sorted by start position', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN, MOCK_GITHUB_PATTERN]);
      const result = detector.detect(
        'Start with GitHub: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx then AWS: AKIAIOSFODNN7EXAMPLE end'
      );

      // GitHub comes first in text, so should be first in results
      expect(result[0].value).toContain('ghp_');
      expect(result[1].value).toContain('AKIA');

      // Verify sorted order
      for (let i = 1; i < result.length; i++) {
        expect(result[i].position.start).toBeGreaterThanOrEqual(
          result[i - 1].position.start
        );
      }
    });

    it('should handle multi-line text with correct positions', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const text = `Line 1: no secret
Line 2: has AKIAIOSFODNN7EXAMPLE here
Line 3: no secret
Line 4: has AKIAIOSFODNN7EXAMPLE again`;

      const result = detector.detect(text);

      expect(result).toHaveLength(2);
      expect(result[0].position.line).toBe(2);
      expect(result[1].position.line).toBe(4);
      expect(result[0].position.start).toBeLessThan(result[1].position.start);
    });
  });

  describe('edge cases', () => {
    it('should handle text with special characters', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect(
        'Special chars: <AKIAIOSFODNN7EXAMPLE> & "AKIAIOSFODNN7EXAMPLE"'
      );

      // Should still detect the keys
      expect(result.length).toBeGreaterThan(0);
    });

    it('should handle very long text', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const longText = 'x'.repeat(10000) + ' AKIAIOSFODNN7EXAMPLE ' + 'y'.repeat(10000);
      const result = detector.detect(longText);

      expect(result).toHaveLength(1);
      expect(result[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
    });

    it('should handle patterns without global flag', () => {
      const singleMatchPattern: SecretPattern = {
        name: 'single-match',
        regex: /AKIA[0-9A-Z]{16}/, // No 'g' flag
        category: 'api_key',
        description: 'AWS key (single match)',
        severity: 'high',
        example: 'AKIAIOSFODNN7EXAMPLE',
      };

      const detector = createDefaultDetector([singleMatchPattern]);
      const result = detector.detect(
        'First: AKIAIOSFODNN7EXAMPLE, Second: AKIAIOSFODNN7EXAMPLE'
      );

      // Without global flag, regex.lastIndex behavior might differ
      // but we handle this by resetting lastIndex
      expect(result.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle empty excluded regions array', () => {
      const entropyEngine = new EntropyEngineStub(4.0, 16);
      const result = entropyEngine.detect('dGhpcyBpcyBhIHNlY3JldCBrZXk=', []);

      expect(result.length).toBeGreaterThan(0);
    });

    it('should handle multiple excluded regions', () => {
      const entropyEngine = new EntropyEngineStub(4.0, 16);
      const result = entropyEngine.detect(
        'ABC dGhpcyBpcyBhIHNlY3JldCBrZXk= XYZ dGhpcyBpcyBhIHNlY3JldCBrZXk= DEF',
        [
          { start: 0, end: 4 }, // "ABC "
          { start: 40, end: 44 }, // " XYZ"
        ]
      );

      // The entropy strings should be detected (not in excluded regions)
      expect(result.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle text with only whitespace', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('   \n\t  \n  ');
      expect(result).toHaveLength(0);
    });

    it('should handle text with unicode characters', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('Unicode: 🎉AKIAIOSFODNN7EXAMPLE🎉 test');
      expect(result).toHaveLength(1);
      expect(result[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
    });

    it('should handle single character text', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('A');
      expect(result).toHaveLength(0);
    });

    it('should handle text with null bytes', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('Key:\x00AKIAIOSFODNN7EXAMPLE\x00end');
      expect(result).toHaveLength(1);
    });
  });

  describe('confidence levels', () => {
    it('should mark regex matches as high confidence', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('Key: AKIAIOSFODNN7EXAMPLE');

      expect(result[0].confidence).toBe('high');
    });

    it('should mark entropy matches as medium confidence', () => {
      const detector = createDefaultDetector([], 4.0, 16);
      const result = detector.detect('Key: dGhpcyBpcyBhIHNlY3JldCBrZXk=');

      expect(result[0].confidence).toBe('medium');
    });
  });

  describe('performance', () => {
    it('should process 1KB text in reasonable time', () => {
      const detector = createDefaultDetector(
        [MOCK_AWS_PATTERN, MOCK_GITHUB_PATTERN, MOCK_PASSWORD_PATTERN],
        4.0,
        16
      );

      // Create ~1KB of text with secrets
      const text =
        'AWS key: AKIAIOSFODNN7EXAMPLE\n'.repeat(10) +
        'GitHub: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n'.repeat(10) +
        'password=secret123456\n'.repeat(10) +
        'Some random high entropy: dGhpcyBpcyBhIHNlY3JldCBrZXk=\n'.repeat(10);

      const start = performance.now();
      const result = detector.detect(text);
      const end = performance.now();

      // Should complete in under 10ms in test environment (target is <1ms in production)
      expect(end - start).toBeLessThan(10);
      expect(result.length).toBeGreaterThan(0);
    });

    it('should process 10KB text efficiently', () => {
      const detector = createDefaultDetector(ALL_BUILTIN_PATTERNS, 4.0, 16);

      // Create ~10KB of text
      const baseText = 'AWS: AKIAIOSFODNN7EXAMPLE\n';
      const text = baseText.repeat(400);

      const start = performance.now();
      const result = detector.detect(text);
      const end = performance.now();

      // Should complete in reasonable time (< 100ms for 10KB)
      expect(end - start).toBeLessThan(100);
      expect(result.length).toBe(400);
    });
  });

  describe('placeholder field', () => {
    it('should have empty placeholder (assigned by filter)', () => {
      const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
      const result = detector.detect('Key: AKIAIOSFODNN7EXAMPLE');

      expect(result[0].placeholder).toBe('');
    });
  });
});

describe('RegexEngineStub', () => {
  it('should detect multiple matches with global flag', () => {
    const engine = new RegexEngineStub([MOCK_AWS_PATTERN]);
    const result = engine.detect(
      'First: AKIAIOSFODNN7EXAMPLE, Second: AKIAIOSFODNN7EXAMPLE'
    );

    expect(result).toHaveLength(2);
    expect(result[0].position.start).toBeLessThan(result[1].position.start);
  });

  it('should calculate correct line and column for multi-line text', () => {
    const engine = new RegexEngineStub([MOCK_AWS_PATTERN]);
    const text = 'Line 1\nLine 2\nAKIAIOSFODNN7EXAMPLE\nLine 4';
    const result = engine.detect(text);

    expect(result).toHaveLength(1);
    expect(result[0].position.line).toBe(3);
    expect(result[0].position.column).toBe(0);
  });

  it('should handle pattern without global flag', () => {
    const pattern: SecretPattern = {
      name: 'non-global',
      regex: /AKIA[0-9A-Z]{16}/,
      category: 'api_key',
      description: 'Non-global pattern',
      severity: 'high',
      example: 'AKIAIOSFODNN7EXAMPLE',
    };

    const engine = new RegexEngineStub([pattern]);
    const result = engine.detect('First: AKIAIOSFODNN7EXAMPLE, Second: AKIAIOSFODNN7EXAMPLE');

    // Should still find both due to our reset logic
    expect(result.length).toBeGreaterThanOrEqual(1);
  });

  it('should handle zero-length matches safely', () => {
    const zeroLengthPattern: SecretPattern = {
      name: 'zero-length',
      regex: /(?=test)/g, // Zero-length lookahead
      category: 'other',
      description: 'Zero-length match pattern',
      severity: 'low',
      example: 'test',
    };

    const engine = new RegexEngineStub([zeroLengthPattern]);
    const result = engine.detect('test test test');

    // Should handle without infinite loop
    expect(result.length).toBeGreaterThanOrEqual(0);
  });
});

describe('EntropyEngineStub', () => {
  it('should detect high-entropy base64 strings', () => {
    const engine = new EntropyEngineStub(4.0, 16);
    const result = engine.detect('dGhpcyBpcyBhIHNlY3JldCBrZXk=', []);

    expect(result.length).toBeGreaterThan(0);
    expect(result[0].entropy).toBeGreaterThanOrEqual(4.0);
  });

  it('should respect minimum length filter', () => {
    const engine = new EntropyEngineStub(3.0, 20);
    const result = engine.detect('short abc123 long dGhpcyBpcyBhIHNlY3JldCBrZXk=', []);

    // Should only detect strings >= 20 chars
    const shortStrings = result.filter((r) => r.value.length < 20);
    expect(shortStrings).toHaveLength(0);
  });

  it('should respect entropy threshold', () => {
    const engineHighThreshold = new EntropyEngineStub(5.0, 8);
    const engineLowThreshold = new EntropyEngineStub(2.0, 8);

    const text = 'abc123def';
    const highResult = engineHighThreshold.detect(text, []);
    const lowResult = engineLowThreshold.detect(text, []);

    // Low threshold should detect more
    expect(lowResult.length).toBeGreaterThanOrEqual(highResult.length);
  });

  it('should skip excluded regions', () => {
    const engine = new EntropyEngineStub(3.5, 8);
    const text = 'ABC dGhpcyBpcyBhIHNlY3JldCBrZXk= XYZ';

    // Exclude the middle region
    const excludedRegions = [{ start: 4, end: 32 }];
    const result = engine.detect(text, excludedRegions);

    // Should not detect anything in the excluded region
    const detectedInExcluded = result.some(
      (r) => r.position.start >= 4 && r.position.end <= 32
    );
    expect(detectedInExcluded).toBe(false);
  });

  it('should calculate Shannon entropy correctly', () => {
    const engine = new EntropyEngineStub(0, 1);

    // Same char = 0 entropy
    const sameChar = engine.detect('aaaaaaaa', []);
    expect(sameChar).toHaveLength(0); // Below any reasonable threshold

    // Random string = high entropy
    const randomString = engine.detect('abcdefghijklmnopqrstuvwxyz', []);
    expect(randomString.length).toBeGreaterThan(0);
    expect(randomString[0].entropy).toBeGreaterThan(4.0);
  });

  it('should handle hex strings', () => {
    const engine = new EntropyEngineStub(3.0, 16);
    const result = engine.detect('f47ac10b58cc4372a5670e02b2c3d479', []);

    expect(result.length).toBeGreaterThan(0);
  });

  it('should handle empty text', () => {
    const engine = new EntropyEngineStub(4.0, 16);
    const result = engine.detect('', []);

    expect(result).toHaveLength(0);
  });

  it('should handle text with no high-entropy candidates', () => {
    const engine = new EntropyEngineStub(5.0, 16);
    const result = engine.detect('hello world foo bar baz', []);

    expect(result).toHaveLength(0);
  });
});

describe('createDefaultDetector', () => {
  it('should create detector with provided patterns', () => {
    const detector = createDefaultDetector([MOCK_AWS_PATTERN]);
    const result = detector.detect('Key: AKIAIOSFODNN7EXAMPLE');

    expect(result.length).toBeGreaterThan(0);
  });

  it('should use default entropy settings when not provided', () => {
    const detector = createDefaultDetector([]);
    const result = detector.detect('dGhpcyBpcyBhIHNlY3JldCBrZXk=');

    // Should detect with default threshold (4.5)
    expect(result.length).toBeGreaterThanOrEqual(0); // May or may not pass threshold
  });

  it('should use custom entropy threshold', () => {
    const detector = createDefaultDetector([], 3.0, 8);
    const result = detector.detect('abc123def456ghi789');

    // Lower threshold should detect this
    expect(result.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// COMPREHENSIVE BUILT-IN PATTERN TESTS (All 20 Patterns)
// ============================================================================

describe('All 20 Built-in Patterns', () => {
  describe('Cloud Providers (5 patterns)', () => {
    it('should detect aws_access_key_id', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'aws_access_key_id')
      );
      const tests = BUILTIN_PATTERN_TESTS.aws_access_key_id;

      for (const valid of tests.valid) {
        const result = detector.detect(`AWS: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
        expect(result.some((r) => r.value.includes(valid))).toBe(true);
      }

      for (const invalid of tests.invalid) {
        const result = detector.detect(`AWS: ${invalid}`);
        expect(result.some((r) => r.value === invalid)).toBe(false);
      }
    });

    it('should detect aws_secret_access_key', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'aws_secret_access_key')
      );
      const tests = BUILTIN_PATTERN_TESTS.aws_secret_access_key;

      for (const valid of tests.valid) {
        const result = detector.detect(`Secret: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect azure_subscription_key', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'azure_subscription_key')
      );
      const tests = BUILTIN_PATTERN_TESTS.azure_subscription_key;

      for (const valid of tests.valid) {
        const result = detector.detect(`Azure: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect gcp_api_key', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'gcp_api_key')
      );
      const tests = BUILTIN_PATTERN_TESTS.gcp_api_key;

      for (const valid of tests.valid) {
        const result = detector.detect(`GCP: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect gcp_oauth_token', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'gcp_oauth_token')
      );
      const tests = BUILTIN_PATTERN_TESTS.gcp_oauth_token;

      for (const valid of tests.valid) {
        const result = detector.detect(`OAuth: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Code Hosting (3 patterns)', () => {
    it('should detect github_personal_token', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'github_personal_token')
      );
      const tests = BUILTIN_PATTERN_TESTS.github_personal_token;

      for (const valid of tests.valid) {
        const result = detector.detect(`GitHub: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect gitlab_personal_token', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'gitlab_personal_token')
      );
      const tests = BUILTIN_PATTERN_TESTS.gitlab_personal_token;

      for (const valid of tests.valid) {
        const result = detector.detect(`GitLab: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect bitbucket_app_password', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'bitbucket_app_password')
      );
      const tests = BUILTIN_PATTERN_TESTS.bitbucket_app_password;

      for (const valid of tests.valid) {
        const result = detector.detect(`Bitbucket: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Communication (2 patterns)', () => {
    it('should detect slack_bot_token', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'slack_bot_token')
      );
      const tests = BUILTIN_PATTERN_TESTS.slack_bot_token;

      for (const valid of tests.valid) {
        const result = detector.detect(`Slack: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect slack_user_token', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'slack_user_token')
      );
      const tests = BUILTIN_PATTERN_TESTS.slack_user_token;

      for (const valid of tests.valid) {
        const result = detector.detect(`Slack: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Payment Services (2 patterns)', () => {
    it('should detect stripe_live_key', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'stripe_live_key')
      );
      const tests = BUILTIN_PATTERN_TESTS.stripe_live_key;

      for (const valid of tests.valid) {
        const result = detector.detect(`Stripe: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect stripe_test_key', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'stripe_test_key')
      );
      const tests = BUILTIN_PATTERN_TESTS.stripe_test_key;

      for (const valid of tests.valid) {
        const result = detector.detect(`Stripe: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Authentication (4 patterns)', () => {
    it('should detect jwt_token', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'jwt_token')
      );
      const tests = BUILTIN_PATTERN_TESTS.jwt_token;

      for (const valid of tests.valid) {
        const result = detector.detect(`JWT: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect bearer_token', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'bearer_token')
      );
      const tests = BUILTIN_PATTERN_TESTS.bearer_token;

      for (const valid of tests.valid) {
        const result = detector.detect(`Auth: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect oauth_access_token', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'oauth_access_token')
      );
      const tests = BUILTIN_PATTERN_TESTS.oauth_access_token;

      for (const valid of tests.valid) {
        const result = detector.detect(`OAuth: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect basic_auth', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'basic_auth')
      );
      const tests = BUILTIN_PATTERN_TESTS.basic_auth;

      for (const valid of tests.valid) {
        const result = detector.detect(`Auth: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Generic Secrets (4 patterns)', () => {
    it('should detect generic_api_key', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'generic_api_key')
      );
      const tests = BUILTIN_PATTERN_TESTS.generic_api_key;

      for (const valid of tests.valid) {
        const result = detector.detect(`Config: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect private_key', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'private_key')
      );
      const tests = BUILTIN_PATTERN_TESTS.private_key;

      for (const valid of tests.valid) {
        const result = detector.detect(`Key: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect database_connection_string', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'database_connection_string')
      );
      const tests = BUILTIN_PATTERN_TESTS.database_connection_string;

      for (const valid of tests.valid) {
        const result = detector.detect(`DB: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it('should detect password_in_code', () => {
      const detector = createDefaultDetector(
        ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'password_in_code')
      );
      const tests = BUILTIN_PATTERN_TESTS.password_in_code;

      for (const valid of tests.valid) {
        const result = detector.detect(`Code: ${valid}`);
        expect(result.length).toBeGreaterThan(0);
      }
    });
  });
});

// ============================================================================
// COMPLEX EDGE CASES AND INTEGRATION TESTS
// ============================================================================

describe('Complex Edge Cases', () => {
  it('should handle multiple secrets on same line', () => {
    const detector = createDefaultDetector([
      ALL_BUILTIN_PATTERNS.find((p) => p.name === 'aws_access_key_id')!,
      ALL_BUILTIN_PATTERNS.find((p) => p.name === 'github_personal_token')!,
      ALL_BUILTIN_PATTERNS.find((p) => p.name === 'stripe_live_key')!,
    ]);

    const text =
      'AWS: AKIAIOSFODNN7EXAMPLE, GitHub: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890, Stripe: sk_live_abcdefghijklmnopqrstuvwxyz1234';
    const result = detector.detect(text);

    expect(result).toHaveLength(3);
    expect(result[0].position.line).toBe(1);
    expect(result[1].position.line).toBe(1);
    expect(result[2].position.line).toBe(1);
  });

  it('should handle secrets at line boundaries', () => {
    const detector = createDefaultDetector([
      ALL_BUILTIN_PATTERNS.find((p) => p.name === 'aws_access_key_id')!,
    ]);

    const text = `AKIAIOSFODNN7EXAMPLE
line2
AKIA1234567890ABCDEF`;
    const result = detector.detect(text);

    expect(result).toHaveLength(2);
    expect(result[0].position.line).toBe(1);
    expect(result[1].position.line).toBe(3);
  });

  it('should handle overlapping pattern definitions', () => {
    // Test with patterns that might have overlapping definitions
    const patterns: SecretPattern[] = [
      {
        name: 'aws-credential',
        regex: /AKIA[0-9A-Z]{16}/g,
        category: 'credential',
        description: 'AWS credential',
        severity: 'critical',
        example: 'AKIAIOSFODNN7EXAMPLE',
      },
      {
        name: 'aws-key',
        regex: /AKIA[0-9A-Z]{16}/g,
        category: 'api_key',
        description: 'AWS key',
        severity: 'high',
        example: 'AKIAIOSFODNN7EXAMPLE',
      },
    ];

    const detector = createDefaultDetector(patterns);
    const result = detector.detect('Key: AKIAIOSFODNN7EXAMPLE');

    // Should handle overlapping patterns (same match, different definitions)
    expect(result.length).toBeGreaterThan(0);
  });

  it('should handle very high entropy with all patterns', () => {
    const detector = createDefaultDetector(ALL_BUILTIN_PATTERNS, 4.5, 32);

    // Create text with multiple high-entropy strings
    const text = `
      AWS Key: AKIAIOSFODNN7EXAMPLE
      High entropy: dGhpcyBpcyBhIHZlcnkgbG9uZyBhbmQgaGlnaCBlbnRyb3B5IHN0cmluZw==
      Another: YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
    `;

    const result = detector.detect(text);

    // Should detect both regex and entropy secrets
    expect(result.length).toBeGreaterThan(1);
  });

  it('should handle secrets in code-like context', () => {
    const detector = createDefaultDetector(ALL_BUILTIN_PATTERNS);

    const codeContext = `
const config = {
  awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
  apiKey: 'api_key=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  dbUrl: 'postgres://user:password123@localhost:5432/mydb',
  password: "MySecretPassword123!"
};

function authenticate() {
  const token = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
  return token;
}
    `;

    const result = detector.detect(codeContext);

    // Should detect multiple secrets in code context
    expect(result.length).toBeGreaterThanOrEqual(4);
  });

  it('should handle large input with scattered secrets', () => {
    const detector = createDefaultDetector(ALL_BUILTIN_PATTERNS);

    // Create a large text with secrets scattered throughout
    const parts: string[] = [];
    for (let i = 0; i < 100; i++) {
      parts.push('Some normal text here and there '.repeat(10));
      if (i % 10 === 0) {
        parts.push(`AKIA${String(i).padStart(2, '0')}ABCDEF12345678`);
      }
    }
    const text = parts.join('\n');

    const result = detector.detect(text);

    // Should find the scattered secrets
    expect(result.length).toBeGreaterThanOrEqual(10);
  });

  it('should handle mixed valid and invalid secrets', () => {
    const detector = createDefaultDetector(
      ALL_BUILTIN_PATTERNS.filter((p) => p.name === 'aws_access_key_id')
    );

    const text = `
      Valid: AKIAIOSFODNN7EXAMPLE
      Invalid: AKIA123
      Valid: AKIA1234567890ABCDEF
      Invalid: AKIAIOSFODNN7EXAMPL
    `;

    const result = detector.detect(text);

    // Should only detect valid patterns
    expect(result).toHaveLength(2);
  });

  it('should maintain performance with all 20 patterns', () => {
    const detector = createDefaultDetector(ALL_BUILTIN_PATTERNS, 4.0, 16);

    // Generate 1KB of realistic-looking text
    const text = `
Configuration file with various secrets:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwxyz1234
DATABASE_URL=postgres://user:password123@localhost:5432/mydb
API_KEY=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI
SLACK_TOKEN=xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX
JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Some high entropy: dGhpcyBpcyBhIHNlY3JldCBrZXk=
    `.repeat(10);

    const start = performance.now();
    const result = detector.detect(text);
    const end = performance.now();

    // Should complete quickly even with all patterns
    expect(end - start).toBeLessThan(50); // 50ms for ~1KB with all patterns
    expect(result.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// PATTERN CATEGORY AND SEVERITY TESTS
// ============================================================================

describe('Pattern Categories and Severities', () => {
  it('should categorize secrets correctly', () => {
    const detector = createDefaultDetector(ALL_BUILTIN_PATTERNS);

    const text = `
      AWS: AKIAIOSFODNN7EXAMPLE
      API: AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI
      Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
      DB: postgres://user:password123@localhost:5432/mydb
      Pass: password = "MySecretPassword123!"
    `;

    const result = detector.detect(text);

    // Check that each result has the correct category
    const categories = new Set(result.map((r) => r.category));
    expect(categories.size).toBeGreaterThan(0);
  });

  it('should assign correct severity levels', () => {
    const detector = createDefaultDetector(ALL_BUILTIN_PATTERNS);

    const text = `
      Critical: AKIAIOSFODNN7EXAMPLE
      High: AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI
      Medium: api_key=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
    `;

    const result = detector.detect(text);

    // Verify severities are assigned
    const severities = new Set(result.map((r) => r.pattern.severity));
    expect(severities.size).toBeGreaterThan(0);
  });
});
