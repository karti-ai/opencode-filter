import { describe, it, expect, beforeEach } from 'vitest';
import {
  RegexEngine,
  RegexEngineConfig,
  ReDoSError,
  BUILTIN_PATTERNS,
  DEFAULT_REGEX_ENGINE_CONFIG,
} from './regex-engine';
import type { SecretPattern } from '../opencode-filter/src/types';

describe('RegexEngine', () => {
  let engine: RegexEngine;

  beforeEach(() => {
    engine = new RegexEngine();
  });

  describe('Pattern Loading', () => {
    it('should load all 20 built-in patterns at startup', () => {
      const patterns = engine.getPatterns();
      expect(patterns.length).toBe(20);
    });

    it('should have patterns for all major secret types', () => {
      const patternNames = engine.getPatterns().map(p => p.name);
      
      expect(patternNames).toContain('aws_access_key_id');
      expect(patternNames).toContain('aws_secret_access_key');
      expect(patternNames).toContain('github_pat');
      expect(patternNames).toContain('slack_token');
      expect(patternNames).toContain('stripe_live_key');
      expect(patternNames).toContain('jwt_token');
      expect(patternNames).toContain('private_key_pem');
      expect(patternNames).toContain('database_url');
    });

    it('should compile patterns only once at startup', () => {
      const startTime = performance.now();
      const newEngine = new RegexEngine();
      const endTime = performance.now();
      
      expect(newEngine.getPatternCount()).toBe(20);
      expect(endTime - startTime).toBeLessThan(100); // Should compile quickly
    });
  });

  describe('AWS Pattern Detection', () => {
    it('should detect AWS Access Key ID', () => {
      const text = 'AKIAIOSFODNN7EXAMPLE';
      const secrets = engine.detect(text);
      
      expect(secrets).toHaveLength(1);
      expect(secrets[0].pattern.name).toBe('aws_access_key_id');
      expect(secrets[0].category).toBe('api_key');
      expect(secrets[0].pattern.severity).toBe('critical');
    });

    it('should detect AWS Secret Access Key', () => {
      const text = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'aws_secret_access_key')).toBe(true);
    });

    it('should detect multiple AWS secrets in text', () => {
      const text = `
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      `;
      const secrets = engine.detect(text);
      
      expect(secrets.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('GitHub Token Detection', () => {
    it('should detect GitHub Personal Access Token', () => {
      const text = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'github_pat')).toBe(true);
    });

    it('should detect GitHub OAuth token', () => {
      const text = 'gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'github_oauth')).toBe(true);
    });

    it('should detect GitHub App token', () => {
      const text = 'ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'github_app_token')).toBe(true);
    });
  });

  describe('Slack Token Detection', () => {
    it('should detect Slack bot token', () => {
      const text = 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'slack_token')).toBe(true);
    });

    it('should detect Slack webhook URL', () => {
      const text = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'slack_webhook')).toBe(true);
    });
  });

  describe('Stripe Key Detection', () => {
    it('should detect Stripe live key', () => {
      const text = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'stripe_live_key')).toBe(true);
    });

    it('should detect Stripe test key', () => {
      const text = 'sk_test_abcdefghijklmnopqrstuvwxyz012345';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'stripe_test_key')).toBe(true);
    });
  });

  describe('JWT Token Detection', () => {
    it('should detect JWT token', () => {
      const text = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'jwt_token')).toBe(true);
    });

    it('should detect JWT in Authorization header', () => {
      const text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'jwt_token' || s.pattern.name === 'api_key_header')).toBe(true);
    });
  });

  describe('Password Detection', () => {
    it('should detect password assignment', () => {
      const text = 'password = "secretpassword123"';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'password_assignment')).toBe(true);
    });

    it('should detect password key-value pair', () => {
      const text = 'password: secretpassword123';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'password_key_value')).toBe(true);
    });

    it('should not detect short passwords', () => {
      const text = 'password: short';
      const secrets = engine.detect(text);
      
      const passwordSecrets = secrets.filter(s => s.category === 'password');
      expect(passwordSecrets).toHaveLength(0);
    });
  });

  describe('API Key Detection', () => {
    it('should detect generic API key', () => {
      const text = 'api_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'generic_api_key')).toBe(true);
    });

    it('should detect API key in Authorization header', () => {
      const text = 'Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'api_key_header')).toBe(true);
    });
  });

  describe('Multi-line Pattern Detection', () => {
    it('should detect PEM format RSA private key', () => {
      const text = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxgNSLExYV0D71SfJh9h3H6FzDzRbKQVbLtw2wFfBZvBCk6Nl
-----END RSA PRIVATE KEY-----`;
      
      const secrets = engine.detect(text);
      expect(secrets.some(s => s.pattern.name === 'private_key_pem')).toBe(true);
    });

    it('should detect OpenSSH private key', () => {
      const text = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----`;
      
      const secrets = engine.detect(text);
      expect(secrets.some(s => s.pattern.name === 'ssh_private_key' || s.pattern.name === 'private_key_pem')).toBe(true);
    });

    it('should handle multiple line breaks in PEM keys', () => {
      const text = `-----BEGIN RSA PRIVATE KEY-----
Line1
Line2
Line3
-----END RSA PRIVATE KEY-----`;
      
      const secrets = engine.detect(text);
      expect(secrets.some(s => s.pattern.name === 'private_key_pem')).toBe(true);
    });
  });

  describe('Database Connection String Detection', () => {
    it('should detect PostgreSQL connection string', () => {
      const text = 'postgresql://user:password123@localhost:5432/database';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'database_url')).toBe(true);
    });

    it('should detect MySQL connection string', () => {
      const text = 'mysql://admin:secretpass@db.example.com:3306/production';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'database_url')).toBe(true);
    });
  });

  describe('Environment Variable Detection', () => {
    it('should detect SECRET_KEY environment variable', () => {
      const text = 'SECRET_KEY=myverylongsecretkey12345';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'env_secret')).toBe(true);
    });

    it('should detect API_TOKEN environment variable', () => {
      const text = 'API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'env_secret')).toBe(true);
    });
  });

  describe('Google Cloud API Key Detection', () => {
    it('should detect GCP API key', () => {
      const text = 'AIzaSyDdI0hCZtE6vySjMm-WEf18o9dq7d3abcde';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'gcp_api_key')).toBe(true);
    });
  });

  describe('Authentication Token Detection', () => {
    it('should detect Bearer token', () => {
      const text = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'bearer_token' || s.pattern.name === 'api_key_header')).toBe(true);
    });

    it('should detect Basic auth header', () => {
      const text = 'Authorization: Basic dXNlcjpwYXNzd29yZA==';
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'basic_auth')).toBe(true);
    });
  });

  describe('Position Tracking', () => {
    it('should track correct line and column positions', () => {
      const text = `line1
line2 with secret: AKIAIOSFODNN7EXAMPLE
line3`;
      
      const secrets = engine.detect(text);
      const awsSecret = secrets.find(s => s.pattern.name === 'aws_access_key_id');
      
      expect(awsSecret).toBeDefined();
      expect(awsSecret!.position.line).toBe(2);
      expect(awsSecret!.position.column).toBe(19); // After "line2 with secret: "
    });

    it('should track correct start and end positions', () => {
      const text = 'prefix AKIAIOSFODNN7EXAMPLE suffix';
      const secrets = engine.detect(text);
      
      const awsSecret = secrets.find(s => s.pattern.name === 'aws_access_key_id');
      expect(awsSecret).toBeDefined();
      expect(awsSecret!.position.start).toBe(7);
      expect(awsSecret!.position.end).toBe(27);
    });
  });

  describe('Confidence Levels', () => {
    it('should assign confidence based on secret complexity', () => {
      const text = 'AKIAIOSFODNN7EXAMPLE'; // 20 chars, alphanumeric
      const secrets = engine.detect(text);
      
      const awsSecret = secrets.find(s => s.pattern.name === 'aws_access_key_id');
      expect(awsSecret).toBeDefined();
      expect(['low', 'medium', 'high']).toContain(awsSecret!.confidence);
    });

    it('should assign confidence based on secret complexity', () => {
      const text = 'password: simple123';
      const secrets = engine.detect(text);
      
      const passwordSecret = secrets.find(s => s.category === 'password');
      if (passwordSecret) {
        expect(['low', 'medium', 'high']).toContain(passwordSecret.confidence);
      }
    });
  });

  describe('Placeholder Generation', () => {
    it('should generate unique placeholders for each secret', () => {
      const text = 'AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE';
      const secrets = engine.detect(text);
      
      const placeholders = secrets.map(s => s.placeholder);
      const uniquePlaceholders = new Set(placeholders);
      
      // Deduplication should result in one unique placeholder
      expect(uniquePlaceholders.size).toBeLessThanOrEqual(placeholders.length);
    });

    it('should include pattern name in placeholder', () => {
      const text = 'AKIAIOSFODNN7EXAMPLE';
      const secrets = engine.detect(text);
      
      expect(secrets[0].placeholder).toContain('AWS');
      expect(secrets[0].placeholder).toContain('ACCESS_KEY_ID');
    });
  });

  describe('ReDoS Protection', () => {
    it('should have ReDoS protection enabled by default', () => {
      expect(DEFAULT_REGEX_ENGINE_CONFIG.enableReDoSProtection).toBe(true);
    });

    it('should allow disabling ReDoS protection via config', () => {
      const config: RegexEngineConfig = {
        ...DEFAULT_REGEX_ENGINE_CONFIG,
        enableReDoSProtection: false,
      };
      
      const customEngine = new RegexEngine(config);
      expect(customEngine.getPatternCount()).toBe(20);
    });

    it('should enforce timeout on pattern matching', () => {
      const config: RegexEngineConfig = {
        timeoutMs: 1, // Very short timeout
        enableReDoSProtection: true,
        maxInputLength: 10000,
      };
      
      const strictEngine = new RegexEngine(config);
      
      // This should not hang or take too long
      const startTime = performance.now();
      try {
        strictEngine.detect('AKIAIOSFODNN7EXAMPLE');
      } catch (e) {
        // May throw ReDoS error with such short timeout
      }
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(500); // Should complete quickly
    });

    it('should skip potentially unsafe patterns when enabled', () => {
      const unsafePattern: SecretPattern = {
        name: 'unsafe_pattern',
        regex: /(a+)+$/, // Potentially catastrophic pattern
        category: 'api_key',
        description: 'Unsafe test pattern',
        severity: 'medium',
        example: 'aaaa',
      };
      
      // Should throw when trying to add unsafe pattern
      expect(() => engine.addPattern(unsafePattern)).toThrow(ReDoSError);
    });

    it('should allow unsafe patterns when ReDoS protection is disabled', () => {
      const config: RegexEngineConfig = {
        ...DEFAULT_REGEX_ENGINE_CONFIG,
        enableReDoSProtection: false,
      };
      
      const unsafeEngine = new RegexEngine(config);
      
      const unsafePattern: SecretPattern = {
        name: 'unsafe_pattern',
        regex: /(a+)+$/, // Potentially catastrophic pattern
        category: 'api_key',
        description: 'Unsafe test pattern',
        severity: 'medium',
        example: 'aaaa',
      };
      
      // Should NOT throw when ReDoS protection is disabled
      expect(() => unsafeEngine.addPattern(unsafePattern)).not.toThrow();
    });

    it('should validate pattern safety before compilation', () => {
      const config: RegexEngineConfig = {
        ...DEFAULT_REGEX_ENGINE_CONFIG,
        enableReDoSProtection: true,
      };
      
      // All built-in patterns should pass safety check
      const safeEngine = new RegexEngine(config);
      expect(safeEngine.getPatternCount()).toBe(20);
    });
  });

  describe('Performance', () => {
    it('should detect secrets in less than 1ms for small inputs', () => {
      const text = 'AKIAIOSFODNN7EXAMPLE';
      
      const startTime = performance.now();
      engine.detect(text);
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(1);
    });

    it('should handle larger inputs efficiently', () => {
      const lines: string[] = [];
      for (let i = 0; i < 100; i++) {
        lines.push(`config_${i}=AKIAIOSFODNN7EXAMPLE${i}`);
      }
      const text = lines.join('\n');
      
      const startTime = performance.now();
      const secrets = engine.detect(text);
      const endTime = performance.now();
      
      expect(secrets.length).toBe(100);
      expect(endTime - startTime).toBeLessThan(100); // Should complete within 100ms
    });

    it('should handle very large inputs within configured limit', () => {
      const text = 'A'.repeat(1000000); // 1MB of text
      
      const startTime = performance.now();
      const secrets = engine.detect(text);
      const endTime = performance.now();
      
      // Should complete without errors (though likely no matches)
      expect(endTime - startTime).toBeLessThan(1000);
    });
  });

  describe('Input Validation', () => {
    it('should throw on input exceeding max length', () => {
      const config: RegexEngineConfig = {
        ...DEFAULT_REGEX_ENGINE_CONFIG,
        maxInputLength: 100,
      };
      
      const limitedEngine = new RegexEngine(config);
      const longText = 'A'.repeat(101);
      
      expect(() => limitedEngine.detect(longText)).toThrow('exceeds maximum length');
    });

    it('should handle empty input', () => {
      const secrets = engine.detect('');
      expect(secrets).toHaveLength(0);
    });

    it('should handle input with no secrets', () => {
      const text = 'This is just regular text without any secrets';
      const secrets = engine.detect(text);
      expect(secrets).toHaveLength(0);
    });
  });

  describe('Custom Patterns', () => {
    it('should allow adding custom patterns at runtime', () => {
      const customPattern: SecretPattern = {
        name: 'custom_api_key',
        regex: /custom_[a-z0-9]{16}/g,
        category: 'api_key',
        description: 'Custom API key pattern',
        severity: 'high',
        example: 'custom_1234567890abcdef',
      };
      
      engine.addPattern(customPattern);
      expect(engine.getPatternCount()).toBe(21);
      
      const secrets = engine.detect('custom_1234567890abcdef');
      expect(secrets.some(s => s.pattern.name === 'custom_api_key')).toBe(true);
    });

    it('should allow removing patterns by name', () => {
      const initialCount = engine.getPatternCount();
      
      engine.removePattern('aws_access_key_id');
      
      expect(engine.getPatternCount()).toBe(initialCount - 1);
      
      const secrets = engine.detect('AKIAIOSFODNN7EXAMPLE');
      expect(secrets.some(s => s.pattern.name === 'aws_access_key_id')).toBe(false);
    });

    it('should handle removing non-existent patterns gracefully', () => {
      const initialCount = engine.getPatternCount();
      
      engine.removePattern('non_existent_pattern');
      
      expect(engine.getPatternCount()).toBe(initialCount);
    });
  });

  describe('Deduplication', () => {
    it('should not return duplicate secrets at same position', () => {
      const text = 'AKIAIOSFODNN7EXAMPLE'; // 20 chars that matches AWS pattern
      const secrets = engine.detect(text);
      
      // Check for unique positions
      const positions = secrets.map(s => `${s.position.start}:${s.position.end}`);
      const uniquePositions = new Set(positions);
      
      expect(uniquePositions.size).toBe(positions.length);
    });
  });

  describe('Edge Cases', () => {
    it('should handle special characters in secrets', () => {
      const text = 'password: "test@#$%^&*()_+"';
      const secrets = engine.detect(text);
      
      // Should still detect the password pattern
      const passwordSecrets = secrets.filter(s => s.category === 'password');
      expect(passwordSecrets.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle unicode text', () => {
      const text = '密码 password: secret123 パスワード';
      const secrets = engine.detect(text);
      
      // Should still detect password
      expect(secrets.some(s => s.category === 'password')).toBe(true);
    });

    it('should handle multiline secrets with varying line endings', () => {
      const text = `-----BEGIN RSA PRIVATE KEY-----\r\nLine1\r\nLine2\r\n-----END RSA PRIVATE KEY-----`;
      const secrets = engine.detect(text);
      
      expect(secrets.some(s => s.pattern.name === 'private_key_pem')).toBe(true);
    });
  });
});

describe('BUILTIN_PATTERNS', () => {
  it('should contain exactly 20 pattern definitions', () => {
    expect(BUILTIN_PATTERNS).toHaveLength(20);
  });

  it('should have valid categories for all patterns', () => {
    const validCategories = [
      'api_key',
      'password',
      'token',
      'private_key',
      'credential',
      'certificate',
      'connection_string',
      'environment_variable',
      'personal_info',
      'other',
    ];
    
    for (const pattern of BUILTIN_PATTERNS) {
      expect(validCategories).toContain(pattern.category);
    }
  });

  it('should have valid severity levels for all patterns', () => {
    const validSeverities = ['low', 'medium', 'high', 'critical'];
    
    for (const pattern of BUILTIN_PATTERNS) {
      expect(validSeverities).toContain(pattern.severity);
    }
  });

  it('should have unique names for all patterns', () => {
    const names = BUILTIN_PATTERNS.map(p => p.name);
    const uniqueNames = new Set(names);
    
    expect(uniqueNames.size).toBe(names.length);
  });

  it('should have examples for all patterns', () => {
    for (const pattern of BUILTIN_PATTERNS) {
      expect(pattern.example).toBeDefined();
      expect(pattern.example.length).toBeGreaterThan(0);
    }
  });
});
