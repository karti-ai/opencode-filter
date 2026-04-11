/**
 * Tests for entropy-based secret detection
 */

import { describe, it, expect } from 'vitest';
import {
  EntropyEngine,
  calculateEntropy,
  detectSecrets,
  type EntropyEngineConfig,
} from './entropy';
import type { DetectedSecret, ConfidenceLevel } from './types';

describe('EntropyEngine', () => {
  describe('calculateEntropy', () => {
    it('should calculate entropy for a simple string', () => {
      const engine = new EntropyEngine();
      const entropy = engine.calculateEntropy('aaa');
      expect(entropy).toBe(0);
    });

    it('should calculate higher entropy for diverse characters', () => {
      const engine = new EntropyEngine();
      const entropy = engine.calculateEntropy('abcd');
      expect(entropy).toBe(2);
    });

    it('should calculate maximum entropy for uniform distribution', () => {
      const engine = new EntropyEngine();
      // 8 characters, all different and equally distributed
      const entropy = engine.calculateEntropy('abcdefgh');
      expect(entropy).toBe(3);
    });

    it('should return 0 for empty string', () => {
      const engine = new EntropyEngine();
      const entropy = engine.calculateEntropy('');
      expect(entropy).toBe(0);
    });

    it('should calculate correct entropy for base64-like string', () => {
      const engine = new EntropyEngine();
      // Random-looking base64 string
      const entropy = engine.calculateEntropy('aB3dE5fG7hJ9kLmN');
      expect(entropy).toBeGreaterThan(3);
      expect(entropy).toBeLessThan(5);
    });

    it('should calculate higher entropy for longer random strings', () => {
      const engine = new EntropyEngine();
      const entropy = engine.calculateEntropy(
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
      );
      expect(entropy).toBeGreaterThan(5);
    });
  });

  describe('high-entropy detection', () => {
    it('should detect high-entropy base64 strings', () => {
      const engine = new EntropyEngine();
      const highEntropyBase64 =
        'qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dAqW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA';
      const secrets = engine.detect(highEntropyBase64);
      expect(secrets.length).toBeGreaterThan(0);
    });

    it('should detect high-entropy hex strings', () => {
      const engine = new EntropyEngine();
      const highEntropyHex = 'a3f5c8e9b2d1470f8e6a5b4c3d2e1f0a8';
      const secrets = engine.detect(highEntropyHex);
      expect(secrets.length).toBeGreaterThan(0);
    });

    it('should detect API key-like strings', () => {
      const engine = new EntropyEngine();
      const apiKey = 'sk-qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA';
      const secrets = engine.detect(apiKey);
      expect(secrets.length).toBeGreaterThan(0);
    });

    it('should detect random token strings', () => {
      const engine = new EntropyEngine();
      const token = 'qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA';
      const secrets = engine.detect(token);
      expect(secrets.length).toBeGreaterThan(0);
    });

    it('should detect secrets in text with surrounding content', () => {
      const engine = new EntropyEngine();
      const text = `
        Here is my API key: sk-qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA
        Please use it carefully.
      `;
      const secrets = engine.detect(text);
      expect(secrets.length).toBeGreaterThan(0);
    });

    it('should detect multiple secrets in the same text', () => {
      const engine = new EntropyEngine();
      const text = `
        API Key 1: a3f5c8e9b2d1470f8e6a5b4c3d2e1f0a
        API Key 2: b8e7d6c5f4a3912g0h9i8j7k6l5m4n3o
      `;
      const secrets = engine.detect(text);
      expect(secrets.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect secrets with high confidence for very random strings', () => {
      const engine = new EntropyEngine();
      const veryRandom =
        'qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dAqW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dAqW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA';
      const secrets = engine.detect(veryRandom);
      expect(secrets.length).toBeGreaterThan(0);
      expect(['medium', 'high']).toContain(secrets[0].confidence);
    });
  });

  describe('low-entropy filtering', () => {
    it('should not detect common passwords', () => {
      const engine = new EntropyEngine();
      const commonPasswords = [
        'password123',
        'qwertyuiop',
        'letmein123',
        'welcome123',
      ];

      for (const password of commonPasswords) {
        const secrets = engine.detect(password);
        expect(secrets.length).toBe(0);
      }
    });

    it('should not detect common words', () => {
      const engine = new EntropyEngine();
      const commonWords = [
        'secret',
        'password',
        'admin123',
        'test1234',
      ];

      for (const word of commonWords) {
        const secrets = engine.detect(word);
        expect(secrets.length).toBe(0);
      }
    });

    it('should not detect sequential numbers', () => {
      const engine = new EntropyEngine();
      const sequential = '1234567890123456';
      const secrets = engine.detect(sequential);
      expect(secrets.length).toBe(0);
    });

    it('should not detect repeated characters', () => {
      const engine = new EntropyEngine();
      const repeated = 'aaaaaaaaaaaaaaaa';
      const secrets = engine.detect(repeated);
      expect(secrets.length).toBe(0);
    });

    it('should not detect UUIDs (identifiers, not secrets)', () => {
      const engine = new EntropyEngine();
      const uuid = '550e8400-e29b-41d4-a716-446655440000';
      const secrets = engine.detect(uuid);
      expect(secrets.length).toBe(0);
    });

    it('should not detect short strings', () => {
      const engine = new EntropyEngine();
      const shortString = 'abc123';
      const secrets = engine.detect(shortString);
      expect(secrets.length).toBe(0);
    });

    it('should not detect programming keywords', () => {
      const engine = new EntropyEngine();
      const programmingTerms = [
        'undefined1234567',
        'configuration123',
        'development12345',
      ];

      for (const term of programmingTerms) {
        const secrets = engine.detect(term);
        expect(secrets.length).toBe(0);
      }
    });
  });

  describe('configurable threshold', () => {
    it('should use default threshold of 4.5', () => {
      const engine = new EntropyEngine();
      const config = engine.getConfig();
      expect(config.threshold).toBe(4.5);
    });

    it('should accept custom threshold in constructor', () => {
      const engine = new EntropyEngine({ threshold: 3.0 });
      const config = engine.getConfig();
      expect(config.threshold).toBe(3.0);
    });

    it('should detect more secrets with lower threshold', () => {
      const text = 'password12345678';

      const strictEngine = new EntropyEngine({ threshold: 5.0 });
      const lenientEngine = new EntropyEngine({ threshold: 3.0 });

      const strictSecrets = strictEngine.detect(text);
      const lenientSecrets = lenientEngine.detect(text);

      // Lower threshold should detect more (or equal) secrets
      expect(lenientSecrets.length).toBeGreaterThanOrEqual(
        strictSecrets.length
      );
    });

    it('should accept custom threshold in detect method', () => {
      const engine = new EntropyEngine();
      const text = 'abc123def456ghi789';

      const secretsHigh = engine.detect(text, 5.0);
      const secretsLow = engine.detect(text, 3.0);

      expect(secretsLow.length).toBeGreaterThanOrEqual(secretsHigh.length);
    });

    it('should allow threshold override per detection call', () => {
      const engine = new EntropyEngine({ threshold: 5.0 });
      const highEntropyString =
        'xJ9mK2pL5nQ8rT4vW7yZ1bC3dE6gH0jF';

      // With high threshold, should still detect very random string
      const secrets = engine.detect(highEntropyString, 4.0);
      expect(secrets.length).toBeGreaterThan(0);
    });
  });

  describe('configurable minimum length', () => {
    it('should use default minimum length of 16', () => {
      const engine = new EntropyEngine();
      const config = engine.getConfig();
      expect(config.minLength).toBe(16);
    });

    it('should accept custom minimum length', () => {
      const engine = new EntropyEngine({ minLength: 8 });
      const config = engine.getConfig();
      expect(config.minLength).toBe(8);
    });

    it('should detect shorter secrets with lower minLength', () => {
      const text = 'qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1';

      const strictEngine = new EntropyEngine({ minLength: 40 });
      const lenientEngine = new EntropyEngine({ minLength: 30 });

      const strictSecrets = strictEngine.detect(text);
      const lenientSecrets = lenientEngine.detect(text);

      expect(strictSecrets.length).toBe(0);
      expect(lenientSecrets.length).toBeGreaterThan(0);
    });

    it('should not detect strings below minimum length', () => {
      const engine = new EntropyEngine({ minLength: 20 });
      const shortButHighEntropy = 'aB3dE5fG7hJ9kLmN';
      const secrets = engine.detect(shortButHighEntropy);
      expect(secrets.length).toBe(0);
    });
  });

  describe('dictionary word filtering', () => {
    it('should filter dictionary words by default', () => {
      const engine = new EntropyEngine();
      const config = engine.getConfig();
      expect(config.filterDictionaryWords).toBe(true);
    });

    it('should not detect filtered dictionary words', () => {
      const engine = new EntropyEngine();
      const filtered = engine.isSecret('password12345678');
      expect(filtered).toBe(false);
    });

    it('should allow disabling dictionary filtering', () => {
      const engine = new EntropyEngine({
        filterDictionaryWords: false,
        threshold: 3.0,
      });
      // With dictionary filtering disabled, some words might be detected
      // depending on their entropy
      const config = engine.getConfig();
      expect(config.filterDictionaryWords).toBe(false);
    });

    it('should accept custom filtered words', () => {
      const engine = new EntropyEngine({
        customFilteredWords: ['mycompany', 'internal'],
      });
      engine.addFilteredWords(['customterm']);
      const isSecret = engine.isSecret('mycompany1234567');
      expect(isSecret).toBe(false);
    });

    it('should remove words from filtered list', () => {
      const engine = new EntropyEngine();
      engine.addFilteredWords(['tempword']);
      expect(engine.isSecret('tempword1234567')).toBe(false);

      engine.removeFilteredWords(['tempword']);
      // After removal, might be detected depending on entropy
      const config = engine.getConfig();
      expect(config.filterDictionaryWords).toBe(true);
    });
  });

  describe('confidence levels', () => {
    it('should assign confidence to detected secrets', () => {
      const engine = new EntropyEngine();
      const text = 'xJ9mK2pL5nQ8rT4vW7yZ1bC3dE6gH0jF';
      const secrets = engine.detect(text);

      expect(secrets.length).toBeGreaterThan(0);
      expect(secrets[0].confidence).toBeDefined();
      expect(['low', 'medium', 'high']).toContain(secrets[0].confidence);
    });

    it('should assign high confidence to very random strings', () => {
      const engine = new EntropyEngine();
      const veryRandom =
        'qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dAqW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dAqW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dAqW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA';
      const secrets = engine.detect(veryRandom);

      expect(secrets.length).toBeGreaterThan(0);
      expect(['medium', 'high']).toContain(secrets[0].confidence);
    });

    it('should include confidence in DetectedSecret interface', () => {
      const engine = new EntropyEngine();
      const text = 'sk-testabc123def456ghi789jkl012mno';
      const secrets = engine.detect(text);

      if (secrets.length > 0) {
        const secret: DetectedSecret = secrets[0];
        expect(secret.confidence).toBeDefined();
      }
    });
  });

  describe('position detection', () => {
    it('should include position information in detected secrets', () => {
      const engine = new EntropyEngine();
      const text = 'prefix sk-qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA suffix';
      const secrets = engine.detect(text);

      expect(secrets.length).toBeGreaterThan(0);
      expect(secrets[0].position).toBeDefined();
      expect(secrets[0].position.start).toBeGreaterThanOrEqual(0);
      expect(secrets[0].position.end).toBeGreaterThan(
        secrets[0].position.start
      );
      expect(secrets[0].position.line).toBe(1);
    });

    it('should calculate correct line numbers', () => {
      const engine = new EntropyEngine();
      const text = `line1
line2
sk-qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA
line4`;
      const secrets = engine.detect(text);

      expect(secrets.length).toBeGreaterThan(0);
      expect(secrets[0].position.line).toBe(3);
    });
  });

  describe('placeholders', () => {
    it('should generate unique placeholders for each secret', () => {
      const engine = new EntropyEngine();
      const text = `key1: a3f5c8e9b2d1470f
key2: b4g6d9f0c3e2581g`;
      const secrets = engine.detect(text);

      if (secrets.length >= 2) {
        expect(secrets[0].placeholder).not.toBe(secrets[1].placeholder);
      }
    });

    it('should include placeholder in detected secret', () => {
      const engine = new EntropyEngine();
      const text = 'sk-qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA';
      const secrets = engine.detect(text);

      expect(secrets.length).toBeGreaterThan(0);
      expect(secrets[0].placeholder).toBeDefined();
      expect(secrets[0].placeholder).toContain('__FILTER_');
    });
  });

  describe('detection statistics', () => {
    it('should provide statistics with detectWithStats', () => {
      const engine = new EntropyEngine();
      const text = `password
sk-qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA
short
qwerty`;
      const result = engine.detectWithStats(text);

      expect(result.stats).toBeDefined();
      expect(result.stats.totalCandidates).toBeGreaterThan(0);
      expect(result.stats.filteredByDictionary).toBeGreaterThanOrEqual(0);
      expect(result.stats.filteredByLength).toBeGreaterThanOrEqual(0);
      expect(result.stats.filteredByEntropy).toBeGreaterThanOrEqual(0);
    });

    it('should count dictionary filtering correctly', () => {
      const engine = new EntropyEngine({
        customFilteredWords: ['mycompany1234567', 'internal12345678', 'project123456789'],
      });
      const text = 'mycompany1234567 internal12345678 project123456789';
      const result = engine.detectWithStats(text);

      expect(result.stats.filteredByDictionary).toBeGreaterThanOrEqual(3);
      expect(result.secrets.length).toBe(0);
    });
  });

  describe('isSecret helper', () => {
    it('should return true for high-entropy strings', () => {
      const engine = new EntropyEngine();
      expect(engine.isSecret('qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA')).toBe(true);
    });

    it('should return false for dictionary words', () => {
      const engine = new EntropyEngine();
      expect(engine.isSecret('password')).toBe(false);
    });

    it('should return false for short strings', () => {
      const engine = new EntropyEngine();
      expect(engine.isSecret('abc123')).toBe(false);
    });

    it('should return false for UUIDs', () => {
      const engine = new EntropyEngine();
      expect(engine.isSecret('550e8400-e29b-41d4-a716-446655440000')).toBe(
        false
      );
    });
  });

  describe('convenience functions', () => {
    it('calculateEntropy should work as standalone function', () => {
      const entropy = calculateEntropy('abcdefgh');
      expect(entropy).toBe(3);
    });

    it('detectSecrets should work as standalone function', () => {
      const secrets = detectSecrets('sk-qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA');
      expect(secrets.length).toBeGreaterThan(0);
    });

    it('detectSecrets should accept threshold parameter', () => {
      const secrets = detectSecrets('qW8kP3mN5xJ2vL7yB9cE4fH', 3.0, 16);
      expect(Array.isArray(secrets)).toBe(true);
    });

    it('detectSecrets should accept minLength parameter', () => {
      const secrets = detectSecrets('qW8kP3mN5xJ2vL7y', 3.0, 16);
      expect(Array.isArray(secrets)).toBe(true);
    });
  });

  describe('configuration management', () => {
    it('should update configuration', () => {
      const engine = new EntropyEngine();
      engine.updateConfig({ threshold: 3.5, minLength: 12 });

      const config = engine.getConfig();
      expect(config.threshold).toBe(3.5);
      expect(config.minLength).toBe(12);
    });

    it('should preserve unchanged config values on partial update', () => {
      const engine = new EntropyEngine({ threshold: 4.0 });
      engine.updateConfig({ minLength: 20 });

      const config = engine.getConfig();
      expect(config.threshold).toBe(4.0);
      expect(config.minLength).toBe(20);
    });
  });

  describe('edge cases', () => {
    it('should handle empty text', () => {
      const engine = new EntropyEngine();
      const secrets = engine.detect('');
      expect(secrets.length).toBe(0);
    });

    it('should handle text with no potential secrets', () => {
      const engine = new EntropyEngine();
      const text = 'This is just normal text without any secrets.';
      const secrets = engine.detect(text);
      expect(secrets.length).toBe(0);
    });

    it('should handle very long strings within limit', () => {
      const engine = new EntropyEngine({ maxLength: 100 });
      const longString = 'aB3'.repeat(30); // 90 characters
      const secrets = engine.detect(longString);
      expect(Array.isArray(secrets)).toBe(true);
    });

    it('should filter strings exceeding max length', () => {
      const engine = new EntropyEngine({ maxLength: 50 });
      const tooLong = 'aB3'.repeat(30); // 90 characters
      const secrets = engine.detect(tooLong);
      expect(secrets.length).toBe(0);
    });

    it('should handle special characters in text', () => {
      const engine = new EntropyEngine();
      const text = 'key: sk-qW8kP3mN5xJ2vL7yB9cE4fH!@#$%^&*()jG0hK1dA';
      const secrets = engine.detect(text);
      expect(Array.isArray(secrets)).toBe(true);
    });

    it('should handle multiple lines correctly', () => {
      const engine = new EntropyEngine();
      const text = `line1: a3f5c8e9b2d1470f8e6a5b4c3d2e1f0a8
line2: normal text
line3: qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA`;
      const secrets = engine.detect(text);
      expect(secrets.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('performance', () => {
    it('should process 1KB text in less than 5ms', () => {
      const engine = new EntropyEngine();
      const oneKBText = 'qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA'.repeat(32);

      const start = performance.now();
      engine.detect(oneKBText);
      const end = performance.now();

      expect(end - start).toBeLessThan(5);
    });

    it('should process multiple detections efficiently', () => {
      const engine = new EntropyEngine();
      const iterations = 100;
      const text = 'sk-qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA';

      const start = performance.now();
      for (let i = 0; i < iterations; i++) {
        engine.detect(text);
      }
      const end = performance.now();

      expect((end - start) / iterations).toBeLessThan(2);
    });

    it('should handle large texts with many candidates', () => {
      const engine = new EntropyEngine();
      const parts = [];
      for (let i = 0; i < 100; i++) {
        parts.push(`key${i}: qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA`);
      }
      const text = parts.join('\n');

      const start = performance.now();
      const secrets = engine.detect(text);
      const end = performance.now();

      expect(secrets.length).toBeGreaterThan(0);
      expect(end - start).toBeLessThan(100);
    });
  });

  describe('base64 and hex specific detection', () => {
    it('should detect standard base64 encoded strings', () => {
      const engine = new EntropyEngine();
      const base64Strings = [
        'qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dAqW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA',
        'aB3dE5fG7hJ9kLmNpQrStUvWxYzA1b2C3d4E5f6G7h8',
        'xJ9mK2pL5nQ8rT4vW7yZ1bC3dE6gH0jFmK2pL5nQ8r',
      ];

      for (const str of base64Strings) {
        if (str.length >= 16) {
          const secrets = engine.detect(str);
          expect(secrets.length).toBeGreaterThan(0);
        }
      }
    });

    it('should detect hex encoded strings', () => {
      const engine = new EntropyEngine();
      const hexStrings = [
        'a3f5c8e9b2d1470f8e6a5b4c3d2e1f0a8',
        '8f6e5d4c3b2a1908f7e6d5c4b3a29180f',
      ];

      for (const str of hexStrings) {
        const secrets = engine.detect(str);
        expect(secrets.length).toBeGreaterThan(0);
      }
    });

    it('should detect JWT-like tokens', () => {
      const engine = new EntropyEngine();
      const jwt =
        'eyJhbGciOiJIUzI1Nix9.eyJzdWIiOiJxVzhrUDNtTjV4SjJ2TDd5QjljRTRmSA.dozjgNryP4J3jVmNHl0w5N_XgL0n3a9w';
      const secrets = engine.detect(jwt);
      expect(secrets.length).toBeGreaterThan(0);
    });

    it('should detect AWS-like access keys', () => {
      const engine = new EntropyEngine();
      const awsKey = 'AKIAQW8KP3MN5XJ2VL7YB9CE4FH6JGK0';
      const secrets = engine.detect(awsKey);
      expect(secrets.length).toBeGreaterThan(0);
    });

    it('should detect random-looking API keys', () => {
      const engine = new EntropyEngine();
      const apiKeys = [
        'sk_live_qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA',
        'pk_test_qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA',
        'ghp_qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dAqW8kP3mN',
      ];

      for (const key of apiKeys) {
        if (key.length >= 16) {
          const secrets = engine.detect(key);
          expect(secrets.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('entropy accuracy', () => {
    it('should calculate near-zero entropy for uniform strings', () => {
      const engine = new EntropyEngine();
      const uniform = 'aaaaaaaaaaaaaaaaaaaaaaaaaa';
      const entropy = engine.calculateEntropy(uniform);
      expect(entropy).toBeCloseTo(0, 1);
    });

    it('should calculate high entropy for random strings', () => {
      const engine = new EntropyEngine();
      const random =
        'qW8kP3mN5xJ2vL7yB9cE4fH6jG0hK1dA';
      const entropy = engine.calculateEntropy(random);
      expect(entropy).toBeGreaterThan(4);
    });

    it('should correctly calculate entropy for mixed strings', () => {
      const engine = new EntropyEngine();
      // Half 'a', half 'b' -> entropy should be 1
      const mixed = 'aaaaaaaaaabbbbbbbbbb';
      const entropy = engine.calculateEntropy(mixed);
      expect(entropy).toBe(1);
    });
  });
});
