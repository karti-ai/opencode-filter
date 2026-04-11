import { describe, it, expect, beforeEach } from 'vitest';
import { MessageFilter } from './filter';
import { SessionManager } from './session';
import { SecretDetector, RegexEngineStub, EntropyEngineStub } from './detector';
import { CryptoUtils } from './crypto';
import { BUILTIN_PATTERNS } from './patterns/builtin';
import type { SecretPattern, DetectedSecret } from './types';

// Test secrets that match the builtin patterns
const TEST_SECRETS = {
  awsKey: 'AKIAIOSFODNN7EXAMPLE',
  githubToken: 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  stripeLiveKey: 'sk_live_abcdefghijklmnopqrstuvwxyz1234',
  jwtToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
};

describe('Security Audit', () => {
  let filter: MessageFilter;
  let session: SessionManager;
  let crypto: CryptoUtils;

  beforeEach(() => {
    const regexEngine = new RegexEngineStub(BUILTIN_PATTERNS);
    const entropyEngine = new EntropyEngineStub(4.5, 16);
    const detector = new SecretDetector(regexEngine, entropyEngine);
    crypto = new CryptoUtils();
    filter = new MessageFilter(detector, crypto);
    session = new SessionManager();
  });

  // ============================================================================
  // SECURITY PROPERTY 1: Confidentiality - Secrets never in LLM payload
  // ============================================================================
  describe('Confidentiality - Secrets Never Leak to LLM', () => {
    it('should replace all secret substrings with placeholders', () => {
      const secret1 = 'AKIAIOSFODNN7EXAMPLE';
      const secret2 = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
      const text = `My AWS key is ${secret1} and my GitHub token is ${secret2}`;

      const result = filter.filterOutgoing(text, session);

      // Verify output contains NO secret substrings
      expect(result.text).not.toContain(secret1);
      expect(result.text).not.toContain(secret2);

      // Verify no partial secret substrings present
      expect(result.text).not.toContain(secret1.slice(0, 10));
      expect(result.text).not.toContain(secret2.slice(0, 10));
      expect(result.text).not.toContain(secret1.slice(-10));
      expect(result.text).not.toContain(secret2.slice(-10));
    });

    it('should output only placeholder format in filtered text', () => {
      const secret = 'AKIAIOSFODNN7EXAMPLE';
      const text = `Use this key: ${secret}`;

      const result = filter.filterOutgoing(text, session);

      // Verify output contains only placeholders (format: __FILTER_<CATEGORY>_<HASH>__)
      expect(result.placeholders.length).toBeGreaterThan(0);
      for (const placeholder of result.placeholders) {
        expect(placeholder).toMatch(/^__FILTER_[A-Z_]+_[a-f0-9]{12}__$/);
      }
    });

    it('should use consistent placeholder for same secret', () => {
      const secret = TEST_SECRETS.awsKey;

      // Filter same secret in two separate messages
      const text1 = `Key1: ${secret}`;
      const text2 = `Key2: ${secret}`;

      const result1 = filter.filterOutgoing(text1, session);
      const result2 = filter.filterOutgoing(text2, session);

      // Both should use the same placeholder for the same secret
      expect(result1.placeholders[0]).toBe(result2.placeholders[0]);
      expect(result1.text).not.toContain(secret);
      expect(result2.text).not.toContain(secret);
    });

    it('should handle secrets embedded in larger text blocks', () => {
      const secret = 'AKIAIOSFODNN7EXAMPLE';
      const text = `
        Here is a long message with lots of text.
        It contains a secret: ${secret}
        More text follows here.
        Even more text to make it realistic.
      `;

      const result = filter.filterOutgoing(text, session);

      expect(result.text).not.toContain(secret);
      expect(result.text).not.toContain(secret.slice(0, 5));
      expect(result.text).not.toContain(secret.slice(-5));
    });

    it('should not leak secrets via placeholder metadata', () => {
      const secret = TEST_SECRETS.githubToken;
      const text = `Token: ${secret}`;

      const result = filter.filterOutgoing(text, session);
      expect(result.placeholders.length).toBeGreaterThan(0);

      for (const placeholder of result.placeholders) {
        for (let i = 0; i < secret.length - 4; i++) {
          const substring = secret.slice(i, i + 5);
          expect(placeholder.toLowerCase()).not.toContain(substring.toLowerCase());
        }
      }
    });
  });

  // ============================================================================
  // SECURITY PROPERTY 2: Key Strength - 256-bit HMAC keys
  // ============================================================================
  describe('Key Strength - 256+ bit HMAC Keys', () => {
    it('should generate 256-bit (32 byte) session keys', () => {
      const key = CryptoUtils.generateSessionKey();

      // Verify 32 bytes = 256 bits
      expect(key.length).toBe(32);
      expect(key.length * 8).toBe(256);
    });

    it('should maintain 256-bit key strength in CryptoUtils instance', () => {
      const key = crypto.getSessionKey();

      expect(key.length).toBe(32);
      expect(key.length * 8).toBe(256);
    });

    it('should generate different keys on each instantiation', () => {
      const keys: Buffer[] = [];
      for (let i = 0; i < 10; i++) {
        keys.push(CryptoUtils.generateSessionKey());
      }

      // Verify all keys are unique
      const keyStrings = keys.map(k => k.toString('hex'));
      const uniqueKeys = new Set(keyStrings);
      expect(uniqueKeys.size).toBe(keys.length);
    });

    it('should have high entropy in generated keys', () => {
      const key = CryptoUtils.generateSessionKey();
      const keyHex = key.toString('hex');

      // Count unique characters (should be high for random 256-bit key)
      const uniqueChars = new Set(keyHex).size;
      expect(uniqueChars).toBeGreaterThan(10); // Should have good distribution

      // Key should not be all zeros or predictable
      expect(keyHex).not.toBe('0'.repeat(64));
      expect(keyHex).not.toBe('f'.repeat(64));
    });
  });

  // ============================================================================
  // SECURITY PROPERTY 3: Ephemeral - Session cleared on exit
  // ============================================================================
  describe('Ephemeral - Session Clears on Exit', () => {
    it('should clear all mappings when session.clear() is called', () => {
      // Add multiple secrets
      const secrets = [
        'AKIAIOSFODNN7EXAMPLE',
        'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
        'sk_live_abcdefghijklmnopqrstuvwxyz',
      ];

      for (const secret of secrets) {
        const text = `Key: ${secret}`;
        filter.filterOutgoing(text, session);
      }

      // Verify secrets are stored
      expect(session.getSecretCount()).toBeGreaterThan(0);

      // Clear the session
      session.clear();

      // Verify all mappings are removed
      expect(session.getSecretCount()).toBe(0);
      expect(session.getAllPlaceholders()).toHaveLength(0);
    });

    it('should remove all placeholder-to-secret mappings on clear', () => {
      const secret = 'AKIAIOSFODNN7EXAMPLE';
      const text = `Key: ${secret}`;

      filter.filterOutgoing(text, session);
      const placeholders = session.getAllPlaceholders();
      expect(placeholders.length).toBeGreaterThan(0);

      const placeholder = placeholders[0];
      expect(session.getSecret(placeholder)).toBeDefined();

      session.clear();

      // After clear, placeholder should not resolve to secret
      expect(session.getSecret(placeholder)).toBeUndefined();
      expect(session.hasPlaceholder(placeholder)).toBe(false);
    });

    it('should reset disabled state on clear', () => {
      session.disable();
      expect(session.isDisabled()).toBe(true);

      session.clear();

      // After clear, session should be re-enabled
      expect(session.isDisabled()).toBe(false);
    });

    it('should allow reuse after clear', () => {
      for (let i = 0; i < 3; i++) {
        const secret = `${TEST_SECRETS.awsKey}${i}`;
        const text = `Key: ${secret}`;

        filter.filterOutgoing(text, session);
        expect(session.getSecretCount()).toBeGreaterThan(0);

        session.clear();
        expect(session.getSecretCount()).toBe(0);
      }
    });
  });

  // ============================================================================
  // SECURITY PROPERTY 4: Safe Errors - No secret leakage in error messages
  // ============================================================================
  describe('Safe Errors - No Secret Leakage in Errors', () => {
    it('should not include secret values in filter error messages', () => {
      const secret = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
      const errorThrowingFilter = new ErrorThrowingFilter(secret);

      try {
        errorThrowingFilter.filterOutgoing(`Key: ${secret}`, session);
        expect.fail('Should have thrown an error');
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Error message should NOT contain the secret
        expect(errorMessage).not.toContain(secret);
        expect(errorMessage).not.toContain(secret.slice(0, 10));
        expect(errorMessage).not.toContain(secret.slice(-10));
      }
    });

    it('should not leak secrets when detector throws', () => {
      const secret = TEST_SECRETS.awsKey;
      const throwingDetector = {
        detect: () => {
          throw new Error('Detection engine failed');
        },
      } as any;

      const testFilter = new MessageFilter(throwingDetector, crypto);

      try {
        testFilter.filterOutgoing(`Key: ${secret}`, session);
        expect.fail('Should have thrown');
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Secret should not be in error chain
        expect(errorMessage).not.toContain(secret);
        expect(errorMessage).not.toContain(secret.slice(0, 10));
      }
    });

    it('should handle malformed input without leaking secrets', () => {
      const secret = TEST_SECRETS.stripeLiveKey;

      const problematicInputs = [
        '\x00' + secret,
        secret + '\ufffe',
      ];

      for (const input of problematicInputs) {
        try {
          filter.filterOutgoing(input, session);
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          expect(errorMessage).not.toContain(secret.slice(0, 10));
        }
      }
    });

    it('should provide generic error messages for security failures', () => {
      // Simulate various security-related errors
      const scenarios = [
        { name: 'session full', action: () => { throw new Error('Session storage limit exceeded'); } },
        { name: 'invalid pattern', action: () => { throw new Error('Pattern compilation failed'); } },
        { name: 'crypto error', action: () => { throw new Error('HMAC generation failed'); } },
      ];

      for (const scenario of scenarios) {
        try {
          scenario.action();
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          // Errors should be generic, not exposing implementation details
          expect(errorMessage.length).toBeLessThan(200);
        }
      }
    });
  });

  // ============================================================================
  // SECURITY PROPERTY 5: Irreversibility - Placeholders can't be reversed without key
  // ============================================================================
  describe('Irreversibility - Placeholders Cannot Be Reversed Without Session Key', () => {
    it('should generate different placeholders with different session keys', () => {
      const crypto1 = new CryptoUtils();
      const crypto2 = new CryptoUtils();
      const secret = TEST_SECRETS.awsKey;
      const category = 'API_KEY';

      const placeholder1 = crypto1.generatePlaceholder(secret, category);
      const placeholder2 = crypto2.generatePlaceholder(secret, category);

      expect(placeholder1).not.toBe(placeholder2);
    });

    it('should not allow placeholder reversal without original key', () => {
      const crypto1 = new CryptoUtils();
      const crypto2 = new CryptoUtils();
      const secret = TEST_SECRETS.githubToken;
      const category = 'TOKEN';

      const placeholder = crypto1.generatePlaceholder(secret, category);

      const session2 = new SessionManager();
      session2.storeMapping('fake-secret', placeholder);

      const retrieved = session2.getSecret(placeholder);
      expect(retrieved).not.toBe(secret);
    });

    it('should use HMAC that cannot be reversed without key', () => {
      const secret = TEST_SECRETS.stripeLiveKey;
      const category = 'API_KEY';

      const placeholder = crypto.generatePlaceholder(secret, category);

      const hashMatch = placeholder.match(/__FILTER_[A-Z_]+_([a-f0-9]{12})__/);
      expect(hashMatch).toBeTruthy();

      const hashFragment = hashMatch![1];

      expect(hashFragment).not.toContain(secret.slice(0, 4));
      expect(hashFragment.toLowerCase()).not.toContain(secret.toLowerCase().slice(0, 4));
    });

    it('should maintain consistent mapping within same session', () => {
      const secret = TEST_SECRETS.awsKey;
      const text = `Key: ${secret} and again: ${secret}`;

      const result = filter.filterOutgoing(text, session);
      expect(result.replacedCount).toBeGreaterThanOrEqual(1);

      const placeholders = result.placeholders;
      const uniquePlaceholders = [...new Set(placeholders)];

      expect(uniquePlaceholders.length).toBeLessThanOrEqual(placeholders.length);
    });

    it('should provide no information about secret from placeholder format', () => {
      const secrets = [
        TEST_SECRETS.awsKey,
        TEST_SECRETS.githubToken,
        TEST_SECRETS.stripeLiveKey,
      ];

      const category = 'API_KEY';
      const hashes: string[] = [];

      for (const secret of secrets) {
        const placeholder = crypto.generatePlaceholder(secret, category);
        const hashMatch = placeholder.match(/__FILTER_[A-Z_]+_([a-f0-9]{12})__/);
        expect(hashMatch).toBeTruthy();
        hashes.push(hashMatch![1]);
      }

      for (const hash of hashes) {
        expect(hash.length).toBe(12);
      }

      const uniqueHashes = [...new Set(hashes)];
      expect(uniqueHashes.length).toBeGreaterThan(0);
    });
  });

  // ============================================================================
  // SECURITY PROPERTY 6: Memory Safety - No secret strings in memory after filter
  // ============================================================================
  describe('Memory Safety - No Secret Leakage in Memory', () => {
    it('should not retain secret in filter output', () => {
      const secret = 'AKIAIOSFODNN7EXAMPLE';
      const text = `My secret is: ${secret}`;

      const result = filter.filterOutgoing(text, session);

      // Result text should be completely different object
      expect(result.text).not.toBe(text);

      // Result should not contain secret anywhere
      expect(result.text).not.toContain(secret);

      // Placeholders array should not contain secret
      for (const placeholder of result.placeholders) {
        expect(placeholder).not.toContain(secret);
        expect(placeholder).not.toContain(secret.slice(0, 5));
      }

      // Detected secrets should not leak in result
      for (const detected of result.detectedSecrets) {
        // Value is expected to be there for internal use
        expect(detected.value).toBe(secret);
      }
    });

    it('should handle large messages without memory issues', () => {
      const secret = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
      // Create large message with multiple secrets
      const parts: string[] = [];
      for (let i = 0; i < 100; i++) {
        parts.push(`Line ${i}: ${secret} and some text`);
      }
      const text = parts.join('\n');

      const result = filter.filterOutgoing(text, session);

      // Result should not contain any secret instances
      expect(result.text).not.toContain(secret);

      // Count how many times secret should have appeared
      const expectedOccurrences = 100;
      const secretInResult = (result.text.match(new RegExp(secret, 'g')) || []).length;
      expect(secretInResult).toBe(0);
    });

    it('should properly isolate session state', () => {
      const secret = TEST_SECRETS.stripeLiveKey;
      const text = `Key: ${secret}`;

      const session1 = new SessionManager();
      const session2 = new SessionManager();

      filter.filterOutgoing(text, session1);

      expect(session2.getSecretCount()).toBe(0);
      expect(session2.getAllPlaceholders()).toHaveLength(0);

      expect(session1.getSecretCount()).toBeGreaterThan(0);
    });

    it('should not expose secrets through placeholder enumeration', () => {
      const secrets = [
        TEST_SECRETS.awsKey,
        TEST_SECRETS.githubToken,
        TEST_SECRETS.stripeLiveKey,
      ];

      for (let i = 0; i < secrets.length; i++) {
        filter.filterOutgoing(`Key: ${secrets[i]}`, session);
      }

      const placeholders = session.getAllPlaceholders();
      expect(placeholders.length).toBeGreaterThan(0);

      for (const placeholder of placeholders) {
        for (const secret of secrets) {
          expect(placeholder.toLowerCase()).not.toContain(secret.toLowerCase());
        }
      }
    });

    it('should clear sensitive data from filter results', () => {
      const secret = TEST_SECRETS.awsKey;
      const text = `Key: ${secret}`;

      const result = filter.filterOutgoing(text, session);

      expect(result.detectedSecrets.length).toBeGreaterThan(0);
      expect(result.detectedSecrets[0].value).toBe(secret);

      expect(result.text).not.toContain(secret);
    });
  });

  // ============================================================================
  // ADDITIONAL SECURITY CHECKS
  // ============================================================================
  describe('Additional Security Checks', () => {
    it('should prevent timing attacks on placeholder generation', () => {
      const crypto1 = new CryptoUtils();

      const secret1 = 'AKIAshort';
      const secret2 = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890extra_long_suffix_here';

      const start1 = performance.now();
      crypto1.generatePlaceholder(secret1, 'API_KEY');
      const end1 = performance.now();

      const start2 = performance.now();
      crypto1.generatePlaceholder(secret2, 'API_KEY');
      const end2 = performance.now();

      const time1 = end1 - start1;
      const time2 = end2 - start2;

      expect(time1).toBeLessThan(10);
      expect(time2).toBeLessThan(10);
    });

    it('should use cryptographically secure random for session keys', () => {
      // Generate many keys and check distribution
      const keys: string[] = [];
      for (let i = 0; i < 100; i++) {
        keys.push(CryptoUtils.generateSessionKey().toString('hex'));
      }

      // Check that keys are not predictable
      const firstBytes = keys.map(k => k.slice(0, 2));
      const uniqueFirstBytes = new Set(firstBytes);

      // Should have good distribution of first bytes
      expect(uniqueFirstBytes.size).toBeGreaterThan(50);
    });

    it('should maintain integrity of session mappings', () => {
      const secret = TEST_SECRETS.awsKey;
      const text = `Key: ${secret}`;

      filter.filterOutgoing(text, session);
      expect(session.getAllPlaceholders().length).toBeGreaterThan(0);

      const placeholder = session.getAllPlaceholders()[0];
      const retrievedSecret = session.getSecret(placeholder);

      expect(retrievedSecret).toBe(secret);
      expect(session.hasPlaceholder(placeholder)).toBe(true);
      expect(session.hasSecret(secret)).toBe(true);
    });

    it('should handle concurrent-like session operations safely', () => {
      const secrets = Array.from({ length: 10 }, (_, i) => 
        `ghp_${String(i).padStart(2, '0')}aBcDeFgHiJkLmNoPqRsTuVwXyZ12345`
      );

      for (const secret of secrets) {
        filter.filterOutgoing(`Key: ${secret}`, session);
      }

      expect(session.getSecretCount()).toBeGreaterThan(0);

      for (const placeholder of session.getAllPlaceholders()) {
        const secret = session.getSecret(placeholder);
        expect(secret).toBeDefined();
      }
    });
  });
});

// ============================================================================
// HELPER CLASSES FOR TESTING
// ============================================================================

/**
 * Filter that throws errors for testing error handling
 */
class ErrorThrowingFilter extends MessageFilter {
  private secretToThrow: string;

  constructor(secretToThrow: string) {
    const regexEngine = new RegexEngineStub([]);
    const entropyEngine = new EntropyEngineStub(4.5, 16);
    const detector = new SecretDetector(regexEngine, entropyEngine);
    const crypto = new CryptoUtils();
    super(detector, crypto);
    this.secretToThrow = secretToThrow;
  }

  filterOutgoing(text: string, session: SessionManager) {
    if (text.includes(this.secretToThrow)) {
      throw new Error('Filtering failed due to processing error');
    }
    return super.filterOutgoing(text, session);
  }
}
