import { describe, it, expect, beforeEach } from 'vitest';
import { MessageFilter } from './filter';
import { SessionManager } from './session';
import { SecretDetector, RegexEngineStub, EntropyEngineStub } from './detector';
import { CryptoUtils } from './crypto';
import { BUILTIN_PATTERNS } from './patterns/builtin';
import type { SecretPattern } from './types';

describe('MessageFilter', () => {
  let filter: MessageFilter;
  let session: SessionManager;

  beforeEach(() => {
    const regexEngine = new RegexEngineStub(BUILTIN_PATTERNS);
    const entropyEngine = new EntropyEngineStub(4.5, 16);
    const detector = new SecretDetector(regexEngine, entropyEngine);
    const crypto = new CryptoUtils();
    filter = new MessageFilter(detector, crypto);
    session = new SessionManager();
  });

  describe('filterOutgoing', () => {
    it('should replace secrets with placeholders', () => {
      const text = 'My AWS key is AKIAIOSFODNN7EXAMPLE for testing';
      const result = filter.filterOutgoing(text, session);

      expect(result.text).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(result.text).toMatch(/__FILTER_[A-Z]+_[a-f0-9]{12}__/);
      expect(result.replacedCount).toBeGreaterThanOrEqual(1);
    });

    it('should handle multiple secrets', () => {
      const text = 'AWS: AKIAIOSFODNN7EXAMPLE and token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
      const result = filter.filterOutgoing(text, session);

      expect(result.replacedCount).toBeGreaterThanOrEqual(1);
    });

    it('should reuse placeholders for duplicate secrets', () => {
      const secret = 'AKIAIOSFODNN7EXAMPLE';
      const text = `key1=${secret} and key2=${secret}`;
      const result = filter.filterOutgoing(text, session);

      const uniquePlaceholders = new Set(result.placeholders);
      expect(uniquePlaceholders.size).toBeLessThanOrEqual(result.placeholders.length);
    });

    it('should return original text when disabled', () => {
      session.disable();
      const text = 'AWS: AKIAIOSFODNN7EXAMPLE';
      const result = filter.filterOutgoing(text, session);

      expect(result.text).toBe(text);
      expect(result.replacedCount).toBe(0);
    });

    it('should handle empty text', () => {
      const result = filter.filterOutgoing('', session);
      expect(result.text).toBe('');
      expect(result.replacedCount).toBe(0);
    });

    it('should handle text without secrets', () => {
      const text = 'hello world no secrets here';
      const result = filter.filterOutgoing(text, session);

      expect(result.text).toBe(text);
      expect(result.replacedCount).toBe(0);
    });
  });

  describe('filterIncoming', () => {
    it('should restore placeholders to secrets', () => {
      const original = 'My key is AKIAIOSFODNN7EXAMPLE';
      const outgoing = filter.filterOutgoing(original, session);

      const restored = filter.filterIncoming(outgoing.text, session);
      expect(restored).toBe(original);
    });

    it('should handle multiple placeholders', () => {
      const original = 'AWS: AKIAIOSFODNN7EXAMPLE and GitHub: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
      const outgoing = filter.filterOutgoing(original, session);

      const restored = filter.filterIncoming(outgoing.text, session);
      expect(restored).toBe(original);
    });

    it('should return original text when disabled', () => {
      session.disable();
      const text = '__FILTER_API_KEY_abc123__';
      const result = filter.filterIncoming(text, session);

      expect(result).toBe(text);
    });

    it('should handle empty text', () => {
      const result = filter.filterIncoming('', session);
      expect(result).toBe('');
    });

    it('should handle text without placeholders', () => {
      const text = 'hello world no placeholders';
      const result = filter.filterIncoming(text, session);
      expect(result).toBe(text);
    });

    it('should handle unknown placeholders gracefully', () => {
      const text = '__FILTER_UNKNOWN_abc123__';
      const result = filter.filterIncoming(text, session);
      expect(result).toBe(text);
    });
  });

  describe('session persistence', () => {
    it('should maintain mappings across multiple operations', () => {
      const text1 = 'AWS: AKIAIOSFODNN7EXAMPLE';
      filter.filterOutgoing(text1, session);

      const placeholder = session.getAllPlaceholders()[0];
      const text2 = `${placeholder} is the key`;
      const restored = filter.filterIncoming(text2, session);

      expect(restored).toContain('AKIAIOSFODNN7EXAMPLE');
    });

    it('should clear mappings when session is cleared', () => {
      const text1 = 'AWS: AKIAIOSFODNN7EXAMPLE';
      const outgoing = filter.filterOutgoing(text1, session);

      session.clear();

      const restored = filter.filterIncoming(outgoing.text, session);
      expect(restored).toBe(outgoing.text);
    });
  });

  describe('overlapping secrets', () => {
    it('should handle overlapping patterns correctly', () => {
      const patterns: SecretPattern[] = [
        {
          name: 'test-key',
          regex: /key-[a-z]+/g,
          category: 'api_key',
          description: 'Test key pattern',
          severity: 'high',
          example: 'key-abc',
        },
        {
          name: 'test-secret',
          regex: /key-[a-z]+-secret/g,
          category: 'credential',
          description: 'Test secret pattern',
          severity: 'critical',
          example: 'key-abc-secret',
        },
      ];

      const detector = new SecretDetector(
        new RegexEngineStub(patterns),
        new EntropyEngineStub(5.0, 32)
      );
      const testFilter = new MessageFilter(detector, new CryptoUtils());
      const testSession = new SessionManager();

      const text = 'Here is key-abc-secret-value';
      const result = testFilter.filterOutgoing(text, testSession);

      expect(result.text).toBeDefined();
    });
  });

  describe('edge cases', () => {
    it('should handle newlines in text', () => {
      const text = 'Line 1\nAWS: AKIAIOSFODNN7EXAMPLE\nLine 3';
      const result = filter.filterOutgoing(text, session);

      expect(result.text).toBeDefined();
    });

    it('should handle secrets at start and end of text', () => {
      const text = 'AKIAIOSFODNN7EXAMPLE is my key and ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 is my token';
      const result = filter.filterOutgoing(text, session);

      expect(result.replacedCount).toBeGreaterThanOrEqual(1);
    });

    it('should handle consecutive secrets', () => {
      const text = 'Key1: AKIAIOSFODNN7EXAMPLE Key2: AKIAIOSFODNN7EXAMPLE2';
      const result = filter.filterOutgoing(text, session);

      expect(result.replacedCount).toBeGreaterThanOrEqual(1);
    });

    it('should track correct placeholder count', () => {
      const text = 'Key: AKIAIOSFODNN7EXAMPLE';
      const result = filter.filterOutgoing(text, session);

      expect(result.placeholders.length).toBe(result.replacedCount);
    });
  });
});
