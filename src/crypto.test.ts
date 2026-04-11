import { describe, it, expect } from 'vitest';
import { CryptoUtils } from './crypto';

describe('CryptoUtils', () => {
  describe('generateSessionKey', () => {
    it('should generate 256-bit (32 byte) random key', () => {
      const key = CryptoUtils.generateSessionKey();
      expect(key.length).toBe(32);
    });

    it('should generate different keys on each call', () => {
      const key1 = CryptoUtils.generateSessionKey();
      const key2 = CryptoUtils.generateSessionKey();
      expect(key1.toString('hex')).not.toBe(key2.toString('hex'));
    });
  });

  describe('generatePlaceholder', () => {
    it('should generate deterministic placeholder for same secret and key', () => {
      const crypto = new CryptoUtils();
      const secret = 'test-secret-123';
      const category = 'API_KEY';
      
      const placeholder1 = crypto.generatePlaceholder(secret, category);
      const placeholder2 = crypto.generatePlaceholder(secret, category);
      
      expect(placeholder1).toBe(placeholder2);
    });

    it('should generate different placeholders for different keys', () => {
      const crypto1 = new CryptoUtils();
      const crypto2 = new CryptoUtils();
      const secret = 'test-secret-123';
      const category = 'API_KEY';
      
      const placeholder1 = crypto1.generatePlaceholder(secret, category);
      const placeholder2 = crypto2.generatePlaceholder(secret, category);
      
      expect(placeholder1).not.toBe(placeholder2);
    });

    it('should format placeholder correctly', () => {
      const crypto = new CryptoUtils();
      const secret = 'test-secret';
      const category = 'aws';
      
      const placeholder = crypto.generatePlaceholder(secret, category);
      
      expect(placeholder).toMatch(/^__FILTER_AWS_[a-f0-9]{12}__$/);
    });

    it('should convert category to uppercase', () => {
      const crypto = new CryptoUtils();
      const secret = 'test';
      const category = 'github';
      
      const placeholder = crypto.generatePlaceholder(secret, category);
      
      expect(placeholder).toContain('GITHUB');
    });
  });

  describe('hashSecret', () => {
    it('should return SHA-256 hash', () => {
      const crypto = new CryptoUtils();
      const secret = 'test-secret';
      
      const hash = crypto.hashSecret(secret);
      
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should return same hash for same input', () => {
      const crypto = new CryptoUtils();
      const secret = 'test-secret';
      
      const hash1 = crypto.hashSecret(secret);
      const hash2 = crypto.hashSecret(secret);
      
      expect(hash1).toBe(hash2);
    });

    it('should return different hash for different input', () => {
      const crypto = new CryptoUtils();
      
      const hash1 = crypto.hashSecret('secret1');
      const hash2 = crypto.hashSecret('secret2');
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('getSessionKey', () => {
    it('should return the session key', () => {
      const crypto = new CryptoUtils();
      const key = crypto.getSessionKey();
      
      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(32);
    });
  });
});
