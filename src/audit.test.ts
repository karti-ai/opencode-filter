import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  AuditLogger,
  getAuditLogger,
  resetAuditLogger,
  formatAuditEntry,
  formatLogStats,
  DEFAULT_AUDIT_CONFIG,
} from './audit';

describe('AuditLogger', () => {
  const testLogDir = path.join(os.tmpdir(), `opencode-filter-test-${Date.now()}`);
  const testLogPath = path.join(testLogDir, 'test-audit.log');

  beforeEach(() => {
    // Create test directory
    if (!fs.existsSync(testLogDir)) {
      fs.mkdirSync(testLogDir, { recursive: true });
    }
    // Reset global logger before each test
    resetAuditLogger();
  });

  afterEach(() => {
    // Clean up test directory
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
    resetAuditLogger();
  });

  describe('initialization', () => {
    it('should initialize with default config', () => {
      const logger = new AuditLogger();
      logger.initialize();
      expect(logger.isEnabled()).toBe(true);
    });

    it('should initialize with custom config', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
        maxSize: 1024,
        maxFiles: 3,
      });
      logger.initialize();
      expect(logger.isEnabled()).toBe(true);
      expect(logger.getConfig().logPath).toBe(testLogPath);
    });

    it('should not initialize when disabled', () => {
      const logger = new AuditLogger({ enabled: false });
      logger.initialize();
      expect(logger.isEnabled()).toBe(false);
    });

    it('should fail-open on initialization errors', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: '/dev/null/invalid\x00/audit.log',
      });
      logger.initialize();
      expect(logger.isEnabled()).toBe(false);
      expect(logger.getInitError()).not.toBeNull();
    });
  });

  describe('logging', () => {
    it('should write FILTERED log entry', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logFiltered(
        'api_key',
        '__FILTER_API_KEY_a1b2c3',
        0.9,
        'regex',
        { pattern: 'aws-access-key', sessionId: 'test-session' }
      );

      const content = fs.readFileSync(testLogPath, 'utf-8');
      const entry = JSON.parse(content.trim());

      expect(entry.action).toBe('FILTERED');
      expect(entry.category).toBe('api_key');
      expect(entry.placeholder).toBe('__FILTER_API_KEY_a1b2c3');
      expect(entry.confidence).toBe(0.9);
      expect(entry.method).toBe('regex');
      expect(entry.pattern).toBe('aws-access-key');
      expect(entry.sessionId).toBe('test-session');
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('should write RESTORED log entry', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logRestored('api_key', '__FILTER_API_KEY_a1b2c3', { sessionId: 'test-session' });

      const content = fs.readFileSync(testLogPath, 'utf-8');
      const entry = JSON.parse(content.trim());

      expect(entry.action).toBe('RESTORED');
      expect(entry.category).toBe('api_key');
      expect(entry.placeholder).toBe('__FILTER_API_KEY_a1b2c3');
      expect(entry.confidence).toBe(1.0);
      expect(entry.method).toBe('regex');
    });

    it('should write BYPASSED log entry', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logBypassed({ messageId: 'msg-123', reason: 'filter disabled' });

      const content = fs.readFileSync(testLogPath, 'utf-8');
      const entry = JSON.parse(content.trim());

      expect(entry.action).toBe('BYPASSED');
      expect(entry.category).toBe('none');
      expect(entry.metadata?.reason).toBe('filter disabled');
    });

    it('should write ERROR log entry', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logError(new Error('Test error'), { sessionId: 'test-session' });

      const content = fs.readFileSync(testLogPath, 'utf-8');
      const entry = JSON.parse(content.trim());

      expect(entry.action).toBe('ERROR');
      expect(entry.category).toBe('error');
      expect(entry.metadata?.errorMessage).toBe('Test error');
    });

    it('should write DISABLED log entry', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logDisabled({ sessionId: 'test-session', reason: 'user request' });

      const content = fs.readFileSync(testLogPath, 'utf-8');
      const entry = JSON.parse(content.trim());

      expect(entry.action).toBe('DISABLED');
      expect(entry.category).toBe('system');
      expect(entry.metadata?.reason).toBe('user request');
    });

    it('should write ENABLED log entry', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logEnabled({ sessionId: 'test-session' });

      const content = fs.readFileSync(testLogPath, 'utf-8');
      const entry = JSON.parse(content.trim());

      expect(entry.action).toBe('ENABLED');
      expect(entry.category).toBe('system');
    });
  });

  describe('privacy', () => {
    it('should reject entries with suspicious placeholder format', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      // Should warn but still log (fail-open for logging)
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      logger.log({
        action: 'FILTERED',
        category: 'api_key',
        placeholder: 'suspicious-format',
        confidence: 0.9,
        method: 'regex',
      });

      // The entry should still be written (fail-open)
      const content = fs.readFileSync(testLogPath, 'utf-8');
      expect(content).toContain('suspicious-format');

      consoleSpy.mockRestore();
    });

    it('should reject entries with potential secrets in metadata (fail-open)', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      // AWS-like key pattern should be rejected - error is caught internally (fail-open)
      logger.log({
        action: 'FILTERED',
        category: 'api_key',
        placeholder: '__FILTER_AWS_a1b2c3',
        confidence: 0.9,
        method: 'regex',
        metadata: { suspiciousValue: 'AKIAIOSFODNN7EXAMPLE' },
      });

      // Should log warning about the security issue
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Potential secret detected in metadata')
      );

      // No log should be written due to privacy protection
      expect(fs.existsSync(testLogPath)).toBe(false);

      consoleSpy.mockRestore();
    });

    it('should not log actual secret values', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      // Log with placeholder
      logger.logFiltered('api_key', '__FILTER_API_KEY_abc123', 0.9, 'regex');

      const content = fs.readFileSync(testLogPath, 'utf-8');

      // Should contain placeholder
      expect(content).toContain('__FILTER_API_KEY_abc123');

      // Should NOT contain actual secret patterns
      expect(content).not.toMatch(/AKIA[A-Z0-9]{16}/);
      expect(content).not.toMatch(/sk-[a-zA-Z0-9]{48}/);
      expect(content).not.toMatch(/ghp_[a-zA-Z0-9]{36}/);
    });

    it('should set secure file permissions', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logFiltered('api_key', '__FILTER_API_KEY_abc123', 0.9, 'regex');

      // Check file exists and has been written
      expect(fs.existsSync(testLogPath)).toBe(true);

      // On Unix-like systems, check permissions
      if (process.platform !== 'win32') {
        const stats = fs.statSync(testLogPath);
        const mode = stats.mode & 0o777;
        expect(mode).toBe(0o600); // Owner read/write only
      }
    });
  });

  describe('log rotation', () => {
    it('should rotate log file when max size exceeded', () => {
      const maxSize = 100; // 100 bytes for testing
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
        maxSize,
        maxFiles: 3,
      });
      logger.initialize();

      // Write enough entries to trigger rotation
      for (let i = 0; i < 20; i++) {
        logger.logFiltered('api_key', `__FILTER_API_KEY_${i}`, 0.9, 'regex');
      }

      // Check that rotation occurred
      const rotatedPath = `${testLogPath}.1`;
      expect(fs.existsSync(rotatedPath)).toBe(true);
    });

    it('should maintain maxFiles limit', () => {
      const maxSize = 50; // Small size to trigger rotation quickly
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
        maxSize,
        maxFiles: 2,
      });
      logger.initialize();

      // Write many entries to trigger multiple rotations
      for (let i = 0; i < 50; i++) {
        logger.logFiltered('api_key', `__FILTER_KEY_${i}_xyz123`, 0.9, 'regex');
      }

      // Should not exceed maxFiles
      expect(fs.existsSync(`${testLogPath}.1`)).toBe(true);
      expect(fs.existsSync(`${testLogPath}.2`)).toBe(true);
      expect(fs.existsSync(`${testLogPath}.3`)).toBe(false);
    });
  });

  describe('log viewer', () => {
    it('should view recent entries', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      // Write test entries
      logger.logFiltered('api_key', '__FILTER_KEY_1', 0.9, 'regex');
      logger.logFiltered('password', '__FILTER_PWD_2', 0.8, 'entropy');
      logger.logRestored('api_key', '__FILTER_KEY_1', {});

      const result = logger.viewLogs({ limit: 10 });

      expect(result.entries.length).toBe(3);
      expect(result.totalCount).toBe(3);
      expect(result.fileSize).toBeGreaterThan(0);
    });

    it('should filter entries by action', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logFiltered('api_key', '__FILTER_KEY_1', 0.9, 'regex');
      logger.logRestored('api_key', '__FILTER_KEY_1', {});

      const result = logger.viewLogs({ filter: { action: 'FILTERED' } });

      expect(result.entries.length).toBe(1);
      expect(result.entries[0].action).toBe('FILTERED');
    });

    it('should filter entries by category', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      logger.logFiltered('api_key', '__FILTER_KEY_1', 0.9, 'regex');
      logger.logFiltered('password', '__FILTER_PWD_2', 0.8, 'regex');

      const result = logger.viewLogs({ filter: { category: 'api_key' } });

      expect(result.entries.length).toBe(1);
      expect(result.entries[0].category).toBe('api_key');
    });

    it('should handle tail option', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      // Write 10 entries
      for (let i = 0; i < 10; i++) {
        logger.logFiltered('api_key', `__FILTER_KEY_${i}`, 0.9, 'regex');
      }

      const result = logger.viewLogs({ limit: 3, tail: true });

      expect(result.entries.length).toBe(3);
      // Should get the last 3 entries
      expect(result.entries[0].placeholder).toContain('__FILTER_KEY_7');
      expect(result.entries[2].placeholder).toContain('__FILTER_KEY_9');
    });

    it('should handle empty log file', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      const result = logger.viewLogs();

      expect(result.entries.length).toBe(0);
      expect(result.totalCount).toBe(0);
      expect(result.fileSize).toBe(0);
    });

    it('should handle malformed log lines', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      // Write a valid entry
      logger.logFiltered('api_key', '__FILTER_KEY_1', 0.9, 'regex');

      // Append a malformed line
      fs.appendFileSync(testLogPath, '\n{invalid json}\n', { encoding: 'utf-8' });

      const result = logger.viewLogs();

      // Should skip malformed line and return valid entry
      expect(result.entries.length).toBe(1);
    });
  });

  describe('clear logs', () => {
    it('should clear all log files', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
        maxFiles: 3,
      });
      logger.initialize();

      // Create log files
      logger.logFiltered('api_key', '__FILTER_KEY_1', 0.9, 'regex');
      fs.writeFileSync(`${testLogPath}.1`, 'rotated log 1', 'utf-8');
      fs.writeFileSync(`${testLogPath}.2`, 'rotated log 2', 'utf-8');

      const result = logger.clearLogs();

      expect(result.success).toBe(true);
      expect(result.deleted).toBe(3);
      expect(fs.existsSync(testLogPath)).toBe(false);
      expect(fs.existsSync(`${testLogPath}.1`)).toBe(false);
      expect(fs.existsSync(`${testLogPath}.2`)).toBe(false);
    });

    it('should handle clear when no logs exist', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      const result = logger.clearLogs();

      expect(result.success).toBe(true);
      expect(result.deleted).toBe(0);
    });
  });

  describe('statistics', () => {
    it('should return log statistics', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
        maxFiles: 3,
      });
      logger.initialize();

      logger.logFiltered('api_key', '__FILTER_KEY_1', 0.9, 'regex');
      logger.logFiltered('password', '__FILTER_PWD_2', 0.8, 'regex');

      // Create rotated files
      fs.writeFileSync(`${testLogPath}.1`, 'rotated', 'utf-8');

      const stats = logger.getStats();

      expect(stats.exists).toBe(true);
      expect(stats.size).toBeGreaterThan(0);
      expect(stats.entryCount).toBe(2);
      expect(stats.rotatedFiles).toBe(1);
    });

    it('should return stats for non-existent log', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: path.join(testLogDir, 'nonexistent', 'audit.log'),
      });

      const stats = logger.getStats();

      expect(stats.exists).toBe(false);
      expect(stats.size).toBe(0);
      expect(stats.entryCount).toBe(0);
      expect(stats.rotatedFiles).toBe(0);
    });
  });

  describe('configuration updates', () => {
    it('should update config', () => {
      const logger = new AuditLogger({
        enabled: true,
        logPath: testLogPath,
      });
      logger.initialize();

      const newPath = path.join(testLogDir, 'new-audit.log');
      logger.updateConfig({ logPath: newPath, maxFiles: 10 });

      expect(logger.getConfig().logPath).toBe(newPath);
      expect(logger.getConfig().maxFiles).toBe(10);
    });

    it('should re-initialize when enabled changes', () => {
      const logger = new AuditLogger({
        enabled: false,
        logPath: testLogPath,
      });
      logger.initialize();

      expect(logger.isEnabled()).toBe(false);

      logger.updateConfig({ enabled: true });

      expect(logger.isEnabled()).toBe(true);
    });
  });

  describe('global instance', () => {
    it('should return same global instance', () => {
      const logger1 = getAuditLogger();
      const logger2 = getAuditLogger();

      expect(logger1).toBe(logger2);
    });

    it('should update global instance config', () => {
      resetAuditLogger();

      const logger1 = getAuditLogger({ enabled: true, logPath: testLogPath });
      logger1.initialize();

      const logger2 = getAuditLogger({ maxFiles: 7 });

      expect(logger1).toBe(logger2);
      expect(logger2.getConfig().maxFiles).toBe(7);
    });
  });

  describe('format helpers', () => {
    it('should format audit entry for display', () => {
      const entry = {
        timestamp: '2024-01-15T10:30:00.000Z',
        action: 'FILTERED' as const,
        category: 'api_key',
        placeholder: '__FILTER_API_KEY_abc123',
        confidence: 0.9,
        method: 'regex' as const,
        index: 1,
      };

      const formatted = formatAuditEntry(entry);

      expect(formatted).toContain('FILTERED');
      expect(formatted).toContain('api_key');
      expect(formatted).toContain('__FILTER_API_KEY_abc123');
      expect(formatted).toContain('90%');
    });

    it('should format log stats for display', () => {
      const stats = {
        exists: true,
        size: 10240,
        entryCount: 50,
        rotatedFiles: 2,
      };

      const formatted = formatLogStats(stats);

      expect(formatted).toContain('50 entries');
      expect(formatted).toContain('10.0 KB');
      expect(formatted).toContain('2 rotated files');
    });

    it('should format non-existent log stats', () => {
      const stats = {
        exists: false,
        size: 0,
        entryCount: 0,
        rotatedFiles: 0,
      };

      const formatted = formatLogStats(stats);

      expect(formatted).toBe('No audit log file exists.');
    });
  });

  describe('default config', () => {
    it('should have correct default values', () => {
      expect(DEFAULT_AUDIT_CONFIG.enabled).toBe(true);
      expect(DEFAULT_AUDIT_CONFIG.logPath).toBe('~/.config/opencode/filter-audit.log');
      expect(DEFAULT_AUDIT_CONFIG.maxSize).toBe(10 * 1024 * 1024); // 10MB
      expect(DEFAULT_AUDIT_CONFIG.maxFiles).toBe(5);
      expect(DEFAULT_AUDIT_CONFIG.level).toBe('info');
    });
  });
});
