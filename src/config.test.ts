import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  getConfigPath,
  loadConfig,
  validateConfig,
  mergeWithDefaults,
  saveConfig,
  serializePattern,
  SerializableSecretPattern,
} from './config';
import { FilterConfig, SecretPattern, DEFAULT_FILTER_CONFIG } from './types';

describe('config', () => {
  const testDir = path.join(os.tmpdir(), 'opencode-filter-test-' + Date.now());
  const homeConfigDir = path.join(testDir, '.config', 'opencode');
  const homeConfigPath = path.join(homeConfigDir, 'filter.config.json');
  const projectConfigPath = path.join(testDir, 'filter.config.json');
  const envConfigPath = path.join(testDir, 'env-config.json');
  const originalCwd = process.cwd();
  const originalEnv = process.env.OPENCODE_FILTER_CONFIG;
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;

  beforeEach(() => {
    fs.mkdirSync(homeConfigDir, { recursive: true });
    process.chdir(testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    process.env.OPENCODE_FILTER_CONFIG = originalEnv;
    process.env.HOME = originalHome;
    process.env.USERPROFILE = originalUserProfile;

    try {
      fs.rmSync(testDir, { recursive: true, force: true });
    } catch (e) {
    }
  });

  describe('getConfigPath', () => {
    it('returns null when no config exists', () => {
      const result = getConfigPath();
      expect(result).toBeNull();
    });

    it('prioritizes OPENCODE_FILTER_CONFIG env var', () => {
      fs.writeFileSync(envConfigPath, JSON.stringify({ enabled: false }));
      fs.writeFileSync(homeConfigPath, JSON.stringify({ enabled: true }));
      fs.writeFileSync(projectConfigPath, JSON.stringify({ enabled: true }));

      process.env.OPENCODE_FILTER_CONFIG = envConfigPath;
      process.env.HOME = testDir;
      process.env.USERPROFILE = testDir;

      const result = getConfigPath();
      expect(result).toBe(envConfigPath);
    });

    it('falls back to home directory config', () => {
      fs.writeFileSync(homeConfigPath, JSON.stringify({ enabled: true }));
      process.env.HOME = testDir;
      process.env.USERPROFILE = testDir;

      const result = getConfigPath();
      expect(result).toBe(homeConfigPath);
    });

    it('falls back to project root config', () => {
      fs.writeFileSync(projectConfigPath, JSON.stringify({ enabled: true }));

      const result = getConfigPath();
      expect(result).toBe(projectConfigPath);
    });
  });

  describe('loadConfig', () => {
    it('returns defaults when no config file exists', () => {
      const result = loadConfig();

      expect(result.config).toEqual(DEFAULT_FILTER_CONFIG);
      expect(result.source).toBe('defaults');
      expect(result.warnings).toContain('No config file found, using default configuration');
    });

    it('loads config from home directory', () => {
      const customConfig = {
        enabled: false,
        mode: 'detect' as const,
        entropyThreshold: 5.0,
        patterns: [],
      };
      fs.writeFileSync(homeConfigPath, JSON.stringify(customConfig));
      process.env.HOME = testDir;
      process.env.USERPROFILE = testDir;

      const result = loadConfig();

      expect(result.source).toBe(homeConfigPath);
      expect(result.config.enabled).toBe(false);
      expect(result.config.mode).toBe('detect');
      expect(result.config.entropyThreshold).toBe(5.0);
    });

    it('loads config from project root', () => {
      const customConfig = {
        minSecretLength: 16,
        maxSecretsPerSession: 50,
        patterns: [],
      };
      fs.writeFileSync(projectConfigPath, JSON.stringify(customConfig));

      const result = loadConfig();

      expect(result.source).toBe(projectConfigPath);
      expect(result.config.minSecretLength).toBe(16);
      expect(result.config.maxSecretsPerSession).toBe(50);
    });

    it('loads config from env var', () => {
      const customConfig = { enabled: false };
      fs.writeFileSync(envConfigPath, JSON.stringify(customConfig));
      process.env.OPENCODE_FILTER_CONFIG = envConfigPath;

      const result = loadConfig();

      expect(result.source).toBe(envConfigPath);
      expect(result.config.enabled).toBe(false);
    });

    it('handles malformed JSON gracefully', () => {
      fs.writeFileSync(projectConfigPath, 'not valid json {{{');

      const result = loadConfig();

      expect(result.source).toBe('defaults');
      expect(result.config).toEqual(DEFAULT_FILTER_CONFIG);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain('Failed to parse');
    });

    it('handles missing config fields with defaults', () => {
      const partialConfig = { enabled: false };
      fs.writeFileSync(projectConfigPath, JSON.stringify(partialConfig));

      const result = loadConfig();

      expect(result.config.enabled).toBe(false);
      expect(result.config.entropyThreshold).toBe(DEFAULT_FILTER_CONFIG.entropyThreshold);
      expect(result.config.mode).toBe(DEFAULT_FILTER_CONFIG.mode);
    });
  });

  describe('validateConfig', () => {
    it('returns empty config for null input', () => {
      const result = validateConfig(null);

      expect(result.config).toEqual({});
      expect(result.warnings).toContain('Config is not an object, using defaults');
    });

    it('returns empty config for non-object input', () => {
      const result = validateConfig('string');

      expect(result.config).toEqual({});
      expect(result.warnings).toContain('Config is not an object, using defaults');
    });

    it('validates entropyThreshold must be a number', () => {
      const result = validateConfig({ entropyThreshold: 'not a number' });

      expect(result.config.entropyThreshold).toBeUndefined();
      expect(result.warnings).toContain('entropyThreshold is not a valid number, using default');
    });

    it('accepts valid entropyThreshold', () => {
      const result = validateConfig({ entropyThreshold: 4.5 });

      expect(result.config.entropyThreshold).toBe(4.5);
      expect(result.warnings).not.toContain('entropyThreshold is not a valid number, using default');
    });

    it('validates minSecretLength must be positive', () => {
      const result = validateConfig({ minSecretLength: -5 });

      expect(result.config.minSecretLength).toBeUndefined();
      expect(result.warnings).toContain('minSecretLength is not a valid positive number, using default');
    });

    it('accepts valid minSecretLength', () => {
      const result = validateConfig({ minSecretLength: 12 });

      expect(result.config.minSecretLength).toBe(12);
    });

    it('validates maxSecretsPerSession must be positive', () => {
      const result = validateConfig({ maxSecretsPerSession: 0 });

      expect(result.config.maxSecretsPerSession).toBeUndefined();
      expect(result.warnings).toContain('maxSecretsPerSession is not a valid positive number, using default');
    });

    it('validates enabled must be boolean', () => {
      const result = validateConfig({ enabled: 'yes' });

      expect(result.config.enabled).toBeUndefined();
      expect(result.warnings).toContain('enabled is not a boolean, using default');
    });

    it('accepts valid enabled boolean', () => {
      const result = validateConfig({ enabled: false });

      expect(result.config.enabled).toBe(false);
    });

    it('validates mode must be one of allowed values', () => {
      const result = validateConfig({ mode: 'invalid' });

      expect(result.config.mode).toBeUndefined();
      expect(result.warnings).toContain('mode must be "detect", "redact", or "sanitize", using default');
    });

    it('accepts valid mode values', () => {
      expect(validateConfig({ mode: 'detect' }).config.mode).toBe('detect');
      expect(validateConfig({ mode: 'redact' }).config.mode).toBe('redact');
      expect(validateConfig({ mode: 'sanitize' }).config.mode).toBe('sanitize');
    });

    it('validates patterns array', () => {
      const result = validateConfig({ patterns: 'not an array' });

      expect(result.config.patterns).toBeUndefined();
      expect(result.warnings).toContain('patterns field is not an array, using defaults');
    });

    it('validates pattern objects have required fields', () => {
      const patterns = [{ name: 'test', pattern: 'test' }];
      const result = validateConfig({ patterns });

      expect(result.config.patterns).toEqual([]);
      expect(result.warnings[0]).toContain('missing required fields');
    });

    it('validates pattern regex is valid', () => {
      const patterns = [{
        name: 'test',
        pattern: '[invalid(',
        category: 'api_key',
        description: 'test',
        severity: 'high',
        example: 'test',
      }];
      const result = validateConfig({ patterns });

      expect(result.config.patterns).toEqual([]);
      expect(result.warnings[0]).toContain('invalid regex');
    });

    it('accepts valid patterns', () => {
      const patterns: SerializableSecretPattern[] = [{
        name: 'api-key',
        pattern: 'api[_-]?key[:=]\\s*[a-zA-Z0-9]{16,}',
        flags: 'i',
        category: 'api_key',
        description: 'API key pattern',
        severity: 'high',
        example: 'api_key=abc123def456ghi7',
      }];
      const result = validateConfig({ patterns });

      expect(result.config.patterns).toHaveLength(1);
      expect(result.config.patterns![0].name).toBe('api-key');
      expect(result.warnings).toHaveLength(0);
    });
  });

  describe('mergeWithDefaults', () => {
    it('returns defaults for empty config', () => {
      const result = mergeWithDefaults({});

      expect(result.patterns).toEqual(DEFAULT_FILTER_CONFIG.patterns);
      expect(result.entropyThreshold).toBe(DEFAULT_FILTER_CONFIG.entropyThreshold);
      expect(result.enabled).toBe(DEFAULT_FILTER_CONFIG.enabled);
      expect(result.mode).toBe(DEFAULT_FILTER_CONFIG.mode);
    });

    it('overrides defaults with provided values', () => {
      const result = mergeWithDefaults({
        enabled: false,
        entropyThreshold: 5.0,
      });

      expect(result.enabled).toBe(false);
      expect(result.entropyThreshold).toBe(5.0);
      expect(result.mode).toBe(DEFAULT_FILTER_CONFIG.mode);
    });

    it('deserializes serializable patterns', () => {
      const serializablePatterns: SerializableSecretPattern[] = [{
        name: 'test-pattern',
        pattern: 'test\\d+',
        flags: 'gi',
        category: 'api_key',
        description: 'Test pattern',
        severity: 'medium',
        example: 'test123',
      }];

      const result = mergeWithDefaults({ patterns: serializablePatterns });

      expect(result.patterns).toHaveLength(1);
      expect(result.patterns[0].name).toBe('test-pattern');
      expect(result.patterns[0].regex).toBeInstanceOf(RegExp);
      expect(result.patterns[0].regex.test('test123')).toBe(true);
    });

    it('preserves SecretPattern objects with RegExp', () => {
      const patterns: SecretPattern[] = [{
        name: 'direct-pattern',
        regex: /test\d+/i,
        category: 'api_key',
        description: 'Direct pattern',
        severity: 'low',
        example: 'test99',
      }];

      const result = mergeWithDefaults({ patterns });

      expect(result.patterns[0].regex).toBeInstanceOf(RegExp);
      expect(result.patterns[0].regex.test('test99')).toBe(true);
    });
  });

  describe('serializePattern', () => {
    it('converts SecretPattern to serializable format', () => {
      const pattern: SecretPattern = {
        name: 'test',
        regex: /api[_-]?key[:=]\s*[a-zA-Z0-9]{16,}/gi,
        category: 'api_key',
        description: 'API key',
        severity: 'high',
        example: 'api_key=abc123',
      };

      const result = serializePattern(pattern);

      expect(result.name).toBe('test');
      expect(result.pattern).toBe(pattern.regex.source);
      expect(result.flags).toBe('gi');
      expect(result.category).toBe('api_key');
    });
  });

  describe('saveConfig', () => {
    it('saves config to default location', () => {
      const config: FilterConfig = {
        patterns: [],
        entropyThreshold: 4.0,
        minSecretLength: 10,
        maxSecretsPerSession: 200,
        enabled: true,
        mode: 'detect',
      };

      process.env.HOME = testDir;
      process.env.USERPROFILE = testDir;

      saveConfig(config);

      expect(fs.existsSync(homeConfigPath)).toBe(true);

      const saved = JSON.parse(fs.readFileSync(homeConfigPath, 'utf-8'));
      expect(saved.entropyThreshold).toBe(4.0);
      expect(saved.mode).toBe('detect');
      expect(saved.patterns).toEqual([]);
    });

    it('saves config to custom path', () => {
      const customPath = path.join(testDir, 'custom-config.json');
      const config: FilterConfig = {
        patterns: [{
          name: 'test',
          regex: /test/i,
          category: 'api_key',
          description: 'test',
          severity: 'low',
          example: 'test',
        }],
        entropyThreshold: 3.0,
        minSecretLength: 5,
        maxSecretsPerSession: 100,
        enabled: false,
        mode: 'sanitize',
      };

      saveConfig(config, customPath);

      expect(fs.existsSync(customPath)).toBe(true);

      const saved = JSON.parse(fs.readFileSync(customPath, 'utf-8'));
      expect(saved.enabled).toBe(false);
      expect(saved.patterns[0].pattern).toBe('test');
      expect(saved.patterns[0].flags).toBe('i');
    });

    it('creates parent directories if needed', () => {
      const nestedPath = path.join(testDir, 'nested', 'deep', 'config.json');
      const config = DEFAULT_FILTER_CONFIG;

      saveConfig(config, nestedPath);

      expect(fs.existsSync(nestedPath)).toBe(true);
    });
  });

  describe('integration', () => {
    it('round-trip: save and load config', () => {
      const originalConfig: FilterConfig = {
        patterns: [{
          name: 'api-key',
          regex: /api[_-]?key[:=]\s*[a-zA-Z0-9]{16,}/i,
          category: 'api_key',
          description: 'API Key pattern',
          severity: 'high',
          example: 'api_key=abc123def456ghi7',
        }],
        entropyThreshold: 4.5,
        minSecretLength: 12,
        maxSecretsPerSession: 500,
        enabled: true,
        mode: 'redact',
      };

      const customPath = path.join(testDir, 'roundtrip.json');
      saveConfig(originalConfig, customPath);

      process.env.OPENCODE_FILTER_CONFIG = customPath;
      const loaded = loadConfig();

      expect(loaded.config.entropyThreshold).toBe(originalConfig.entropyThreshold);
      expect(loaded.config.minSecretLength).toBe(originalConfig.minSecretLength);
      expect(loaded.config.maxSecretsPerSession).toBe(originalConfig.maxSecretsPerSession);
      expect(loaded.config.enabled).toBe(originalConfig.enabled);
      expect(loaded.config.mode).toBe(originalConfig.mode);
      expect(loaded.config.patterns).toHaveLength(1);
      expect(loaded.config.patterns[0].name).toBe('api-key');
    });
  });
});
