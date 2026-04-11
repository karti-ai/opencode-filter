import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { 
  ConfigWizard, 
  runWizard, 
  createConfigFromAnswers, 
  WizardAnswers,
  WizardOptions 
} from './wizard.js';

const TEST_CONFIG_DIR = path.join(os.tmpdir(), 'opencode-filter-test-' + Date.now());

describe('Wizard', () => {
  beforeEach(() => {
    if (!fs.existsSync(TEST_CONFIG_DIR)) {
      fs.mkdirSync(TEST_CONFIG_DIR, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(TEST_CONFIG_DIR)) {
      fs.rmSync(TEST_CONFIG_DIR, { recursive: true, force: true });
    }
  });

  describe('createConfigFromAnswers', () => {
    it('should create a valid config from minimal answers', () => {
      const answers: WizardAnswers = {
        selectedCategories: ['cloud'],
        entropyThreshold: 4.5,
        failMode: 'fail-closed',
        enableAuditLogging: false,
        logFileLocation: '',
        updateOpencodeJson: false,
      };

      const config = createConfigFromAnswers(answers);

      expect(config.enabled).toBe(true);
      expect(config.mode).toBe('redact');
      expect(config.failMode).toBe('fail-closed');
      expect(config.entropyThreshold).toBe(4.5);
      expect(config.minSecretLength).toBe(8);
      expect(config.maxSecretsPerSession).toBe(1000);
      expect(config.patterns).toBeInstanceOf(Array);
      expect(config.patterns.length).toBeGreaterThan(0);
      expect(config.customPatterns).toEqual([]);
      expect(config.auditLogging).toBeUndefined();
    });

    it('should include audit logging when enabled', () => {
      const answers: WizardAnswers = {
        selectedCategories: ['cloud', 'payment'],
        entropyThreshold: 5.5,
        failMode: 'fail-open',
        enableAuditLogging: true,
        logFileLocation: '/custom/path/audit.log',
        updateOpencodeJson: false,
      };

      const config = createConfigFromAnswers(answers);

      expect(config.failMode).toBe('fail-open');
      expect(config.entropyThreshold).toBe(5.5);
      expect(config.auditLogging).toEqual({
        enabled: true,
        logFile: '/custom/path/audit.log',
      });
    });

    it('should include patterns from multiple categories', () => {
      const answers: WizardAnswers = {
        selectedCategories: ['cloud', 'authentication', 'generic'],
        entropyThreshold: 4.0,
        failMode: 'fail-closed',
        enableAuditLogging: false,
        logFileLocation: '',
        updateOpencodeJson: false,
      };

      const config = createConfigFromAnswers(answers);
      const patternCount = config.patterns.length as number;
      
      expect(patternCount).toBeGreaterThan(0);
      
      const patternNames = (config.patterns as Array<{name: string}>).map(p => p.name);
      expect(patternNames.some(name => name.includes('aws'))).toBe(true);
      expect(patternNames.some(name => name.includes('jwt') || name.includes('auth'))).toBe(true);
    });

    it('should handle empty categories gracefully', () => {
      const answers: WizardAnswers = {
        selectedCategories: [],
        entropyThreshold: 3.0,
        failMode: 'fail-closed',
        enableAuditLogging: false,
        logFileLocation: '',
        updateOpencodeJson: false,
      };

      const config = createConfigFromAnswers(answers);
      
      expect(config.patterns).toEqual([]);
      expect(config.customPatterns).toEqual([]);
    });
  });

  describe('ConfigWizard', () => {
    it('should initialize with default options', () => {
      const wizard = new ConfigWizard();
      expect(wizard).toBeDefined();
    });

    it('should initialize with custom options', () => {
      const options: WizardOptions = {
        configPath: path.join(TEST_CONFIG_DIR, 'test.config.json'),
        skipOpencodeJson: true,
      };
      const wizard = new ConfigWizard(options);
      expect(wizard).toBeDefined();
    });
  });

  describe('Config file generation', () => {
    it('should generate valid filter.config.json structure', () => {
      const answers: WizardAnswers = {
        selectedCategories: ['cloud', 'payment'],
        entropyThreshold: 4.5,
        failMode: 'fail-closed',
        enableAuditLogging: true,
        logFileLocation: path.join(TEST_CONFIG_DIR, 'audit.log'),
        updateOpencodeJson: false,
      };

      const config = createConfigFromAnswers(answers);
      const configPath = path.join(TEST_CONFIG_DIR, 'filter.config.json');
      
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
      
      const loaded = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      
      expect(loaded.enabled).toBe(true);
      expect(loaded.mode).toBe('redact');
      expect(loaded.failMode).toBe('fail-closed');
      expect(loaded.entropyThreshold).toBe(4.5);
      expect(loaded.patterns).toBeInstanceOf(Array);
      expect(loaded.auditLogging.enabled).toBe(true);
    });

    it('should generate patterns with required fields', () => {
      const answers: WizardAnswers = {
        selectedCategories: ['cloud'],
        entropyThreshold: 4.5,
        failMode: 'fail-closed',
        enableAuditLogging: false,
        logFileLocation: '',
        updateOpencodeJson: false,
      };

      const config = createConfigFromAnswers(answers);
      const patterns = config.patterns as Array<{
        name: string;
        pattern: string;
        category: string;
        description: string;
        severity: string;
        example: string;
      }>;

      patterns.forEach(pattern => {
        expect(pattern.name).toBeDefined();
        expect(typeof pattern.name).toBe('string');
        expect(pattern.pattern).toBeDefined();
        expect(typeof pattern.pattern).toBe('string');
        expect(pattern.category).toBeDefined();
        expect(pattern.description).toBeDefined();
        expect(pattern.severity).toBeDefined();
        expect(['low', 'medium', 'high', 'critical']).toContain(pattern.severity);
        expect(pattern.example).toBeDefined();
      });
    });
  });

  describe('Entropy threshold validation', () => {
    it('should accept valid entropy thresholds', () => {
      const thresholds = [1.0, 5.0, 10.0, 4.5, 3.14159];
      
      thresholds.forEach(threshold => {
        const answers: WizardAnswers = {
          selectedCategories: ['generic'],
          entropyThreshold: threshold,
          failMode: 'fail-closed',
          enableAuditLogging: false,
          logFileLocation: '',
          updateOpencodeJson: false,
        };

        const config = createConfigFromAnswers(answers);
        expect(config.entropyThreshold).toBe(threshold);
      });
    });
  });

  describe('Fail mode options', () => {
    it('should handle fail-closed mode', () => {
      const answers: WizardAnswers = {
        selectedCategories: ['generic'],
        entropyThreshold: 4.5,
        failMode: 'fail-closed',
        enableAuditLogging: false,
        logFileLocation: '',
        updateOpencodeJson: false,
      };

      const config = createConfigFromAnswers(answers);
      expect(config.failMode).toBe('fail-closed');
    });

    it('should handle fail-open mode', () => {
      const answers: WizardAnswers = {
        selectedCategories: ['generic'],
        entropyThreshold: 4.5,
        failMode: 'fail-open',
        enableAuditLogging: false,
        logFileLocation: '',
        updateOpencodeJson: false,
      };

      const config = createConfigFromAnswers(answers);
      expect(config.failMode).toBe('fail-open');
    });
  });

  describe('Pattern categories', () => {
    it('should have patterns for all categories', () => {
      const categories = [
        'cloud',
        'codeHosting', 
        'communication',
        'payment',
        'authentication',
        'saas',
        'infrastructure',
        'generic'
      ];

      categories.forEach(category => {
        const answers: WizardAnswers = {
          selectedCategories: [category],
          entropyThreshold: 4.5,
          failMode: 'fail-closed',
          enableAuditLogging: false,
          logFileLocation: '',
          updateOpencodeJson: false,
        };

        const config = createConfigFromAnswers(answers);
        expect((config.patterns as Array<unknown>).length).toBeGreaterThan(0);
      });
    });
  });
});
