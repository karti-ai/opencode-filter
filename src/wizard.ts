#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as readline from 'readline';
import {
  CLOUD_PATTERNS,
  CODE_HOSTING_PATTERNS,
  COMMUNICATION_PATTERNS,
  PAYMENT_PATTERNS,
  AUTHENTICATION_PATTERNS,
  SAAS_PATTERNS,
  INFRASTRUCTURE_PATTERNS,
  GENERIC_PATTERNS,
} from './patterns/v2/index.js';
import { FilterConfig, SecretPattern, FilterMode } from './types.js';
import { serializePattern } from './config.js';

const PATTERN_CATEGORIES = [
  { id: 'cloud', label: 'Cloud (AWS, Azure, GCP)', patterns: CLOUD_PATTERNS },
  { id: 'codeHosting', label: 'Code Hosting (GitHub, GitLab, Bitbucket)', patterns: CODE_HOSTING_PATTERNS },
  { id: 'communication', label: 'Communication (Slack, Discord, Teams, Telegram)', patterns: COMMUNICATION_PATTERNS },
  { id: 'payment', label: 'Payment (Stripe, PayPal, Square, Braintree)', patterns: PAYMENT_PATTERNS },
  { id: 'authentication', label: 'Authentication (JWT, OAuth, API keys)', patterns: AUTHENTICATION_PATTERNS },
  { id: 'saas', label: 'SaaS Services (50+ services)', patterns: SAAS_PATTERNS },
  { id: 'infrastructure', label: 'Infrastructure (DB, SSH, SSL, Docker, Kubernetes)', patterns: INFRASTRUCTURE_PATTERNS },
  { id: 'generic', label: 'Generic (passwords, secrets, tokens)', patterns: GENERIC_PATTERNS },
] as const;

const FAIL_MODES = [
  { value: 'fail-closed', label: 'closed (safe - block on errors)', description: 'Block when filter errors occur' },
  { value: 'fail-open', label: 'open (convenient - allow on errors)', description: 'Allow through when filter errors occur' },
] as const;

export interface WizardAnswers {
  selectedCategories: string[];
  entropyThreshold: number;
  failMode: 'fail-closed' | 'fail-open';
  enableAuditLogging: boolean;
  logFileLocation: string;
  updateOpencodeJson: boolean;
}

export interface WizardOptions {
  skipOpencodeJson?: boolean;
  configPath?: string;
  nonInteractive?: boolean;
}

export class ConfigWizard {
  private rl: readline.Interface;
  private answers: Partial<WizardAnswers> = {};
  private options: WizardOptions;

  constructor(options: WizardOptions = {}) {
    this.options = options;
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
  }

  async run(): Promise<WizardAnswers> {
    console.log('\n🛡️  Welcome to OpenCode Filter Configuration Wizard\n');
    console.log('This wizard will help you set up secret filtering for your project.\n');

    try {
      this.answers.selectedCategories = await this.selectCategories();
      this.answers.entropyThreshold = await this.configureEntropyThreshold();
      this.answers.failMode = await this.selectFailMode();
      this.answers.enableAuditLogging = await this.configureAuditLogging();

      if (this.answers.enableAuditLogging) {
        this.answers.logFileLocation = await this.configureLogLocation();
      }

      if (!this.options.skipOpencodeJson) {
        this.answers.updateOpencodeJson = await this.askUpdateOpencodeJson();
      } else {
        this.answers.updateOpencodeJson = false;
      }

      const confirmed = await this.confirmConfiguration(this.answers as WizardAnswers);

      if (!confirmed) {
        console.log('\n❌ Configuration cancelled. Run again to start over.\n');
        process.exit(0);
      }

      await this.createConfiguration(this.answers as WizardAnswers);

      return this.answers as WizardAnswers;
    } finally {
      this.rl.close();
    }
  }

  private async selectCategories(): Promise<string[]> {
    console.log('? What types of secrets do you want to detect? (select multiple)');
    console.log('  Press space to toggle, enter to confirm\n');

    const selected = new Set<number>();
    let currentIndex = 0;

    const render = () => {
      readline.moveCursor(process.stdout, 0, -PATTERN_CATEGORIES.length - 2);
      readline.clearScreenDown(process.stdout);

      console.log('? What types of secrets do you want to detect? (select multiple)');
      console.log('  Press space to toggle, enter to confirm\n');

      PATTERN_CATEGORIES.forEach((cat, index) => {
        const isSelected = selected.has(index);
        const isCurrent = index === currentIndex;
        const checkbox = isSelected ? '◉' : '◯';
        const cursor = isCurrent ? '>' : ' ';
        const count = cat.patterns.length;
        console.log(`  ${cursor} ${checkbox} ${cat.label} (${count} patterns)`);
      });
    };

    PATTERN_CATEGORIES.forEach((cat) => {
      console.log(`    ◯ ${cat.label} (${cat.patterns.length} patterns)`);
    });

    return new Promise((resolve) => {
      const stdin = process.stdin;
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding('utf8');

      const onKey = (key: string) => {
        const keyCode = key.charCodeAt(0);

        if (key === '\u0003' || key === '\u001b') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onKey);
          console.log('\n');
          process.exit(0);
        }

        if (key === '\r' || key === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onKey);
          
          if (selected.size === 0) {
            PATTERN_CATEGORIES.forEach((_, i) => selected.add(i));
          }
          
          const result = Array.from(selected).map(i => PATTERN_CATEGORIES[i].id);
          
          readline.moveCursor(process.stdout, 0, PATTERN_CATEGORIES.length - currentIndex);
          readline.clearScreenDown(process.stdout);
          
          console.log('\n✓ Selected categories:\n');
          result.forEach(id => {
            const cat = PATTERN_CATEGORIES.find(c => c.id === id);
            if (cat) console.log(`  • ${cat.label}`);
          });
          console.log('');
          
          resolve(result);
          return;
        }

        if (key === ' ') {
          if (selected.has(currentIndex)) {
            selected.delete(currentIndex);
          } else {
            selected.add(currentIndex);
          }
          render();
        }

        if (key === '\u001b[A' && currentIndex > 0) {
          currentIndex--;
          render();
        }

        if (key === '\u001b[B' && currentIndex < PATTERN_CATEGORIES.length - 1) {
          currentIndex++;
          render();
        }
      };

      stdin.on('data', onKey);
    });
  }

  private async configureEntropyThreshold(): Promise<number> {
    const defaultValue = 4.5;
    
    console.log(`? What's your entropy threshold? (1.0 - 10.0)`);
    console.log(`  Higher values = more strict detection`);
    console.log(`  Current: ${defaultValue}\n`);

    const answer = await this.askQuestion(`  > ${defaultValue} `);
    
    if (!answer.trim()) {
      console.log(`  Using default: ${defaultValue}\n`);
      return defaultValue;
    }

    const threshold = parseFloat(answer);
    
    if (isNaN(threshold) || threshold < 1 || threshold > 10) {
      console.log('  ⚠ Invalid value. Using default: 4.5\n');
      return 4.5;
    }

    console.log(`  Set to: ${threshold}\n`);
    return threshold;
  }

  private async selectFailMode(): Promise<'fail-closed' | 'fail-open'> {
    console.log('? Fail mode when filter encounters errors:\n');

    let currentIndex = 0;

    const render = () => {
      readline.moveCursor(process.stdout, 0, -FAIL_MODES.length);
      readline.clearScreenDown(process.stdout);

      FAIL_MODES.forEach((mode, index) => {
        const isCurrent = index === currentIndex;
        const cursor = isCurrent ? '>' : ' ';
        console.log(`  ${cursor} ${mode.label}`);
        if (isCurrent) {
          console.log(`    ${mode.description}`);
        }
      });
    };

    FAIL_MODES.forEach((mode, index) => {
      const cursor = index === 0 ? '>' : ' ';
      console.log(`  ${cursor} ${mode.label}`);
      if (index === 0) {
        console.log(`    ${mode.description}`);
      }
    });

    return new Promise((resolve) => {
      const stdin = process.stdin;
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding('utf8');

      const onKey = (key: string) => {
        if (key === '\u0003' || key === '\u001b') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onKey);
          console.log('\n');
          process.exit(0);
        }

        if (key === '\r' || key === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onKey);
          
          const result = FAIL_MODES[currentIndex].value;
          
          readline.moveCursor(process.stdout, 0, FAIL_MODES.length - currentIndex);
          readline.clearScreenDown(process.stdout);
          
          console.log(`\n✓ Selected: ${result}\n`);
          resolve(result as 'fail-closed' | 'fail-open');
          return;
        }

        if (key === '\u001b[A' && currentIndex > 0) {
          currentIndex--;
          render();
        }

        if (key === '\u001b[B' && currentIndex < FAIL_MODES.length - 1) {
          currentIndex++;
          render();
        }
      };

      stdin.on('data', onKey);
    });
  }

  private async configureAuditLogging(): Promise<boolean> {
    console.log('? Enable audit logging? (Y/n)');
    console.log('  Logs detected secrets to a file for security review\n');

    const answer = await this.askQuestion('  > y ');
    const enabled = answer.trim().toLowerCase() !== 'n';
    
    console.log(`  ${enabled ? '✓ Enabled' : '✗ Disabled'}\n`);
    return enabled;
  }

  private async configureLogLocation(): Promise<string> {
    const defaultPath = path.join(os.homedir(), '.config', 'opencode', 'filter-audit.log');
    
    console.log('? Log file location:');
    console.log(`  Default: ${defaultPath}\n`);

    const answer = await this.askQuestion(`  > ${defaultPath} `);
    const location = answer.trim() || defaultPath;
    
    console.log(`  Set to: ${location}\n`);
    return location;
  }

  private async askUpdateOpencodeJson(): Promise<boolean> {
    const opencodeJsonPath = path.join(process.cwd(), 'opencode.json');
    
    if (!fs.existsSync(opencodeJsonPath)) {
      console.log('ℹ No opencode.json found in current directory.\n');
      return false;
    }

    console.log('? Update opencode.json to add the filter plugin? (Y/n)');
    console.log(`  Found: ${opencodeJsonPath}\n`);

    const answer = await this.askQuestion('  > y ');
    const update = answer.trim().toLowerCase() !== 'n';
    
    console.log(`  ${update ? '✓ Will update' : '✗ Will not update'}\n`);
    return update;
  }

  private async confirmConfiguration(answers: WizardAnswers): Promise<boolean> {
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│           Configuration Summary                               │');
    console.log('├─────────────────────────────────────────────────────────────┤');
    
    console.log(`│ Pattern Categories:                                         │`);
    answers.selectedCategories.forEach(id => {
      const cat = PATTERN_CATEGORIES.find(c => c.id === id);
      if (cat) {
        const label = cat.label.substring(0, 45).padEnd(45);
        console.log(`│   • ${label} │`);
      }
    });
    
    console.log(`│ Entropy Threshold: ${answers.entropyThreshold.toString().padEnd(41)} │`);
    console.log(`│ Fail Mode: ${answers.failMode.padEnd(49)} │`);
    console.log(`│ Audit Logging: ${(answers.enableAuditLogging ? 'Enabled' : 'Disabled').padEnd(44)} │`);
    
    if (answers.enableAuditLogging) {
      const logPath = answers.logFileLocation.substring(0, 49).padEnd(49);
      console.log(`│ Log Location: ${logPath} │`);
    }
    
    console.log(`│ Update opencode.json: ${(answers.updateOpencodeJson ? 'Yes' : 'No').padEnd(38)} │`);
    console.log('└─────────────────────────────────────────────────────────────┘\n');

    const answer = await this.askQuestion('? Create configuration with these settings? (Y/n) ');
    return answer.trim().toLowerCase() !== 'n';
  }

  private async createConfiguration(answers: WizardAnswers): Promise<void> {
    const configPath = this.options.configPath || this.getDefaultConfigPath();
    
    const patterns = this.getPatternsForCategories(answers.selectedCategories);
    
    const config = {
      enabled: true,
      mode: 'redact' as FilterMode,
      failMode: answers.failMode,
      entropyThreshold: answers.entropyThreshold,
      minSecretLength: 8,
      maxSecretsPerSession: 1000,
      patterns: patterns.map(serializePattern),
      customPatterns: [],
      auditLogging: answers.enableAuditLogging ? {
        enabled: true,
        logFile: answers.logFileLocation,
      } : undefined,
    };

    const dir = path.dirname(configPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
    console.log(`✓ Created ${configPath}`);

    if (answers.updateOpencodeJson) {
      await this.updateOpencodeJson();
    }
    console.log('\n✅ Configuration complete!\n');
    console.log('Next steps:');
    console.log('  1. Review your configuration file');
    console.log('  2. Add custom patterns if needed');
    console.log('  3. Test with: opencode-filter --config ' + configPath);
    console.log('\nFor more information, visit:');
    console.log('  https://github.com/YOUR_ORG/opencode-filter#readme\n');
  }

  private getPatternsForCategories(categoryIds: string[]): SecretPattern[] {
    const patterns: SecretPattern[] = [];
    
    for (const id of categoryIds) {
      const category = PATTERN_CATEGORIES.find(c => c.id === id);
      if (category) {
        patterns.push(...category.patterns);
      }
    }
    
    return patterns;
  }

  private getDefaultConfigPath(): string {
    const projectPath = path.join(process.cwd(), 'filter.config.json');
    if (fs.existsSync(projectPath)) {
      return projectPath;
    }
    
    return path.join(os.homedir(), '.config', 'opencode', 'filter.config.json');
  }

  private async updateOpencodeJson(): Promise<void> {
    const opencodeJsonPath = path.join(process.cwd(), 'opencode.json');
    
    try {
      let opencodeConfig: Record<string, unknown> = {};
      
      if (fs.existsSync(opencodeJsonPath)) {
        const content = fs.readFileSync(opencodeJsonPath, 'utf-8');
        opencodeConfig = JSON.parse(content);
      }

      const plugins = opencodeConfig.plugin || [];
      const pluginArray = Array.isArray(plugins) ? plugins : [plugins];
      
      if (!pluginArray.includes('opencode-filter')) {
        pluginArray.push('opencode-filter');
        opencodeConfig.plugin = pluginArray;
        
        fs.writeFileSync(opencodeJsonPath, JSON.stringify(opencodeConfig, null, 2), 'utf-8');
        console.log(`✓ Added plugin to ${opencodeJsonPath}`);
      } else {
        console.log(`ℹ Plugin already in ${opencodeJsonPath}`);
      }
    } catch (error) {
      console.error(`✗ Failed to update opencode.json: ${(error as Error).message}`);
    }
  }

  private askQuestion(question: string): Promise<string> {
    return new Promise((resolve) => {
      this.rl.question(question, (answer) => {
        resolve(answer);
      });
    });
  }
}

export async function runWizard(options: WizardOptions = {}): Promise<WizardAnswers> {
  const wizard = new ConfigWizard(options);
  return wizard.run();
}

export function createConfigFromAnswers(answers: WizardAnswers): Record<string, unknown> {
  const selectedPatterns: SecretPattern[] = [];
  
  for (const id of answers.selectedCategories) {
    const category = PATTERN_CATEGORIES.find(c => c.id === id);
    if (category) {
      selectedPatterns.push(...category.patterns);
    }
  }

  return {
    enabled: true,
    mode: 'redact',
    failMode: answers.failMode,
    entropyThreshold: answers.entropyThreshold,
    minSecretLength: 8,
    maxSecretsPerSession: 1000,
    patterns: selectedPatterns.map(serializePattern),
    customPatterns: [],
    auditLogging: answers.enableAuditLogging ? {
      enabled: true,
      logFile: answers.logFileLocation,
    } : undefined,
  };
}


