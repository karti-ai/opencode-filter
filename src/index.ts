/**
 * OpenCode Filter - Main Entry Point
 *
 * A powerful filtering and processing tool for OpenCode workflows.
 */

export * from './types.js';
export * from './hooks.js';
export * from './config.js';
export {
  SecretDetector,
  RegexEngineStub,
  EntropyEngineStub,
  createDefaultDetector,
  type EntropyEngine,
} from './detector.js';
export {
  RegexEngine,
  ReDoSError,
  DEFAULT_REGEX_ENGINE_CONFIG,
  type RegexEngineConfig,
} from './patterns/regex-engine.js';
export type { RegexEngine as RegexEngineInterface } from './detector.js';
export {
  getBuiltinPatterns,
  getPatternsByCategory,
  getPatternsBySeverity,
  findPatternByName,
  BUILTIN_PATTERNS as BUILTIN_SECRET_PATTERNS,
} from './patterns/builtin.js';

/**
 * Legacy filter configuration (deprecated, use FilterConfig from types.ts)
 * @deprecated Use the new FilterConfig from types.ts
 */
export interface LegacyFilterConfig {
  input?: string;
  output?: string;
  rules?: FilterRule[];
}

/**
 * Filter rule for legacy filter
 * @deprecated Use SecretPattern from types.ts
 */
export interface FilterRule {
  name: string;
  condition: (item: unknown) => boolean;
  action?: "include" | "exclude" | "transform";
}

/**
 * Main filter class (legacy)
 * @deprecated Use SecretFilterPlugin interface from types.ts
 */
export class OpenCodeFilter {
  private config: LegacyFilterConfig;

  constructor(config: LegacyFilterConfig = {}) {
    this.config = config;
  }

  async process<T>(data: T[]): Promise<T[]> {
    let result = [...data];

    for (const rule of this.config.rules || []) {
      if (rule.action === "exclude") {
        result = result.filter((item) => !rule.condition(item));
      } else if (rule.action === "include") {
        result = result.filter((item) => rule.condition(item));
      }
    }

    return result;
  }

  addRule(rule: FilterRule): void {
    if (!this.config.rules) {
      this.config.rules = [];
    }
    this.config.rules.push(rule);
  }
}

export const VERSION = "0.1.0";

export { secretFilterPlugin as default } from './hooks.js';

export { default as tuiPlugin } from './tui-plugin.js';
export * from './visual/feedback-manager.js';
