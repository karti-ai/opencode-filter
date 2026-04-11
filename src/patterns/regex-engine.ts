import type {
  SecretPattern,
  SecretCategory,
  SecretSeverity,
  DetectedSecret,
  SecretPosition,
  ConfidenceLevel,
} from '../types.js';

export interface RegexEngineConfig {
  readonly timeoutMs: number;
  readonly enableReDoSProtection: boolean;
  readonly maxInputLength: number;
  readonly customPatterns?: readonly SecretPattern[];
}

export const DEFAULT_REGEX_ENGINE_CONFIG: RegexEngineConfig = {
  timeoutMs: 100,
  enableReDoSProtection: true,
  maxInputLength: 10 * 1024 * 1024,
} as const;

interface PatternMatch {
  readonly pattern: SecretPattern;
  readonly value: string;
  readonly index: number;
  readonly length: number;
}

interface CompiledPattern extends SecretPattern {
  compiledRegex: RegExp;
  isMultiline: boolean;
}

export class ReDoSError extends Error {
  constructor(pattern: string, timeoutMs: number) {
    super(
      `Regex pattern "${pattern}" exceeded timeout of ${timeoutMs}ms (potential ReDoS attack)`
    );
    this.name = 'ReDoSError';
  }
}

class SafeRegexExecutor {
  private timeoutMs: number;
  private enabled: boolean;

  constructor(timeoutMs: number, enabled: boolean) {
    this.timeoutMs = timeoutMs;
    this.enabled = enabled;
  }

  *findAll(pattern: CompiledPattern, text: string): Generator<PatternMatch> {
    const regex = new RegExp(
      pattern.compiledRegex.source,
      pattern.compiledRegex.flags.includes('g')
        ? pattern.compiledRegex.flags
        : pattern.compiledRegex.flags + 'g'
    );

    const startTime = performance.now();
    let match: RegExpExecArray | null;
    let matchCount = 0;
    const maxMatches = 10000;

    try {
      while ((match = regex.exec(text)) !== null) {
        matchCount++;
        
        if (matchCount % 100 === 0) {
          const elapsed = performance.now() - startTime;
          if (elapsed > this.timeoutMs) {
            throw new ReDoSError(pattern.name, this.timeoutMs);
          }
        }

        if (match.index === regex.lastIndex) {
          regex.lastIndex++;
        }

        if (matchCount > maxMatches) {
          break;
        }

        yield {
          pattern,
          value: match[0],
          index: match.index,
          length: match[0].length,
        };
      }
    } catch (error) {
      if (error instanceof ReDoSError) {
        throw error;
      }
    }
  }
}

export const BUILTIN_PATTERNS: Omit<SecretPattern, 'regex'>[] = [
  {
    name: 'aws_access_key_id',
    category: 'api_key',
    description: 'AWS Access Key ID (AKIA... format)',
    severity: 'critical',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },
  {
    name: 'aws_secret_access_key',
    category: 'api_key',
    description: 'AWS Secret Access Key',
    severity: 'critical',
    example: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },
  {
    name: 'github_pat',
    category: 'token',
    description: 'GitHub Personal Access Token',
    severity: 'critical',
    example: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'github_oauth',
    category: 'token',
    description: 'GitHub OAuth Token',
    severity: 'high',
    example: 'gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'github_app_token',
    category: 'token',
    description: 'GitHub App Token',
    severity: 'critical',
    example: 'ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'slack_token',
    category: 'token',
    description: 'Slack API Token',
    severity: 'high',
    example: 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
  },
  {
    name: 'slack_webhook',
    category: 'credential',
    description: 'Slack Webhook URL',
    severity: 'high',
    example: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
  },
  {
    name: 'stripe_live_key',
    category: 'api_key',
    description: 'Stripe Live API Key',
    severity: 'critical',
    example: 'sk_live_abcdefghijklmnopqrstuvwxyz012345',
  },
  {
    name: 'stripe_test_key',
    category: 'api_key',
    description: 'Stripe Test API Key',
    severity: 'medium',
    example: 'sk_test_abcdefghijklmnopqrstuvwxyz012345',
  },
  {
    name: 'jwt_token',
    category: 'token',
    description: 'JSON Web Token',
    severity: 'high',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  },
  {
    name: 'password_assignment',
    category: 'password',
    description: 'Password in code (assignment)',
    severity: 'critical',
    example: 'password = "secret123"',
  },
  {
    name: 'password_key_value',
    category: 'password',
    description: 'Password as key-value pair',
    severity: 'critical',
    example: 'password: secret123',
  },
  {
    name: 'generic_api_key',
    category: 'api_key',
    description: 'Generic API key pattern',
    severity: 'medium',
    example: 'api_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'api_key_header',
    category: 'api_key',
    description: 'API key in Authorization header',
    severity: 'high',
    example: 'Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'private_key_pem',
    category: 'private_key',
    description: 'PEM format private key',
    severity: 'critical',
    example: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAxgNS...',
  },
  {
    name: 'database_url',
    category: 'connection_string',
    description: 'Database connection string with credentials',
    severity: 'critical',
    example: 'postgresql://user:password@localhost:5432/db',
  },
  {
    name: 'env_secret',
    category: 'environment_variable',
    description: 'Environment variable with secret value',
    severity: 'high',
    example: 'SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'bearer_token',
    category: 'token',
    description: 'Bearer token pattern',
    severity: 'high',
    example: 'Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'basic_auth',
    category: 'credential',
    description: 'Basic authentication header',
    severity: 'critical',
    example: 'Basic dXNlcjpwYXNzd29yZA==',
  },
  {
    name: 'gcp_api_key',
    category: 'api_key',
    description: 'Google Cloud API Key',
    severity: 'high',
    example: 'AIzaSyDdI0hCZtE6vySjMm-WEf18o9dq7d3',
  },
];

const PATTERN_REGEXES: Record<string, { regex: RegExp; isMultiline?: boolean }> = {
  aws_access_key_id: { regex: /AKIA[0-9A-Z]{16}/g },
  aws_secret_access_key: { regex: /(?:[^A-Z]|^)([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)/g },
  github_pat: { regex: /ghp_[a-zA-Z0-9]{36}/g },
  github_oauth: { regex: /gho_[a-zA-Z0-9]{36}/g },
  github_app_token: { regex: /ghs_[a-zA-Z0-9]{36}/g },
  slack_token: { regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(?:-[a-zA-Z0-9]{24})?/g },
  slack_webhook: { regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,24}\/[a-zA-Z0-9_]{24}/g },
  stripe_live_key: { regex: /sk_live_[0-9a-zA-Z]{24,99}/g },
  stripe_test_key: { regex: /sk_test_[0-9a-zA-Z]{24,99}/g },
  jwt_token: { regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g },
  password_assignment: { regex: /password\s*[=:]\s*["'][^"']{8,}["']/gi },
  password_key_value: { regex: /password["']?\s*[=:]\s*[^\s"']{8,}/gi },
  generic_api_key: { regex: /(?:api[_-]?key|apikey)["']?\s*[=:]\s*["']?[a-zA-Z0-9_\-]{16,}["']?/gi },
  api_key_header: { regex: /Authorization:\s*Bearer\s+[a-zA-Z0-9_\-\.=]{20,}/gi },
  private_key_pem: {
    regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    isMultiline: true,
  },
  database_url: {
    regex: /(?:postgres|mysql|mongodb|redis|amqp)?:\/\/[a-zA-Z0-9._-]+:[^@\s]+@[a-zA-Z0-9._-]+:\d+\/[a-zA-Z0-9._-]*/gi,
  },
  env_secret: { regex: /(?:SECRET|KEY|TOKEN|PW|PASS|AUTH)[A-Z_]*\s*=\s*[^\s]{8,}/gi },
  bearer_token: { regex: /Bearer\s+[a-zA-Z0-9_\-\.=]{20,}/gi },
  basic_auth: { regex: /Basic\s+[a-zA-Z0-9+/=]{10,}/gi },
  gcp_api_key: { regex: /AIza[0-9A-Za-z_-]{35}/g },
};

function isSafeRegex(pattern: string): boolean {
  const dangerousPatterns = [
    /\([^)]*\+[^)]*\+[^)]*\)/,
    /\([^)]*\*[^)]*\*[^)]*\)/,
    /\([^)]*\+[^)]*\*[^)]*\)/,
    /\([^)]*\*[^)]*\+[^)]*\)/,
    /\(\?\:.*\)\+\([^)]*\)\+/,
    /\([^)]*\)\+\$/,
    /\([^)]*\)\*\$/,
  ];

  for (const danger of dangerousPatterns) {
    if (danger.test(pattern)) {
      return false;
    }
  }

  const nestedQuantifiers = /\([^)]*[+*{][^)]*\)[+*{]/;
  if (nestedQuantifiers.test(pattern)) {
    const safeNestedPatterns = [
      /eyJ/,
      /-----BEGIN/,
    ];
    const isAllowed = safeNestedPatterns.some(p => p.test(pattern));
    if (!isAllowed) {
      return false;
    }
  }

  if (pattern.length > 1000) {
    return false;
  }

  return true;
}

export class RegexEngine {
  private patterns: CompiledPattern[];
  private config: RegexEngineConfig;
  private executor: SafeRegexExecutor;

  constructor(config: Partial<RegexEngineConfig> = {}) {
    this.config = { ...DEFAULT_REGEX_ENGINE_CONFIG, ...config };
    this.executor = new SafeRegexExecutor(
      this.config.timeoutMs,
      this.config.enableReDoSProtection
    );
    this.patterns = this.compilePatterns();
  }

  private compilePatterns(): CompiledPattern[] {
    const compiled: CompiledPattern[] = [];

    for (const pattern of BUILTIN_PATTERNS) {
      const regexConfig = PATTERN_REGEXES[pattern.name];
      if (regexConfig) {
        if (this.config.enableReDoSProtection && !isSafeRegex(regexConfig.regex.source)) {
          continue;
        }

        compiled.push({
          ...pattern,
          regex: regexConfig.regex,
          compiledRegex: regexConfig.regex,
          isMultiline: regexConfig.isMultiline ?? false,
        });
      }
    }

    if (this.config.customPatterns) {
      for (const pattern of this.config.customPatterns) {
        if (this.config.enableReDoSProtection && !isSafeRegex(pattern.regex.source)) {
          throw new ReDoSError(pattern.name, this.config.timeoutMs);
        }

        compiled.push({
          ...pattern,
          compiledRegex: pattern.regex,
          isMultiline: pattern.regex.multiline || pattern.regex.dotAll,
        });
      }
    }

    return compiled;
  }

  getPatterns(): readonly CompiledPattern[] {
    return this.patterns;
  }

  private calculatePosition(text: string, index: number, length: number): SecretPosition {
    const beforeText = text.substring(0, index);
    const lines = beforeText.split('\n');
    const line = lines.length;
    const column = lines[lines.length - 1].length;

    return {
      start: index,
      end: index + length,
      line,
      column,
    };
  }

  private calculateConfidence(pattern: SecretPattern, value: string): ConfidenceLevel {
    if (value.length >= 24 && /[a-zA-Z]/.test(value) && /[0-9]/.test(value)) {
      return 'high';
    }
    if (value.length >= 16) {
      return 'medium';
    }
    return 'low';
  }

  private generatePlaceholder(pattern: SecretPattern, index: number): string {
    return `<${pattern.category.toUpperCase()}_${pattern.name.toUpperCase()}_${index}>`;
  }

  detect(text: string): DetectedSecret[] {
    if (text.length > this.config.maxInputLength) {
      throw new Error(
        `Input exceeds maximum length of ${this.config.maxInputLength} characters`
      );
    }

    const detected: DetectedSecret[] = [];
    const seen = new Set<string>();

    for (const pattern of this.patterns) {
      try {
        for (const match of this.executor.findAll(pattern, text)) {
          const dedupKey = `${match.index}:${match.pattern.name}`;
          if (seen.has(dedupKey)) {
            continue;
          }
          seen.add(dedupKey);

          const position = this.calculatePosition(text, match.index, match.length);
          const severity: SecretSeverity = pattern.severity;

          const secret: DetectedSecret = {
            value: match.value,
            pattern: {
              name: pattern.name,
              regex: pattern.regex,
              category: pattern.category,
              description: pattern.description,
              severity: severity,
              example: pattern.example,
            },
            category: pattern.category,
            position: position,
            placeholder: this.generatePlaceholder(pattern, detected.length),
            confidence: this.calculateConfidence(pattern, match.value),
          };

          detected.push(secret);
        }
      } catch (error) {
        if (error instanceof ReDoSError) {
          continue;
        }
        throw error;
      }
    }

    return detected.sort((a, b) => {
      if (a.position.line !== b.position.line) {
        return a.position.line - b.position.line;
      }
      return a.position.column - b.position.column;
    });
  }

  addPattern(pattern: SecretPattern): void {
    if (this.config.enableReDoSProtection && !isSafeRegex(pattern.regex.source)) {
      throw new ReDoSError(pattern.name, this.config.timeoutMs);
    }

    this.patterns.push({
      ...pattern,
      compiledRegex: pattern.regex,
      isMultiline: pattern.regex.multiline || pattern.regex.dotAll,
    });
  }

  removePattern(name: string): void {
    this.patterns = this.patterns.filter(p => p.name !== name);
  }

  getPatternCount(): number {
    return this.patterns.length;
  }
}

export default RegexEngine;
