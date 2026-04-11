/**
 * Entropy-based secret detection using Shannon entropy
 *
 * Detects high-entropy strings that are likely to be secrets (API keys, tokens,
 * private keys) by analyzing character distribution. Filters out common words
 * and patterns to reduce false positives.
 */

import type {
  DetectedSecret,
  SecretPattern,
  SecretCategory,
  SecretPosition,
  ConfidenceLevel,
} from './types.js';

/**
 * Common dictionary words and patterns that should be filtered out
 * to reduce false positives in entropy detection
 */
const COMMON_WORDS = new Set([
  // Common passwords and variations
  'password', 'password123', 'password1', 'password12', 'pass1234',
  'qwerty', 'qwerty123', 'qwertyuiop', 'asdfgh', 'asdfghjkl',
  'letmein', 'welcome', 'welcome123', 'admin', 'admin123',
  'login', 'login123', 'user', 'user123', 'test', 'test123',
  'guest', 'guest123', 'default', 'default123', 'root', 'root123',
  // Common words
  'secret', 'secret123', 'key', 'key123', 'token', 'token123',
  'api', 'api123', 'auth', 'auth123', 'credentials', 'credential123',
  'access', 'access123', 'private', 'private123', 'public', 'public123',
  // Common sequences
  '123456', '12345678', '1234567890', '111111', '000000',
  'abcdef', 'abc123', 'xyz123', 'temp', 'temp123', 'temporary',
  // File extensions and common terms
  'index', 'main', 'app', 'server', 'client', 'config', 'configuration',
  'production', 'development', 'staging', 'localhost', 'example',
  'sample', 'demo', 'test', 'testing', 'mock', 'fake', 'dummy',
  // Programming terms
  'undefined', 'null', 'true', 'false', 'boolean', 'string', 'number',
  'object', 'array', 'function', 'class', 'const', 'let', 'var',
  'import', 'export', 'default', 'return', 'async', 'await', 'promise',
  'error', 'exception', 'catch', 'try', 'finally', 'throw', 'new',
  'this', 'that', 'self', 'window', 'document', 'console', 'log',
  // Git terms
  'master', 'main', 'develop', 'development', 'feature', 'bugfix',
  'hotfix', 'release', 'tag', 'branch', 'commit', 'merge', 'pull',
  // Common variable names
  'data', 'result', 'response', 'request', 'params', 'options', 'config',
  'settings', 'value', 'values', 'item', 'items', 'list', 'array',
  'obj', 'object', 'val', 'key', 'id', 'name', 'title', 'description',
]);

/**
 * Pattern for detecting potential secret strings in text
 * Matches sequences of characters that could be secrets
 */
const POTENTIAL_SECRET_PATTERN = /[A-Za-z0-9+/=]+|[A-Fa-f0-9]+/g;

/**
 * Pattern for hex strings (for higher confidence detection)
 */
const HEX_PATTERN = /^[A-Fa-f0-9]+$/;

/**
 * Pattern for base64 strings (for higher confidence detection)
 */
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Pattern to detect if string looks like a UUID
 */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const DEFAULT_ENTROPY_THRESHOLD = 4.5;

/**
 * Minimum length for a string to be considered a potential secret
 */
const DEFAULT_MIN_LENGTH = 16;

/**
 * Maximum length to prevent processing extremely long strings
 */
const MAX_LENGTH = 4096;

/**
 * Secret pattern used for entropy-based detection
 */
const ENTROPY_PATTERN: SecretPattern = {
  name: 'entropy_detector',
  category: 'other' as SecretCategory,
  regex: /[A-Za-z0-9+/=]{16,}/,
  description: 'High-entropy string detected (potential secret)',
  severity: 'medium',
  example: 'aB3dE5fG7hJ9kLmN',
};

/**
 * Configuration options for the entropy engine
 */
export interface EntropyEngineConfig {
  /** Minimum entropy threshold in bits per character (default: 4.5) */
  threshold?: number;
  /** Minimum string length to consider (default: 16) */
  minLength?: number;
  /** Maximum string length to consider (default: 4096) */
  maxLength?: number;
  /** Whether to filter out common dictionary words (default: true) */
  filterDictionaryWords?: boolean;
  /** Custom words to add to the filter set */
  customFilteredWords?: string[];
}

/**
 * Result of an entropy detection operation
 */
export interface EntropyDetectionResult {
  /** Array of detected secrets */
  secrets: DetectedSecret[];
  /** Statistics about the detection process */
  stats: {
    totalCandidates: number;
    filteredByDictionary: number;
    filteredByLength: number;
    filteredByEntropy: number;
  };
}

/**
 * Engine for detecting secrets using Shannon entropy analysis
 */
export class EntropyEngine {
  private config: Required<EntropyEngineConfig>;
  private filteredWords: Set<string>;

  /**
   * Create a new EntropyEngine with the specified configuration
   */
  constructor(config: EntropyEngineConfig = {}) {
    this.config = {
      threshold: config.threshold ?? DEFAULT_ENTROPY_THRESHOLD,
      minLength: config.minLength ?? DEFAULT_MIN_LENGTH,
      maxLength: config.maxLength ?? MAX_LENGTH,
      filterDictionaryWords: config.filterDictionaryWords ?? true,
      customFilteredWords: config.customFilteredWords ?? [],
    };

    // Build the filtered words set
    this.filteredWords = new Set(COMMON_WORDS);
    for (const word of this.config.customFilteredWords) {
      this.filteredWords.add(word.toLowerCase());
    }
  }

  /**
   * Calculate Shannon entropy of a string
   * H = -sum(p * log2(p)) for each character frequency
   *
   * @param text - The string to calculate entropy for
   * @returns Entropy value in bits per character
   */
  calculateEntropy(text: string): number {
    if (text.length === 0) {
      return 0;
    }

    // Count character frequencies
    const charCounts = new Map<string, number>();
    for (const char of text) {
      charCounts.set(char, (charCounts.get(char) ?? 0) + 1);
    }

    // Calculate entropy
    const length = text.length;
    let entropy = 0;

    for (const count of charCounts.values()) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }

    return entropy;
  }

  /**
   * Check if a string is in the filtered words list (case-insensitive)
   */
  private isFilteredWord(text: string): boolean {
    const lowerText = text.toLowerCase();
    return this.filteredWords.has(lowerText);
  }

  /**
   * Check if a string looks like a UUID
   */
  private isUUID(text: string): boolean {
    return UUID_PATTERN.test(text);
  }

  /**
   * Estimate the character set size for a string
   * Used to determine if the string uses a limited character set
   */
  private estimateCharsetSize(text: string): number {
    let hasLower = false;
    let hasUpper = false;
    let hasDigit = false;
    let hasSpecial = false;

    for (const char of text) {
      if (char >= 'a' && char <= 'z') hasLower = true;
      else if (char >= 'A' && char <= 'Z') hasUpper = true;
      else if (char >= '0' && char <= '9') hasDigit = true;
      else hasSpecial = true;
    }

    let size = 0;
    if (hasLower) size += 26;
    if (hasUpper) size += 26;
    if (hasDigit) size += 10;
    if (hasSpecial) size += 32; // Approximate

    return size || 256; // Default to full byte range if empty
  }

  /**
   * Calculate a normalized entropy score that accounts for character set size
   * This helps distinguish truly random strings from patterned ones
   */
  private calculateNormalizedEntropy(text: string): number {
    const rawEntropy = this.calculateEntropy(text);
    const charsetSize = this.estimateCharsetSize(text);
    const maxPossibleEntropy = Math.log2(charsetSize);

    // Normalize to 0-1 range (1 = perfectly random for the charset)
    if (maxPossibleEntropy === 0) {
      return 0;
    }

    return rawEntropy / maxPossibleEntropy;
  }

  /**
   * Check if a string appears to be base64 encoded
   */
  private isBase64(text: string): boolean {
    if (!BASE64_PATTERN.test(text)) {
      return false;
    }
    // Additional check: base64 strings should have valid padding
    const length = text.length;
    if (text.endsWith('==')) {
      return length % 4 === 0;
    } else if (text.endsWith('=')) {
      return length % 4 === 0;
    }
    return length % 4 === 0 || (length % 4 === 2 || length % 4 === 3);
  }

  /**
   * Check if a string appears to be hex encoded
   */
  private isHex(text: string): boolean {
    return HEX_PATTERN.test(text) && text.length >= this.config.minLength;
  }

  private calculateConfidence(
    entropy: number,
    text: string,
    isBase64: boolean,
    isHex: boolean
  ): ConfidenceLevel {
    const normalizedEntropy = this.calculateNormalizedEntropy(text);

    if (normalizedEntropy > 0.85 && text.length >= 40) {
      return 'high';
    }
    if ((isBase64 || isHex) && normalizedEntropy > 0.8 && text.length >= 32) {
      return 'high';
    }
    if (normalizedEntropy > 0.75 && text.length >= 24) {
      return 'medium';
    }
    if (entropy >= this.config.threshold && text.length >= this.config.minLength) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Generate a placeholder for a detected secret
   */
  private generatePlaceholder(value: string, index: number): string {
    const hash = this.simpleHash(value);
    return `__FILTER_ENTROPY_${hash}_${index}__`;
  }

  /**
   * Simple hash function for generating consistent placeholders
   */
  private simpleHash(text: string): string {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    // Return positive hex string, limited to 8 chars
    return Math.abs(hash).toString(16).substring(0, 8).padStart(8, '0');
  }

  private findPosition(text: string, startIndex: number, length: number): SecretPosition {
    const lines = text.substring(0, startIndex).split('\n');
    const line = lines.length;
    const column = lines[lines.length - 1].length;

    return {
      start: startIndex,
      end: startIndex + length,
      line,
      column,
    };
  }

  /**
   * Detect high-entropy secrets in the given text
   *
   * @param text - The text to scan for secrets
   * @param threshold - Optional override for entropy threshold
   * @returns Array of detected secrets
   */
  detect(text: string, threshold?: number): DetectedSecret[] {
    const result = this.detectWithStats(text, threshold);
    return result.secrets;
  }

  /**
   * Detect high-entropy secrets with detailed statistics
   *
   * @param text - The text to scan for secrets
   * @param threshold - Optional override for entropy threshold
   * @returns Detection result with secrets and statistics
   */
  detectWithStats(
    text: string,
    threshold?: number
  ): EntropyDetectionResult {
    const effectiveThreshold = threshold ?? this.config.threshold;
    const secrets: DetectedSecret[] = [];

    let totalCandidates = 0;
    let filteredByDictionary = 0;
    let filteredByLength = 0;
    let filteredByEntropy = 0;

    // Find all potential secret strings
    let match;
    const regex = new RegExp(POTENTIAL_SECRET_PATTERN);

    while ((match = regex.exec(text)) !== null) {
      const candidate = match[0];
      const startIndex = match.index;

      totalCandidates++;

      // Filter by length
      if (candidate.length < this.config.minLength) {
        filteredByLength++;
        continue;
      }

      if (candidate.length > this.config.maxLength) {
        filteredByLength++;
        continue;
      }

      // Filter out UUIDs (they are identifiers, not secrets)
      if (this.isUUID(candidate)) {
        filteredByDictionary++;
        continue;
      }

      // Filter dictionary words
      if (this.config.filterDictionaryWords && this.isFilteredWord(candidate)) {
        filteredByDictionary++;
        continue;
      }

      const isBase64 = this.isBase64(candidate);
      const isHex = this.isHex(candidate);

      const entropy = this.calculateEntropy(candidate);

      const hexThreshold = 2.0;
      const actualThreshold = isHex ? hexThreshold : effectiveThreshold;

      if (entropy < actualThreshold) {
        filteredByEntropy++;
        continue;
      }

      const normalizedEntropy = this.calculateNormalizedEntropy(candidate);
      const minNormalizedEntropy = isHex ? 0.55 : 0.75;
      if (normalizedEntropy < minNormalizedEntropy) {
        filteredByEntropy++;
        continue;
      }

      // Calculate confidence
      const confidence = this.calculateConfidence(
        entropy,
        candidate,
        isBase64,
        isHex
      );

      // Skip low confidence detections unless entropy is very high
      if (confidence === 'low' && entropy < effectiveThreshold + 0.5) {
        filteredByEntropy++;
        continue;
      }

      const position = this.findPosition(text, startIndex, candidate.length);

      // Create the detected secret
      const secret: DetectedSecret = {
        value: candidate,
        pattern: ENTROPY_PATTERN,
        category: 'other',
        position,
        placeholder: this.generatePlaceholder(candidate, secrets.length),
        confidence,
      };

      secrets.push(secret);
    }

    return {
      secrets,
      stats: {
        totalCandidates,
        filteredByDictionary,
        filteredByLength,
        filteredByEntropy,
      },
    };
  }

  /**
   * Update the engine configuration
   */
  updateConfig(config: Partial<EntropyEngineConfig>): void {
    this.config = { ...this.config, ...config };

    // Rebuild filtered words if custom words changed
    if (config.customFilteredWords) {
      this.filteredWords = new Set(COMMON_WORDS);
      for (const word of config.customFilteredWords) {
        this.filteredWords.add(word.toLowerCase());
      }
    }
  }

  /**
   * Get current configuration
   */
  getConfig(): Required<EntropyEngineConfig> {
    return { ...this.config };
  }

  /**
   * Add words to the filtered words list
   */
  addFilteredWords(words: string[]): void {
    for (const word of words) {
      this.filteredWords.add(word.toLowerCase());
    }
  }

  /**
   * Remove words from the filtered words list
   */
  removeFilteredWords(words: string[]): void {
    for (const word of words) {
      this.filteredWords.delete(word.toLowerCase());
    }
  }

  /**
   * Check if a single string would be detected as a secret
   * Useful for testing and validation
   */
  isSecret(text: string, threshold?: number): boolean {
    const effectiveThreshold = threshold ?? this.config.threshold;

    // Check basic requirements
    if (text.length < this.config.minLength) {
      return false;
    }

    if (text.length > this.config.maxLength) {
      return false;
    }

    if (this.config.filterDictionaryWords && this.isFilteredWord(text)) {
      return false;
    }

    if (this.isUUID(text)) {
      return false;
    }

    const entropy = this.calculateEntropy(text);
    const isHex = this.isHex(text);

    const hexThreshold = 2.0;
    const actualThreshold = isHex ? hexThreshold : effectiveThreshold;

    if (entropy < actualThreshold) {
      return false;
    }

    const normalizedEntropy = this.calculateNormalizedEntropy(text);
    const minNormalizedEntropy = isHex ? 0.55 : 0.75;
    if (normalizedEntropy < minNormalizedEntropy) {
      return false;
    }

    return true;
  }
}

/**
 * Convenience function for one-off entropy calculation
 */
export function calculateEntropy(text: string): number {
  const engine = new EntropyEngine();
  return engine.calculateEntropy(text);
}

/**
 * Convenience function for one-off secret detection
 */
export function detectSecrets(
  text: string,
  threshold?: number,
  minLength?: number
): DetectedSecret[] {
  const engine = new EntropyEngine({
    threshold,
    minLength,
  });
  return engine.detect(text);
}
