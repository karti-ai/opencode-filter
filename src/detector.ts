/**
 * Secret Detector - Combines Regex and Entropy Detection Engines
 *
 * The SecretDetector class orchestrates both regex pattern matching (for known secrets)
 * and entropy analysis (for unknown secrets) to provide comprehensive secret detection.
 *
 * Detection Priority:
 * 1. Regex patterns (known secrets) - high confidence
 * 2. Entropy analysis (unknown secrets) - medium confidence
 * 3. Deduplicate overlapping regions
 *
 * Performance Target: <1ms for 1KB text
 */

import type {
  DetectedSecret,
  SecretPattern,
  SecretCategory,
  SecretPosition,
  ConfidenceLevel,
  SecretSeverity,
} from './types.js';

// ============================================================================
// ENGINE INTERFACES (to be implemented in separate files)
// ============================================================================

/**
 * Interface for regex-based secret detection
 * Implementation: src/patterns/regex-engine.ts (Task 5)
 */
export interface RegexEngine {
  /**
   * Detect secrets using regex patterns
   * @param text - Text to scan for secrets
   * @returns Array of secrets found via regex patterns
   */
  detect(text: string): Array<{
    value: string;
    pattern: SecretPattern;
    position: SecretPosition;
  }>;
}

/**
 * Interface for entropy-based secret detection
 * Implementation: src/entropy.ts (Task 6)
 */
export interface EntropyEngine {
  /**
   * Detect secrets using entropy analysis
   * @param text - Text to scan for secrets
   * @param excludedRegions - Regions to skip (already detected by regex)
   * @returns Array of high-entropy secrets
   */
  detect(text: string, excludedRegions: Array<{ start: number; end: number }>): Array<{
    value: string;
    position: SecretPosition;
    entropy: number;
  }>;
}

// ============================================================================
// DETECTOR IMPLEMENTATION
// ============================================================================

/**
 * Combined secret detector using both regex and entropy engines
 */
export class SecretDetector {
  private regexEngine: RegexEngine;
  private entropyEngine: EntropyEngine;
  private entropyPattern: SecretPattern;

  constructor(regexEngine: RegexEngine, entropyEngine: EntropyEngine) {
    this.regexEngine = regexEngine;
    this.entropyEngine = entropyEngine;

    // Create a synthetic pattern for entropy-detected secrets
    this.entropyPattern = {
      name: 'entropy-detected',
      regex: /./, // Placeholder, not used directly
      category: 'other' as SecretCategory,
      description: 'High-entropy string detected as potential secret',
      severity: 'medium' as SecretSeverity,
      example: 'dGhpcyBpcyBhIHNlY3JldCBrZXk=',
    };
  }

  /**
   * Detect secrets in text using both regex and entropy engines
   *
   * Algorithm:
   * 1. Run regex engine to find known secrets (high confidence)
   * 2. Collect excluded regions from regex matches
   * 3. Run entropy engine only on non-excluded regions
   * 4. Combine results and resolve overlapping matches
   * 5. Sort by position (start index)
   *
   * @param text - Text to scan for secrets
   * @returns Array of detected secrets sorted by position
   */
  detect(text: string): DetectedSecret[] {
    if (!text || text.length === 0) {
      return [];
    }

    // Step 1: Detect known secrets with regex (high confidence)
    const regexMatches = this.regexEngine.detect(text);
    const regexSecrets: DetectedSecret[] = regexMatches.map((match) => ({
      value: match.value,
      pattern: match.pattern,
      category: match.pattern.category,
      position: match.position,
      placeholder: '', // Placeholder assigned by filter
      confidence: 'high' as ConfidenceLevel,
    }));

    // Step 2: Build excluded regions from regex matches
    const excludedRegions: Array<{ start: number; end: number }> =
      regexSecrets.map((secret) => ({
        start: secret.position.start,
        end: secret.position.end,
      }));

    // Step 3: Detect unknown secrets with entropy (skip excluded regions)
    const entropyMatches = this.entropyEngine.detect(text, excludedRegions);
    const entropySecrets: DetectedSecret[] = entropyMatches.map((match) => ({
      value: match.value,
      pattern: this.entropyPattern,
      category: 'other' as SecretCategory,
      position: match.position,
      placeholder: '', // Placeholder assigned by filter
      confidence: 'medium' as ConfidenceLevel,
    }));

    // Step 4: Combine and deduplicate
    const combined: DetectedSecret[] = [...regexSecrets, ...entropySecrets];

    // Step 5: Resolve overlapping matches (longest match wins)
    const resolved = this.resolveOverlappingMatches(combined);

    // Step 6: Sort by position
    return this.sortByPosition(resolved);
  }

  /**
   * Resolve overlapping matches by keeping the longest match
   * When matches have the same length, regex (high confidence) wins
   *
   * @param secrets - Array of detected secrets (potentially overlapping)
   * @returns Array with overlaps resolved
   */
  private resolveOverlappingMatches(secrets: DetectedSecret[]): DetectedSecret[] {
    if (secrets.length <= 1) {
      return secrets;
    }

    // Sort by start position, then by length (descending)
    const sorted = [...secrets].sort((a, b) => {
      const startDiff = a.position.start - b.position.start;
      if (startDiff !== 0) return startDiff;

      // Same start position: prefer longer match
      const lengthDiff =
        (b.position.end - b.position.start) - (a.position.end - a.position.start);
      if (lengthDiff !== 0) return lengthDiff;

      // Same length: prefer high confidence (regex) over medium (entropy)
      const confidenceOrder = { high: 0, medium: 1, low: 2 };
      return confidenceOrder[a.confidence] - confidenceOrder[b.confidence];
    });

    const result: DetectedSecret[] = [];
    let lastEnd = -1;

    for (const secret of sorted) {
      const { start, end } = secret.position;

      // Check if this secret overlaps with any already-accepted secret
      if (start < lastEnd) {
        // Overlapping - skip (the earlier/longer one was already accepted)
        continue;
      }

      result.push(secret);
      lastEnd = end;
    }

    return result;
  }

  /**
   * Sort secrets by their start position
   *
   * @param secrets - Array of detected secrets
   * @returns Sorted array
   */
  private sortByPosition(secrets: DetectedSecret[]): DetectedSecret[] {
    return [...secrets].sort((a, b) => a.position.start - b.position.start);
  }
}

// ============================================================================
// STUB IMPLEMENTATIONS (for testing until T5 and T6 are complete)
// These will be replaced by actual implementations from:
// - src/patterns/regex-engine.ts (Task 5)
// - src/entropy.ts (Task 6)
// ============================================================================

/**
 * Stub RegexEngine implementation for testing
 */
export class RegexEngineStub implements RegexEngine {
  private patterns: SecretPattern[];

  constructor(patterns: SecretPattern[] = []) {
    this.patterns = patterns;
  }

  detect(text: string): Array<{
    value: string;
    pattern: SecretPattern;
    position: SecretPosition;
  }> {
    const results: Array<{
      value: string;
      pattern: SecretPattern;
      position: SecretPosition;
    }> = [];

    for (const pattern of this.patterns) {
      // Reset lastIndex to ensure consistent behavior
      pattern.regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      let lastMatchIndex = -1;

      while ((match = pattern.regex.exec(text)) !== null) {
        // Prevent infinite loop on non-global patterns or stuck regex
        if (match.index === lastMatchIndex) {
          break;
        }
        lastMatchIndex = match.index;

        // Calculate line and column
        const textBeforeMatch = text.slice(0, match.index);
        const lines = textBeforeMatch.split('\n');
        const line = lines.length;
        const column = lines[lines.length - 1].length;

        results.push({
          value: match[0],
          pattern,
          position: {
            start: match.index,
            end: match.index + match[0].length,
            line,
            column,
          },
        });

        // Prevent infinite loop on zero-length matches
        if (match[0].length === 0) {
          pattern.regex.lastIndex++;
        }

        // For non-global patterns, only find the first match
        if (!pattern.regex.global) {
          break;
        }
      }
    }

    return results;
  }
}

/**
 * Stub EntropyEngine implementation for testing
 * Uses Shannon entropy calculation
 */
export class EntropyEngineStub implements EntropyEngine {
  private threshold: number;
  private minLength: number;

  constructor(threshold = 4.5, minLength = 16) {
    this.threshold = threshold;
    this.minLength = minLength;
  }

  detect(
    text: string,
    excludedRegions: Array<{ start: number; end: number }>
  ): Array<{
    value: string;
    position: SecretPosition;
    entropy: number;
  }> {
    const results: Array<{
      value: string;
      position: SecretPosition;
      entropy: number;
    }> = [];

    // Find potential high-entropy candidates
    // Look for alphanumeric sequences, base64 strings, hex strings
    const candidates = this.findCandidates(text, excludedRegions);

    for (const candidate of candidates) {
      const entropy = this.calculateShannonEntropy(candidate.value);

      if (entropy >= this.threshold) {
        results.push({
          value: candidate.value,
          position: candidate.position,
          entropy,
        });
      }
    }

    return results;
  }

  /**
   * Find candidate strings that might be secrets
   * Skips excluded regions and filters by minimum length
   */
  private findCandidates(
    text: string,
    excludedRegions: Array<{ start: number; end: number }>
  ): Array<{ value: string; position: SecretPosition }> {
    const candidates: Array<{ value: string; position: SecretPosition }> = [];

    // Pattern to match potential secret-like strings
    // Matches: base64, hex, alphanumeric sequences
    const pattern = /[A-Za-z0-9+/=]{16,}|[a-f0-9]{16,}/gi;

    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;

      // Skip if in excluded region
      if (this.isInExcludedRegion(start, end, excludedRegions)) {
        // Advance lastIndex to prevent infinite loop
        if (match[0].length === 0) pattern.lastIndex++;
        continue;
      }

      // Skip if too short
      if (match[0].length < this.minLength) {
        // Advance lastIndex to prevent infinite loop
        if (match[0].length === 0) pattern.lastIndex++;
        continue;
      }

      // Calculate line and column
      const textBeforeMatch = text.slice(0, start);
      const lines = textBeforeMatch.split('\n');
      const line = lines.length;
      const column = lines[lines.length - 1].length;

      candidates.push({
        value: match[0],
        position: { start, end, line, column },
      });
    }

    return candidates;
  }

  /**
   * Check if a range overlaps with any excluded region
   */
  private isInExcludedRegion(
    start: number,
    end: number,
    excludedRegions: Array<{ start: number; end: number }>
  ): boolean {
    return excludedRegions.some(
      (region) => start < region.end && end > region.start
    );
  }

  /**
   * Calculate Shannon entropy of a string
   * Higher entropy = more random = more likely to be a secret
   */
  private calculateShannonEntropy(str: string): number {
    if (str.length === 0) return 0;

    const charCounts = new Map<string, number>();

    for (const char of str) {
      charCounts.set(char, (charCounts.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = str.length;

    for (const count of charCounts.values()) {
      const frequency = count / len;
      entropy -= frequency * Math.log2(frequency);
    }

    return entropy;
  }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Create a default detector with stub engines
 * This is a convenience function for testing
 */
export function createDefaultDetector(
  patterns: SecretPattern[] = [],
  entropyThreshold = 4.5,
  minLength = 16
): SecretDetector {
  const regexEngine = new RegexEngineStub(patterns);
  const entropyEngine = new EntropyEngineStub(entropyThreshold, minLength);
  return new SecretDetector(regexEngine, entropyEngine);
}
