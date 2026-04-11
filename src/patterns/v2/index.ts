/**
 * V2 Secret Patterns Index
 *
 * Exports all 200+ secret patterns organized by category.
 * These patterns are based on research from TruffleHog, GitHub Secret Scanning,
 * and GitLeaks for comprehensive secret detection.
 */

import type { SecretPattern } from '../../types.js';

// Import all category patterns
import CLOUD_PATTERNS from './cloud.js';
import CODE_HOSTING_PATTERNS from './code-hosting.js';
import COMMUNICATION_PATTERNS from './communication.js';
import PAYMENT_PATTERNS from './payment.js';
import AUTHENTICATION_PATTERNS from './authentication.js';
import SAAS_PATTERNS from './saas.js';
import INFRASTRUCTURE_PATTERNS from './infrastructure.js';
import GENERIC_PATTERNS from './generic.js';

/**
 * All V2 patterns combined
 * Total: 200+ patterns
 */
export const V2_PATTERNS: SecretPattern[] = [
  ...CLOUD_PATTERNS,
  ...CODE_HOSTING_PATTERNS,
  ...COMMUNICATION_PATTERNS,
  ...PAYMENT_PATTERNS,
  ...AUTHENTICATION_PATTERNS,
  ...SAAS_PATTERNS,
  ...INFRASTRUCTURE_PATTERNS,
  ...GENERIC_PATTERNS,
];

/**
 * Pattern counts by category
 */
export const V2_PATTERN_COUNTS = {
  cloud: CLOUD_PATTERNS.length,
  codeHosting: CODE_HOSTING_PATTERNS.length,
  communication: COMMUNICATION_PATTERNS.length,
  payment: PAYMENT_PATTERNS.length,
  authentication: AUTHENTICATION_PATTERNS.length,
  saas: SAAS_PATTERNS.length,
  infrastructure: INFRASTRUCTURE_PATTERNS.length,
  generic: GENERIC_PATTERNS.length,
  total: V2_PATTERNS.length,
} as const;

/**
 * Export individual category arrays for selective use
 */
export {
  CLOUD_PATTERNS,
  CODE_HOSTING_PATTERNS,
  COMMUNICATION_PATTERNS,
  PAYMENT_PATTERNS,
  AUTHENTICATION_PATTERNS,
  SAAS_PATTERNS,
  INFRASTRUCTURE_PATTERNS,
  GENERIC_PATTERNS,
};

/**
 * Get patterns by category name
 */
export function getV2PatternsByCategory(category: string): SecretPattern[] {
  switch (category) {
    case 'cloud':
      return [...CLOUD_PATTERNS];
    case 'code-hosting':
      return [...CODE_HOSTING_PATTERNS];
    case 'communication':
      return [...COMMUNICATION_PATTERNS];
    case 'payment':
      return [...PAYMENT_PATTERNS];
    case 'authentication':
      return [...AUTHENTICATION_PATTERNS];
    case 'saas':
      return [...SAAS_PATTERNS];
    case 'infrastructure':
      return [...INFRASTRUCTURE_PATTERNS];
    case 'generic':
      return [...GENERIC_PATTERNS];
    default:
      return [];
  }
}

/**
 * Find a V2 pattern by name
 */
export function findV2PatternByName(name: string): SecretPattern | undefined {
  return V2_PATTERNS.find((p) => p.name === name);
}

/**
 * Get patterns filtered by severity
 */
export function getV2PatternsBySeverity(severity: SecretPattern['severity']): SecretPattern[] {
  return V2_PATTERNS.filter((p) => p.severity === severity);
}

/**
 * Export default for convenience
 */
export default V2_PATTERNS;
