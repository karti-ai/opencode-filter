/**
 * Comprehensive Performance Benchmark Suite for OpenCode Filter
 *
 * Tests multiple scenarios:
 * - Message sizes: 1KB, 10KB, 100KB, 1MB
 * - Secret densities: 1, 10, 100 secrets per message
 * - Components: Detection only, Filtering, Full pipeline
 *
 * Performance Gates:
 * - 1KB message: <1ms p95
 * - 10KB message: <5ms p95
 * - 100KB message: <50ms p95
 * - 1MB message: <500ms p95
 */

import { SecretDetector, RegexEngineStub, EntropyEngineStub } from '../src/detector';
import { RegexEngine } from '../src/patterns/regex-engine';
import { EntropyEngine } from '../src/entropy';
import { MessageFilter } from '../src/filter';
import { CryptoUtils } from '../src/crypto';
import { SessionManager } from '../src/session';
import type { SecretPattern, DetectedSecret, FilteredMessage } from '../src/types';

// ============================================================================
// PERFORMANCE GATES
// ============================================================================

const PERFORMANCE_GATES: Record<string, { p95: number; p99: number }> = {
  '1KB': { p95: 1, p99: 5 },      // < 1ms p95, < 5ms p99
  '10KB': { p95: 5, p99: 10 },    // < 5ms p95, < 10ms p99
  '100KB': { p95: 50, p99: 100 }, // < 50ms p95, < 100ms p99
  '1MB': { p95: 500, p99: 1000 }, // < 500ms p95, < 1000ms p99
};

// ============================================================================
// SAMPLE PATTERNS FOR STUB TESTS
// ============================================================================

const SAMPLE_PATTERNS: SecretPattern[] = [
  {
    name: 'aws_access_key_id',
    regex: /AKIA[0-9A-Z]{16}/g,
    category: 'api_key',
    description: 'AWS Access Key ID',
    severity: 'critical',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },
  {
    name: 'github_pat',
    regex: /ghp_[a-zA-Z0-9]{36}/g,
    category: 'token',
    description: 'GitHub Personal Access Token',
    severity: 'critical',
    example: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
  {
    name: 'slack_token',
    regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(?:-[a-zA-Z0-9]{24})?/g,
    category: 'token',
    description: 'Slack API Token',
    severity: 'high',
    example: 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
  },
  {
    name: 'jwt_token',
    regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    category: 'token',
    description: 'JSON Web Token',
    severity: 'high',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  },
  {
    name: 'stripe_live_key',
    regex: /sk_live_[0-9a-zA-Z]{24,99}/g,
    category: 'api_key',
    description: 'Stripe Live API Key',
    severity: 'critical',
    example: 'sk_live_abcdefghijklmnopqrstuvwxyz012345',
  },
  {
    name: 'generic_api_key',
    regex: /(?:api[_-]?key|apikey)["']?\s*[=:]\s*["']?[a-zA-Z0-9_\-]{16,}["']?/gi,
    category: 'api_key',
    description: 'Generic API key pattern',
    severity: 'medium',
    example: 'api_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  },
];

// ============================================================================
// REALISTIC SECRET GENERATORS
// ============================================================================

const REALISTIC_SECRETS = {
  aws_access_key_id: () => 'AKIA' + generateRandomString(16, 'A-Z0-9'),
  aws_secret_access_key: () => generateRandomString(40, 'A-Za-z0-9/='),
  github_pat: () => 'ghp_' + generateRandomString(36, 'a-zA-Z0-9'),
  github_oauth: () => 'gho_' + generateRandomString(36, 'a-zA-Z0-9'),
  github_app_token: () => 'ghs_' + generateRandomString(36, 'a-zA-Z0-9'),
  slack_token: () => `xoxb-${generateRandomString(12, '0-9')}-${generateRandomString(12, '0-9')}-${generateRandomString(24, 'a-zA-Z0-9')}`,
  slack_webhook: () => `https://hooks.slack.com/services/T${generateRandomString(8, 'A-Z0-9')}/B${generateRandomString(8, 'A-Z0-9')}/${generateRandomString(24, 'a-zA-Z0-9')}`,
  stripe_live_key: () => 'sk_live_' + generateRandomString(32, 'a-zA-Z0-9'),
  stripe_test_key: () => 'sk_test_' + generateRandomString(32, 'a-zA-Z0-9'),
  jwt_token: () => {
    const header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
    const payload = btoa(JSON.stringify({ sub: generateRandomString(10, '0-9'), exp: Date.now() }));
    const sig = generateRandomString(43, 'a-zA-Z0-9_-');
    return `${header}.${payload}.${sig}`;
  },
  password: () => generateRandomString(20, 'a-zA-Z0-9!@#$%^&*'),
  base64_secret: () => btoa(generateRandomString(32, 'a-zA-Z0-9')),
  hex_secret: () => generateRandomString(64, 'a-f0-9'),
  generic_api_key: () => `api_key=${generateRandomString(32, 'a-zA-Z0-9_-')}`,
  bearer_token: () => `Bearer ${generateRandomString(40, 'a-zA-Z0-9_-.')}`,
  database_url: () => `postgresql://user:${generateRandomString(16, 'a-zA-Z0-9')}@localhost:5432/db`,
};

function generateRandomString(length: number, charset: string): string {
  let result = '';
  const chars = charset.split('');
  
  for (let i = 0; i < length; i++) {
    if (charset === 'a-zA-Z0-9') {
      result += String.fromCharCode(
        Math.random() < 0.5
          ? Math.floor(Math.random() * 26) + 65  // A-Z
          : Math.random() < 0.5
            ? Math.floor(Math.random() * 26) + 97  // a-z
            : Math.floor(Math.random() * 10) + 48  // 0-9
      );
    } else if (charset === 'A-Z0-9') {
      result += Math.random() < 0.5
        ? String.fromCharCode(Math.floor(Math.random() * 26) + 65)
        : String.fromCharCode(Math.floor(Math.random() * 10) + 48);
    } else if (charset === 'a-f0-9') {
      result += Math.random() < 0.5
        ? String.fromCharCode(Math.floor(Math.random() * 6) + 97)
        : String.fromCharCode(Math.floor(Math.random() * 10) + 48);
    } else if (charset === 'A-Za-z0-9/=') {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/=';
      result += chars[Math.floor(Math.random() * chars.length)];
    } else if (charset === 'a-zA-Z0-9_-.') {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-';
      result += chars[Math.floor(Math.random() * chars.length)];
    } else if (charset === 'a-zA-Z0-9!@#$%^&*') {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
      result += chars[Math.floor(Math.random() * chars.length)];
    } else if (charset === 'a-zA-Z0-9_-') {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
      result += chars[Math.floor(Math.random() * chars.length)];
    } else {
      result += String.fromCharCode(Math.floor(Math.random() * 26) + 97);
    }
  }
  
  return result;
}

const FILLER_WORDS = [
  'Lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit',
  'Sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore',
  'magna', 'aliqua', 'Ut', 'enim', 'ad', 'minim', 'veniam', 'quis', 'nostrud',
  'exercitation', 'ullamco', 'laboris', 'nisi', 'aliquip', 'ex', 'ea', 'commodo',
  'consequat', 'Duis', 'aute', 'irure', 'in', 'reprehenderit', 'voluptate', 'velit',
  'esse', 'cillum', 'fugiat', 'nulla', 'pariatur', 'Excepteur', 'sint', 'occaecat',
  'cupidatat', 'non', 'proident', 'sunt', 'culpa', 'qui', 'officia', 'deserunt',
  'mollit', 'anim', 'id', 'est', 'laborum', 'function', 'const', 'let', 'var',
  'return', 'async', 'await', 'import', 'export', 'class', 'interface', 'type',
  'password', 'secret', 'token', 'api_key', 'credential', 'config', 'settings',
  'database', 'connection', 'server', 'client', 'request', 'response', 'error',
  'success', 'failed', 'timeout', 'retry', 'attempt', 'limit', 'rate', 'quota',
  'Here', 'is', 'my', 'the', 'a', 'an', 'to', 'for', 'with', 'from', 'by', 'on',
  'The', 'quick', 'brown', 'fox', 'jumps', 'over', 'lazy', 'dog', 'Hello',
  'World', 'test', 'data', 'example', 'sample', 'demo', 'code', 'script',
  'configuration', 'environment', 'production', 'development', 'staging',
  'localhost', 'docker', 'kubernetes', 'deployment', 'service', 'endpoint',
];

const CODE_CONTEXTS = [
  'const config = {',
  '  apiKey: "SECRET_PLACEHOLDER",',
  '  timeout: 5000,',
  '};',
  '',
  'function connect() {',
  '  const token = "SECRET_PLACEHOLDER";',
  '  return fetch("/api/data", {',
  '    headers: {',
  '      "Authorization": "Bearer SECRET_PLACEHOLDER",',
  '    },',
  '  });',
  '}',
  '',
  'const dbUrl = "SECRET_PLACEHOLDER";',
  'const awsKey = "SECRET_PLACEHOLDER";',
  '',
  'export async function handler() {',
  '  const client = new Client({',
  '    accessKeyId: "SECRET_PLACEHOLDER",',
  '    secretAccessKey: "SECRET_PLACEHOLDER",',
  '  });',
  '}',
];

// ============================================================================
// TEST DATA GENERATION
// ============================================================================

/**
 * Generate a realistic secret value
 */
function generateSecret(): string {
  const keys = Object.keys(REALISTIC_SECRETS);
  const type = keys[Math.floor(Math.random() * keys.length)] as keyof typeof REALISTIC_SECRETS;
  return REALISTIC_SECRETS[type]();
}

/**
 * Generate test message of specified size with specified number of secrets
 */
function generateTestMessage(sizeBytes: number, secretCount: number): string {
  const secrets: string[] = [];
  for (let i = 0; i < secretCount; i++) {
    secrets.push(generateSecret());
  }

  let message = '';
  let secretIndex = 0;
  const avgSecretSpacing = sizeBytes / (secretCount + 1);

  while (message.length < sizeBytes) {
    // Add code context occasionally
    if (Math.random() < 0.1 && message.length < sizeBytes - 500) {
      const context = CODE_CONTEXTS[Math.floor(Math.random() * CODE_CONTEXTS.length)];
      if (context.includes('SECRET_PLACEHOLDER') && secretIndex < secrets.length) {
        message += context.replace('SECRET_PLACEHOLDER', secrets[secretIndex++]) + '\n';
      } else if (!context.includes('SECRET_PLACEHOLDER')) {
        message += context + '\n';
      }
      continue;
    }

    // Add filler text
    const wordCount = Math.floor(Math.random() * 8) + 3;
    for (let i = 0; i < wordCount && message.length < sizeBytes; i++) {
      const word = FILLER_WORDS[Math.floor(Math.random() * FILLER_WORDS.length)];
      message += word + ' ';
    }

    // Insert secret at calculated position
    if (secretIndex < secrets.length && message.length > (secretIndex + 1) * avgSecretSpacing) {
      message += secrets[secretIndex] + ' ';
      secretIndex++;
    }
  }

  // Ensure exact size
  return message.substring(0, sizeBytes);
}

// ============================================================================
// BENCHMARK TYPES
// ============================================================================

interface LatencyMetrics {
  p50: number;
  p95: number;
  p99: number;
  mean: number;
  min: number;
  max: number;
  stdDev: number;
}

interface MemoryMetrics {
  before: number;
  after: number;
  delta: number;
}

interface BenchmarkScenario {
  messageSize: string;
  sizeBytes: number;
  secretCount: number;
  iterations: number;
  component: 'detection' | 'filtering' | 'pipeline';
}

interface BenchmarkResult {
  scenario: BenchmarkScenario;
  latency: LatencyMetrics;
  memory: MemoryMetrics;
  status: 'PASS' | 'FAIL';
  gate: string;
}

interface BenchmarkSummary {
  total: number;
  passed: number;
  failed: number;
  duration: number;
}

interface FullBenchmarkReport {
  timestamp: string;
  environment: {
    runtime: string;
    version: string;
    platform: string;
  };
  configuration: {
    warmupIterations: number;
    measureIterations: number;
  };
  results: BenchmarkResult[];
  summary: BenchmarkSummary;
}

// ============================================================================
// BENCHMARK UTILITIES
// ============================================================================

/**
 * Calculate percentiles and statistics from timing data
 */
function calculateStatistics(times: number[]): LatencyMetrics {
  const sorted = [...times].sort((a, b) => a - b);
  const len = sorted.length;
  
  const percentile = (p: number): number => {
    const index = Math.ceil((p / 100) * len) - 1;
    return sorted[Math.max(0, Math.min(index, len - 1))];
  };

  const mean = sorted.reduce((a, b) => a + b, 0) / len;
  const variance = sorted.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / len;
  const stdDev = Math.sqrt(variance);

  return {
    p50: percentile(50),
    p95: percentile(95),
    p99: percentile(99),
    mean,
    min: sorted[0],
    max: sorted[len - 1],
    stdDev,
  };
}

/**
 * Get current memory usage
 */
function getMemoryUsage(): number {
  const usage = process.memoryUsage();
  return usage.heapUsed;
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Format time in milliseconds with appropriate precision
 */
function formatTime(ms: number): string {
  if (ms < 0.001) return `${(ms * 1000).toFixed(2)} μs`;
  if (ms < 1) return `${(ms * 1000).toFixed(1)} μs`;
  if (ms < 10) return `${ms.toFixed(3)} ms`;
  if (ms < 100) return `${ms.toFixed(2)} ms`;
  return `${ms.toFixed(1)} ms`;
}

/**
 * Check if result passes performance gate
 */
function checkPerformanceGate(sizeLabel: string, p95: number): { status: 'PASS' | 'FAIL'; gate: string } {
  const gate = PERFORMANCE_GATES[sizeLabel];
  if (!gate) {
    return { status: 'PASS', gate: 'No gate defined' };
  }
  
  if (p95 <= gate.p95) {
    return { status: 'PASS', gate: `P95 < ${gate.p95}ms` };
  }
  return { status: 'FAIL', gate: `P95 < ${gate.p95}ms (actual: ${p95.toFixed(2)}ms)` };
}

// ============================================================================
// COMPONENT BENCHMARKS
// ============================================================================

/**
 * Benchmark detection only (RegexEngine + EntropyEngine via SecretDetector)
 */
function benchmarkDetection(
  text: string,
  iterations: number,
  warmupIterations: number
): { latency: number[]; memory: MemoryMetrics } {
  const regexEngine = new RegexEngine();
  const entropyEngine = new EntropyEngine();
  const detector = new SecretDetector(regexEngine, entropyEngine);

  // Warmup
  for (let i = 0; i < warmupIterations; i++) {
    detector.detect(text);
  }

  // Force GC if available
  if (global.gc) {
    global.gc();
  }

  const memoryBefore = getMemoryUsage();
  const times: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    detector.detect(text);
    const end = performance.now();
    times.push(end - start);
  }

  const memoryAfter = getMemoryUsage();

  return {
    latency: times,
    memory: {
      before: memoryBefore,
      after: memoryAfter,
      delta: memoryAfter - memoryBefore,
    },
  };
}

/**
 * Benchmark filtering (MessageFilter with full pipeline)
 */
function benchmarkFiltering(
  text: string,
  iterations: number,
  warmupIterations: number
): { latency: number[]; memory: MemoryMetrics } {
  const regexEngine = new RegexEngine();
  const entropyEngine = new EntropyEngine();
  const detector = new SecretDetector(regexEngine, entropyEngine);
  const crypto = new CryptoUtils();
  const filter = new MessageFilter(detector, crypto);
  
  // Create a fresh session for each iteration
  const sessions: SessionManager[] = [];
  for (let i = 0; i < iterations + warmupIterations; i++) {
    sessions.push(new SessionManager());
  }

  // Warmup
  for (let i = 0; i < warmupIterations; i++) {
    filter.filterOutgoing(text, sessions[i]);
  }

  // Force GC if available
  if (global.gc) {
    global.gc();
  }

  const memoryBefore = getMemoryUsage();
  const times: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const session = sessions[warmupIterations + i];
    const start = performance.now();
    filter.filterOutgoing(text, session);
    const end = performance.now();
    times.push(end - start);
  }

  const memoryAfter = getMemoryUsage();

  return {
    latency: times,
    memory: {
      before: memoryBefore,
      after: memoryAfter,
      delta: memoryAfter - memoryBefore,
    },
  };
}

/**
 * Benchmark full pipeline (detect + filter)
 */
function benchmarkPipeline(
  text: string,
  iterations: number,
  warmupIterations: number
): { latency: number[]; memory: MemoryMetrics } {
  const regexEngine = new RegexEngine();
  const entropyEngine = new EntropyEngine();
  const detector = new SecretDetector(regexEngine, entropyEngine);
  const crypto = new CryptoUtils();
  const filter = new MessageFilter(detector, crypto);
  
  // Create sessions
  const sessions: SessionManager[] = [];
  for (let i = 0; i < iterations + warmupIterations; i++) {
    sessions.push(new SessionManager());
  }

  // Warmup
  for (let i = 0; i < warmupIterations; i++) {
    const detected = detector.detect(text);
    filter.filterOutgoing(text, sessions[i]);
  }

  // Force GC if available
  if (global.gc) {
    global.gc();
  }

  const memoryBefore = getMemoryUsage();
  const times: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const session = sessions[warmupIterations + i];
    const start = performance.now();
    const detected = detector.detect(text);
    filter.filterOutgoing(text, session);
    const end = performance.now();
    times.push(end - start);
  }

  const memoryAfter = getMemoryUsage();

  return {
    latency: times,
    memory: {
      before: memoryBefore,
      after: memoryAfter,
      delta: memoryAfter - memoryBefore,
    },
  };
}

// ============================================================================
// SCENARIO RUNNER
// ============================================================================

const WARMUP_ITERATIONS = 100;
const MEASURE_ITERATIONS = 1000;

const SCENARIOS: BenchmarkScenario[] = [
  // 1KB messages
  { messageSize: '1KB', sizeBytes: 1024, secretCount: 1, iterations: MEASURE_ITERATIONS, component: 'detection' },
  { messageSize: '1KB', sizeBytes: 1024, secretCount: 1, iterations: MEASURE_ITERATIONS, component: 'filtering' },
  { messageSize: '1KB', sizeBytes: 1024, secretCount: 1, iterations: MEASURE_ITERATIONS, component: 'pipeline' },
  { messageSize: '1KB', sizeBytes: 1024, secretCount: 10, iterations: MEASURE_ITERATIONS, component: 'detection' },
  { messageSize: '1KB', sizeBytes: 1024, secretCount: 10, iterations: MEASURE_ITERATIONS, component: 'filtering' },
  { messageSize: '1KB', sizeBytes: 1024, secretCount: 10, iterations: MEASURE_ITERATIONS, component: 'pipeline' },
  
  // 10KB messages
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 1, iterations: MEASURE_ITERATIONS, component: 'detection' },
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 1, iterations: MEASURE_ITERATIONS, component: 'filtering' },
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 1, iterations: MEASURE_ITERATIONS, component: 'pipeline' },
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 10, iterations: MEASURE_ITERATIONS, component: 'detection' },
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 10, iterations: MEASURE_ITERATIONS, component: 'filtering' },
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 10, iterations: MEASURE_ITERATIONS, component: 'pipeline' },
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 100, iterations: MEASURE_ITERATIONS / 2, component: 'detection' },
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 100, iterations: MEASURE_ITERATIONS / 2, component: 'filtering' },
  { messageSize: '10KB', sizeBytes: 10 * 1024, secretCount: 100, iterations: MEASURE_ITERATIONS / 2, component: 'pipeline' },
  
  // 100KB messages
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 1, iterations: MEASURE_ITERATIONS / 2, component: 'detection' },
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 1, iterations: MEASURE_ITERATIONS / 2, component: 'filtering' },
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 1, iterations: MEASURE_ITERATIONS / 2, component: 'pipeline' },
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 10, iterations: MEASURE_ITERATIONS / 2, component: 'detection' },
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 10, iterations: MEASURE_ITERATIONS / 2, component: 'filtering' },
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 10, iterations: MEASURE_ITERATIONS / 2, component: 'pipeline' },
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 100, iterations: MEASURE_ITERATIONS / 4, component: 'detection' },
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 100, iterations: MEASURE_ITERATIONS / 4, component: 'filtering' },
  { messageSize: '100KB', sizeBytes: 100 * 1024, secretCount: 100, iterations: MEASURE_ITERATIONS / 4, component: 'pipeline' },
  
  // 1MB messages (fewer iterations due to size)
  { messageSize: '1MB', sizeBytes: 1024 * 1024, secretCount: 1, iterations: 100, component: 'detection' },
  { messageSize: '1MB', sizeBytes: 1024 * 1024, secretCount: 1, iterations: 100, component: 'filtering' },
  { messageSize: '1MB', sizeBytes: 1024 * 1024, secretCount: 1, iterations: 100, component: 'pipeline' },
  { messageSize: '1MB', sizeBytes: 1024 * 1024, secretCount: 10, iterations: 100, component: 'detection' },
  { messageSize: '1MB', sizeBytes: 1024 * 1024, secretCount: 10, iterations: 100, component: 'filtering' },
  { messageSize: '1MB', sizeBytes: 1024 * 1024, secretCount: 10, iterations: 100, component: 'pipeline' },
];

function runScenario(scenario: BenchmarkScenario): BenchmarkResult {
  const text = generateTestMessage(scenario.sizeBytes, scenario.secretCount);
  
  let result: { latency: number[]; memory: MemoryMetrics };
  
  switch (scenario.component) {
    case 'detection':
      result = benchmarkDetection(text, scenario.iterations, WARMUP_ITERATIONS);
      break;
    case 'filtering':
      result = benchmarkFiltering(text, scenario.iterations, WARMUP_ITERATIONS);
      break;
    case 'pipeline':
      result = benchmarkPipeline(text, scenario.iterations, WARMUP_ITERATIONS);
      break;
    default:
      throw new Error(`Unknown component: ${scenario.component}`);
  }

  const stats = calculateStatistics(result.latency);
  const gateCheck = checkPerformanceGate(scenario.messageSize, stats.p95);

  return {
    scenario,
    latency: stats,
    memory: result.memory,
    status: gateCheck.status,
    gate: gateCheck.gate,
  };
}

// ============================================================================
// OUTPUT FORMATTERS
// ============================================================================

function printHumanReadable(results: BenchmarkResult[]): void {
  console.log('\n' + '='.repeat(100));
  console.log('OPENCODE FILTER - PERFORMANCE BENCHMARK RESULTS');
  console.log('='.repeat(100));
  console.log(`\nConfiguration:`);
  console.log(`  - Warmup iterations: ${WARMUP_ITERATIONS}`);
  console.log(`  - Measure iterations: ${MEASURE_ITERATIONS} (varies by scenario)`);
  console.log(`  - Metrics: P50, P95, P99, Mean, Min, Max, StdDev`);
  console.log(`  - Memory: Heap usage tracking`);
  console.log(`\nPerformance Gates:`);
  Object.entries(PERFORMANCE_GATES).forEach(([size, gate]) => {
    console.log(`  - ${size}: P95 < ${gate.p95}ms, P99 < ${gate.p99}ms`);
  });
  console.log('\n' + '='.repeat(100));

  // Group by message size
  const sizes = ['1KB', '10KB', '100KB', '1MB'];
  
  for (const size of sizes) {
    const sizeResults = results.filter(r => r.scenario.messageSize === size);
    if (sizeResults.length === 0) continue;

    console.log(`\n📦 Message Size: ${size}`);
    console.log('-'.repeat(100));
    
    // Group by secret count within size
    const secretCounts = [...new Set(sizeResults.map(r => r.scenario.secretCount))].sort((a, b) => a - b);
    
    for (const secretCount of secretCounts) {
      console.log(`\n  🔑 Secrets: ${secretCount}`);
      console.log('  ' + '-'.repeat(96));
      console.log(
        `  ${'Component'.padEnd(12)} ${'Iters'.padEnd(8)} ${'P50'.padEnd(10)} ${'P95'.padEnd(10)} ${'P99'.padEnd(10)} ${'Mean'.padEnd(10)} ${'Memory Δ'.padEnd(12)} ${'Status'.padEnd(10)}`
      );
      console.log('  ' + '-'.repeat(96));

      const componentResults = sizeResults.filter(r => r.scenario.secretCount === secretCount);
      
      for (const result of componentResults) {
        const status = result.status === 'PASS' ? '✅ PASS' : '❌ FAIL';
        console.log(
          `  ${result.scenario.component.padEnd(12)} ` +
          `${result.scenario.iterations.toString().padEnd(8)} ` +
          `${formatTime(result.latency.p50).padEnd(10)} ` +
          `${formatTime(result.latency.p95).padEnd(10)} ` +
          `${formatTime(result.latency.p99).padEnd(10)} ` +
          `${formatTime(result.latency.mean).padEnd(10)} ` +
          `${formatBytes(result.memory.delta).padEnd(12)} ` +
          `${status}`
        );
      }
    }
  }

  console.log('\n' + '='.repeat(100));
  
  // Summary
  const total = results.length;
  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = total - passed;
  
  console.log('\n📊 SUMMARY:');
  console.log(`  Total scenarios: ${total}`);
  console.log(`  Passed: ${passed} ✅`);
  console.log(`  Failed: ${failed} ${failed > 0 ? '❌' : ''}`);
  
  if (failed > 0) {
    console.log('\n❌ FAILED SCENARIOS:');
    results
      .filter(r => r.status === 'FAIL')
      .forEach(r => {
        console.log(`  - ${r.scenario.messageSize} / ${r.scenario.secretCount} secrets / ${r.scenario.component}: ${r.gate}`);
      });
  }
  
  console.log('\n' + '='.repeat(100));
  
  if (failed > 0) {
    console.log('\n❌ BENCHMARK FAILED: Some performance targets not met!\n');
  } else {
    console.log('\n✅ ALL BENCHMARKS PASSED: Performance targets met!\n');
  }
}

function generateJSONReport(results: BenchmarkResult[]): string {
  const report: FullBenchmarkReport = {
    timestamp: new Date().toISOString(),
    environment: {
      runtime: process.env.RUNTIME || 'bun',
      version: process.version,
      platform: process.platform,
    },
    configuration: {
      warmupIterations: WARMUP_ITERATIONS,
      measureIterations: MEASURE_ITERATIONS,
    },
    results: results,
    summary: {
      total: results.length,
      passed: results.filter(r => r.status === 'PASS').length,
      failed: results.filter(r => r.status === 'FAIL').length,
      duration: 0, // Will be calculated by caller
    },
  };
  
  return JSON.stringify(report, null, 2);
}

// ============================================================================
// MAIN
// ============================================================================

const isJSONMode = process.argv.includes('--json') || process.argv.includes('-j');

console.log('\n🔧 Initializing comprehensive benchmark suite...');
console.log(`   Mode: ${isJSONMode ? 'JSON (CI)' : 'Human-readable'}`);
console.log(`   Scenarios: ${SCENARIOS.length}`);
console.log(`   Message sizes: 1KB, 10KB, 100KB, 1MB`);
console.log(`   Secret densities: 1, 10, 100 per message`);
console.log(`   Components: detection, filtering, pipeline`);

const startTime = performance.now();
const results: BenchmarkResult[] = [];

console.log('\n🏃 Running benchmarks...\n');

for (let i = 0; i < SCENARIOS.length; i++) {
  const scenario = SCENARIOS[i];
  const progress = `[${i + 1}/${SCENARIOS.length}]`;
  
  if (!isJSONMode) {
    console.log(`  ${progress} Testing ${scenario.messageSize} with ${scenario.secretCount} secrets (${scenario.component})...`);
  }
  
  try {
    const result = runScenario(scenario);
    results.push(result);
    
    if (!isJSONMode) {
      const status = result.status === 'PASS' ? '✅' : '❌';
      console.log(`       ${status} P95: ${formatTime(result.latency.p95)} (${result.gate})`);
    }
  } catch (error) {
    console.error(`       ❌ Error: ${error instanceof Error ? error.message : String(error)}`);
    // Create a failed result
    results.push({
      scenario,
      latency: { p50: 0, p95: Infinity, p99: Infinity, mean: 0, min: 0, max: Infinity, stdDev: 0 },
      memory: { before: 0, after: 0, delta: 0 },
      status: 'FAIL',
      gate: `Error: ${error instanceof Error ? error.message : String(error)}`,
    });
  }
}

const endTime = performance.now();
const duration = endTime - startTime;

if (isJSONMode) {
  // Update duration in report
  const report = JSON.parse(generateJSONReport(results));
  report.summary.duration = Math.round(duration);
  console.log(JSON.stringify(report, null, 2));
} else {
  printHumanReadable(results);
  console.log(`\n⏱️  Total benchmark duration: ${(duration / 1000).toFixed(2)}s`);
}

// Exit with appropriate code
const failed = results.filter(r => r.status === 'FAIL').length;
process.exit(failed > 0 ? 1 : 0);
