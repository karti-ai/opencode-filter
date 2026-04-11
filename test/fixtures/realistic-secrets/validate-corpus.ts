/**
 * Corpus Validation Script
 * 
 * Validates all secret detection patterns against the realistic corpus of 146 examples.
 * Goal: Achieve 85%+ detection rate with <5% false positives.
 */

import { V2_PATTERNS, V2_PATTERN_COUNTS } from '../../../src/patterns/v2/index.js';
import type { SecretPattern } from '../../../src/types.js';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ============================================================================
// CORPUS FILE DEFINITIONS
// ============================================================================

const CORPUS_FILES = [
  { file: 'aws-keys.txt', expectedPatterns: ['aws_access_key_id', 'aws_secret_access_key'], totalExamples: 20 },
  { file: 'github-tokens.txt', expectedPatterns: ['github_personal_access_token', 'github_oauth_token', 'github_app_token', 'github_user_token', 'github_refresh_token'], totalExamples: 19 },
  { file: 'slack-tokens.txt', expectedPatterns: ['slack_bot_token', 'slack_user_token', 'slack_app_token', 'slack_webhook_url'], totalExamples: 11 },
  { file: 'database-urls.txt', expectedPatterns: ['postgres_connection_string', 'mysql_connection_string', 'mongodb_connection_string', 'redis_connection_string'], totalExamples: 18 },
  { file: 'jwt-tokens.txt', expectedPatterns: ['jwt_token_standard', 'jwt_token_hs256', 'jwt_token_rs256', 'jwt_token_es256'], totalExamples: 10 },
  { file: 'oauth-tokens.txt', expectedPatterns: ['oauth_access_token', 'oauth_refresh_token', 'oauth_authorization_code', 'gcp_oauth_access_token'], totalExamples: 15 },
  { file: 'ssh-keys.txt', expectedPatterns: ['ssh_rsa_private_key', 'ssh_openssh_private_key', 'ssh_ecdsa_private_key', 'ssh_dsa_private_key'], totalExamples: 5 },
  { file: 'stripe-keys.txt', expectedPatterns: ['stripe_live_secret_key', 'stripe_test_secret_key', 'stripe_webhook_secret'], totalExamples: 12 },
  { file: 'generic-api-keys.txt', expectedPatterns: ['generic_api_key_header', 'generic_api_key_pattern', 'generic_secret_assignment'], totalExamples: 27 },
];

const CORPUS_DIR = resolve(process.cwd(), 'test/fixtures/realistic-secrets');

// ============================================================================
// TYPES
// ============================================================================

interface DetectionResult {
  line: string;
  lineNumber: number;
  detected: boolean;
  matchedBy: string[];
  isComment: boolean;
  isEmpty: boolean;
}

interface FileValidationResult {
  fileName: string;
  totalLines: number;
  secretsFound: number;
  falsePositives: number;
  detectionRate: number;
  falsePositiveRate: number;
  detections: DetectionResult[];
}

interface OverallResult {
  totalExamples: number;
  totalDetected: number;
  totalMissed: number;
  totalFalsePositives: number;
  detectionRate: number;
  falsePositiveRate: number;
  fileResults: FileValidationResult[];
  patternStats: Map<string, { detected: number; total: number }>;
}

// ============================================================================
// PATTERN TESTING
// ============================================================================

/**
 * Test a single line against all patterns
 */
function testLineAgainstPatterns(line: string, lineNumber: number, patterns: SecretPattern[]): DetectionResult {
  const trimmed = line.trim();
  const isComment = trimmed.startsWith('#');
  const isEmpty = trimmed.length === 0;
  
  // Skip comment and empty lines for detection metrics, but track them
  const matchedPatterns: string[] = [];
  
  for (const pattern of patterns) {
    try {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
      if (regex.test(line)) {
        matchedPatterns.push(pattern.name);
      }
    } catch (e) {
      console.error(`  ⚠️  Pattern error in ${pattern.name}: ${e}`);
    }
  }
  
  return {
    line: line.substring(0, 80) + (line.length > 80 ? '...' : ''),
    lineNumber,
    detected: matchedPatterns.length > 0,
    matchedBy: matchedPatterns,
    isComment,
    isEmpty,
  };
}

/**
 * Determine if a detection is a likely false positive
 */
function isLikelyFalsePositive(detection: DetectionResult, fileName: string): boolean {
  // Comment lines are not false positives if they're examples
  if (detection.isComment && !detection.line.includes('Example')) {
    return false; // Comments explaining patterns are fine
  }
  
  // If it's a comment but we detected something, might be a false positive
  if (detection.isComment && detection.detected) {
    // Check if it looks like a real secret in the comment
    const hasSecretIndicators = /[a-zA-Z0-9]{16,}/.test(detection.line);
    if (!hasSecretIndicators) {
      return true;
    }
  }
  
  return false;
}

/**
 * Validate a single corpus file
 */
function validateCorpusFile(fileName: string, expectedPatterns: string[], totalExamples: number): FileValidationResult {
  const filePath = resolve(CORPUS_DIR, fileName);
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  
  const detections: DetectionResult[] = [];
  let secretsFound = 0;
  let falsePositives = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const detection = testLineAgainstPatterns(lines[i], i + 1, V2_PATTERNS);
    detections.push(detection);
    
    if (detection.detected && !detection.isComment && !detection.isEmpty) {
      secretsFound++;
    } else if (detection.detected && isLikelyFalsePositive(detection, fileName)) {
      falsePositives++;
    }
  }
  
  // Calculate meaningful lines (non-comment, non-empty)
  const meaningfulLines = detections.filter(d => !d.isComment && !d.isEmpty).length;
  const detectionRate = meaningfulLines > 0 ? (secretsFound / meaningfulLines) * 100 : 0;
  const falsePositiveRate = secretsFound > 0 ? (falsePositives / secretsFound) * 100 : 0;
  
  return {
    fileName,
    totalLines: lines.length,
    secretsFound,
    falsePositives,
    detectionRate,
    falsePositiveRate,
    detections,
  };
}

/**
 * Run full corpus validation
 */
function runValidation(): OverallResult {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║         OpenCode Filter V2 - Corpus Validation               ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');
  
  console.log(`Pattern Counts by Category:`);
  Object.entries(V2_PATTERN_COUNTS).forEach(([cat, count]) => {
    console.log(`  • ${cat}: ${count} patterns`);
  });
  console.log('');
  
  const fileResults: FileValidationResult[] = [];
  const patternStats = new Map<string, { detected: number; total: number }>();
  
  for (const corpus of CORPUS_FILES) {
    console.log(`📁 Validating: ${corpus.file}`);
    console.log(`   Expected patterns: ${corpus.expectedPatterns.join(', ')}`);
    
    const result = validateCorpusFile(corpus.file, corpus.expectedPatterns, corpus.totalExamples);
    fileResults.push(result);
    
    console.log(`   Total lines: ${result.totalLines}`);
    console.log(`   Secrets detected: ${result.secretsFound}`);
    console.log(`   Detection rate: ${result.detectionRate.toFixed(1)}%`);
    console.log('');
    
    // Track pattern statistics
    for (const detection of result.detections) {
      if (detection.detected && !detection.isComment && !detection.isEmpty) {
        for (const patternName of detection.matchedBy) {
          const current = patternStats.get(patternName) || { detected: 0, total: 0 };
          patternStats.set(patternName, { detected: current.detected + 1, total: current.total + 1 });
        }
      }
    }
  }
  
  // Calculate overall metrics
  let totalExamples = 0;
  let totalDetected = 0;
  let totalFalsePositives = 0;
  
  for (const result of fileResults) {
    const meaningfulLines = result.detections.filter(d => !d.isComment && !d.isEmpty).length;
    totalExamples += meaningfulLines;
    totalDetected += result.secretsFound;
    totalFalsePositives += result.falsePositives;
  }
  
  const detectionRate = totalExamples > 0 ? (totalDetected / totalExamples) * 100 : 0;
  const falsePositiveRate = totalDetected > 0 ? (totalFalsePositives / totalDetected) * 100 : 0;
  
  return {
    totalExamples,
    totalDetected,
    totalMissed: totalExamples - totalDetected,
    totalFalsePositives,
    detectionRate,
    falsePositiveRate,
    fileResults,
    patternStats,
  };
}

/**
 * Print detailed report
 */
function printReport(result: OverallResult): void {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║                    VALIDATION REPORT                         ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');
  
  console.log('📊 OVERALL METRICS');
  console.log('─────────────────────────────────────────────────────────────');
  console.log(`Total Examples:      ${result.totalExamples}`);
  console.log(`Secrets Detected:    ${result.totalDetected}`);
  console.log(`Secrets Missed:      ${result.totalMissed}`);
  console.log(`False Positives:     ${result.totalFalsePositives}`);
  console.log('');
  console.log(`Detection Rate:      ${result.detectionRate.toFixed(1)}% ${result.detectionRate >= 85 ? '✅' : '❌ (< 85%)'}`);
  console.log(`False Positive Rate: ${result.falsePositiveRate.toFixed(1)}% ${result.falsePositiveRate < 5 ? '✅' : '❌ (> 5%)'}`);
  console.log('');
  
  // File-by-file breakdown
  console.log('📁 FILE-BY-FILE BREAKDOWN');
  console.log('─────────────────────────────────────────────────────────────');
  for (const fileResult of result.fileResults) {
    const status = fileResult.detectionRate >= 80 ? '✅' : '⚠️ ';
    console.log(`${status} ${fileResult.fileName}`);
    console.log(`   Lines: ${fileResult.totalLines} | Detected: ${fileResult.secretsFound} | Rate: ${fileResult.detectionRate.toFixed(1)}%`);
  }
  console.log('');
  
  // Pattern effectiveness
  console.log('🎯 TOP PATTERNS BY DETECTION');
  console.log('─────────────────────────────────────────────────────────────');
  const sortedPatterns = Array.from(result.patternStats.entries())
    .sort((a, b) => b[1].detected - a[1].detected)
    .slice(0, 15);
  
  for (const [patternName, stats] of sortedPatterns) {
    console.log(`  • ${patternName}: ${stats.detected} detections`);
  }
  console.log('');
  
  // Underperforming patterns (patterns that should match but didn't)
  console.log('🔧 PATTERNS NEEDING ATTENTION');
  console.log('─────────────────────────────────────────────────────────────');
  
  for (const corpus of CORPUS_FILES) {
    const fileResult = result.fileResults.find(r => r.fileName === corpus.file);
    if (fileResult && fileResult.detectionRate < 80) {
      console.log(`⚠️  ${corpus.file}: ${fileResult.detectionRate.toFixed(1)}% detection`);
      console.log(`   Expected patterns: ${corpus.expectedPatterns.join(', ')}`);
      
      // Check which patterns are not matching
      for (const expectedPattern of corpus.expectedPatterns) {
        const stats = result.patternStats.get(expectedPattern);
        if (!stats || stats.detected === 0) {
          console.log(`   ❌ ${expectedPattern}: 0 detections - needs tuning`);
        }
      }
    }
  }
  console.log('');
  
  // Final verdict
  console.log('🏁 FINAL VERDICT');
  console.log('─────────────────────────────────────────────────────────────');
  const passed = result.detectionRate >= 85 && result.falsePositiveRate < 5;
  if (passed) {
    console.log('✅ VALIDATION PASSED');
    console.log('   Detection rate >= 85%: ✓');
    console.log('   False positive rate < 5%: ✓');
  } else {
    console.log('❌ VALIDATION FAILED');
    if (result.detectionRate < 85) {
      console.log(`   Detection rate too low: ${result.detectionRate.toFixed(1)}% (need >= 85%)`);
    }
    if (result.falsePositiveRate >= 5) {
      console.log(`   False positive rate too high: ${result.falsePositiveRate.toFixed(1)}% (need < 5%)`);
    }
  }
  console.log('');
}

/**
 * Run detailed line-by-line analysis for debugging
 */
function runDetailedAnalysis(fileName: string): void {
  const corpus = CORPUS_FILES.find(c => c.file === fileName);
  if (!corpus) {
    console.log(`❌ Unknown corpus file: ${fileName}`);
    return;
  }
  
  console.log(`\n🔍 Detailed Analysis: ${fileName}\n`);
  
  const filePath = resolve(CORPUS_DIR, fileName);
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    
    const detection = testLineAgainstPatterns(lines[i], i + 1, V2_PATTERNS);
    
    if (detection.detected) {
      console.log(`✅ Line ${i + 1}: DETECTED by [${detection.matchedBy.join(', ')}]`);
      console.log(`   ${line.substring(0, 60)}${line.length > 60 ? '...' : ''}`);
    } else {
      console.log(`❌ Line ${i + 1}: NOT DETECTED`);
      console.log(`   ${line.substring(0, 60)}${line.length > 60 ? '...' : ''}`);
    }
  }
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
Usage: bun run test/fixtures/realistic-secrets/validate-corpus.ts [options]

Options:
  --help, -h         Show this help message
  --analyze <file>   Run detailed analysis on a specific corpus file
  --report           Generate JSON report for CI/CD

Examples:
  bun run test/fixtures/realistic-secrets/validate-corpus.ts
  bun run test/fixtures/realistic-secrets/validate-corpus.ts --analyze aws-keys.txt
`);
  process.exit(0);
}

if (args.includes('--analyze')) {
  const fileIndex = args.indexOf('--analyze');
  const fileName = args[fileIndex + 1];
  if (fileName) {
    runDetailedAnalysis(fileName);
  } else {
    console.log('❌ Please specify a file to analyze: --analyze <filename>');
    process.exit(1);
  }
} else {
  const result = runValidation();
  printReport(result);
  
  // Save report
  const reportPath = resolve(process.cwd(), '.sisyphus/evidence/v2-t10-corpus-validation.txt');
  const reportContent = `
Corpus Validation Report
========================
Date: ${new Date().toISOString().split('T')[0]}
Total Examples: ${result.totalExamples}
Detected: ${result.totalDetected}
Missed: ${result.totalMissed}
Detection Rate: ${result.detectionRate.toFixed(1)}% ${result.detectionRate >= 85 ? '✅' : '❌'}

False Positives: ${result.totalFalsePositives}
False Positive Rate: ${result.falsePositiveRate.toFixed(1)}% ${result.falsePositiveRate < 5 ? '✅' : '❌'}

Top Patterns by Detection:
${Array.from(result.patternStats.entries())
  .sort((a, b) => b[1].detected - a[1].detected)
  .slice(0, 10)
  .map(([name, stats]) => `- ${name}: ${stats.detected} detections`)
  .join('\n')}

Files Needing Attention:
${result.fileResults
  .filter(f => f.detectionRate < 80)
  .map(f => `- ${f.fileName}: ${f.detectionRate.toFixed(1)}% detection`)
  .join('\n') || 'None - all files meet targets'}
`;
  
  try {
    import('fs').then(fs => {
      fs.mkdirSync(resolve(process.cwd(), '.sisyphus/evidence'), { recursive: true });
      fs.writeFileSync(reportPath, reportContent);
      console.log(`📄 Report saved to: ${reportPath}`);
    });
  } catch (e) {
    // Ignore write errors
  }
  
  // Exit with appropriate code for CI/CD
  const passed = result.detectionRate >= 85 && result.falsePositiveRate < 5;
  process.exit(passed ? 0 : 1);
}
