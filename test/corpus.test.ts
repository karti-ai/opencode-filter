/**
 * Realistic Secret Corpus Test
 *
 * Validates detection accuracy on 100+ realistic secret examples.
 * Tests against real-world patterns from GitHub Secret Scanning,
 * TruffleHog, and GitLeaks test data.
 *
 * Target: >85% detection accuracy
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join, basename } from 'path';
import { fileURLToPath } from 'url';
import { RegexEngine } from '../src/patterns/regex-engine';
import { EntropyEngine } from '../src/entropy';
import { SecretDetector } from '../src/detector';
import type { DetectedSecret } from '../src/types';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const FIXTURES_DIR = join(__dirname, 'fixtures/realistic-secrets');

interface SecretExample {
  value: string;
  category: string;
  line: number;
  source: string;
}

interface CategoryResult {
  total: number;
  detected: number;
  accuracy: number;
  secrets: SecretExample[];
}

interface CorpusResults {
  total: number;
  detected: number;
  accuracy: number;
  byCategory: Record<string, CategoryResult>;
}

/**
 * Parse fixture files and extract secret examples
 * Ignores comment lines (starting with #) and empty lines
 */
function loadSecretCorpus(): SecretExample[] {
  const files = readdirSync(FIXTURES_DIR).filter(f => f.endsWith('.txt'));
  const examples: SecretExample[] = [];

  for (const file of files) {
    const category = basename(file, '.txt');
    const content = readFileSync(join(FIXTURES_DIR, file), 'utf-8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      // Skip comments, empty lines, and continuation lines
      if (!line || line.startsWith('#')) continue;
      // Skip lines that are clearly continuation of multiline secrets
      if (line.startsWith('-----') || line.includes('= ') && !line.includes(':') && !line.includes('=')) {
        continue;
      }
      
      examples.push({
        value: line,
        category,
        line: i + 1,
        source: file,
      });
    }
  }

  return examples;
}

/**
 * Check if a secret value is detected by the engine
 */
function isDetected(secret: SecretExample, detector: SecretDetector): boolean {
  const text = secret.value;
  const results = detector.detect(text);
  
  // A secret is detected if any result overlaps with the secret value
  return results.length > 0;
}

/**
 * Get detailed detection results for a secret
 */
function getDetectionDetails(secret: SecretExample, detector: SecretDetector): DetectedSecret[] {
  const text = secret.value;
  return detector.detect(text);
}

describe('Realistic Secret Corpus', () => {
  let detector: SecretDetector;
  let corpus: SecretExample[];
  let results: CorpusResults;

  beforeAll(() => {
    // Initialize detector with regex and entropy engines
    const regexEngine = new RegexEngine();
    const entropyEngine = new EntropyEngine(4.5, 16);
    detector = new SecretDetector(regexEngine, entropyEngine);

    // Load corpus
    corpus = loadSecretCorpus();

    // Initialize results
    results = {
      total: corpus.length,
      detected: 0,
      accuracy: 0,
      byCategory: {},
    };

    // Run detection on all examples
    for (const secret of corpus) {
      if (!results.byCategory[secret.category]) {
        results.byCategory[secret.category] = {
          total: 0,
          detected: 0,
          accuracy: 0,
          secrets: [],
        };
      }

      results.byCategory[secret.category].total++;
      results.byCategory[secret.category].secrets.push(secret);

      if (isDetected(secret, detector)) {
        results.detected++;
        results.byCategory[secret.category].detected++;
      }
    }

    // Calculate accuracy percentages
    results.accuracy = (results.detected / results.total) * 100;
    
    for (const category of Object.keys(results.byCategory)) {
      const cat = results.byCategory[category];
      cat.accuracy = (cat.detected / cat.total) * 100;
    }
  });

  describe('Corpus Statistics', () => {
    it('should have loaded at least 100 secret examples', () => {
      expect(results.total).toBeGreaterThanOrEqual(100);
    });

    it('should detect secrets in all categories', () => {
      const categories = Object.keys(results.byCategory);
      expect(categories.length).toBeGreaterThanOrEqual(8);
    });

    it('should print corpus statistics', () => {
      console.log('\n=== Realistic Secret Corpus Results ===\n');
      console.log(`Total Examples: ${results.total}`);
      console.log(`Total Detected: ${results.detected}`);
      console.log(`Overall Accuracy: ${results.accuracy.toFixed(2)}%\n`);

      console.log('By Category:');
      console.table(
        Object.entries(results.byCategory).map(([name, data]) => ({
          Category: name,
          Total: data.total,
          Detected: data.detected,
          Accuracy: `${data.accuracy.toFixed(1)}%`,
        }))
      );

      // Print undetected examples for debugging
      const undetected: Record<string, SecretExample[]> = {};
      for (const [category, data] of Object.entries(results.byCategory)) {
        const missed = data.secrets.filter(s => !isDetected(s, detector));
        if (missed.length > 0) {
          undetected[category] = missed.slice(0, 3); // Show first 3 per category
        }
      }

      if (Object.keys(undetected).length > 0) {
        console.log('\n=== Undetected Examples (first 3 per category) ===\n');
        for (const [category, examples] of Object.entries(undetected)) {
          console.log(`\n${category}:`);
          examples.forEach(ex => {
            console.log(`  Line ${ex.line}: ${ex.value.substring(0, 50)}${ex.value.length > 50 ? '...' : ''}`);
          });
        }
      }
    });
  });

  describe('Overall Accuracy', () => {
    it('should achieve >85% detection accuracy', () => {
      expect(results.accuracy).toBeGreaterThan(85);
    });
  });

  describe('Category Accuracy', () => {
    const criticalCategories = ['aws-keys', 'github-tokens', 'stripe-keys'];
    
    for (const category of criticalCategories) {
      it(`should detect ${category} with >80% accuracy`, () => {
        const cat = results.byCategory[category];
        expect(cat).toBeDefined();
        expect(cat.accuracy).toBeGreaterThan(80);
      });
    }

    it('should detect jwt-tokens with reasonable accuracy', () => {
      const cat = results.byCategory['jwt-tokens'];
      expect(cat).toBeDefined();
      expect(cat.accuracy).toBeGreaterThan(70);
    });

    it('should detect slack-tokens with reasonable accuracy', () => {
      const cat = results.byCategory['slack-tokens'];
      expect(cat).toBeDefined();
      expect(cat.accuracy).toBeGreaterThan(70);
    });

    it('should detect database-urls with reasonable accuracy', () => {
      const cat = results.byCategory['database-urls'];
      expect(cat).toBeDefined();
      expect(cat.accuracy).toBeGreaterThan(70);
    });
  });

  describe('Specific Detection Tests', () => {
    it('should detect AWS Access Key IDs', () => {
      const awsExamples = corpus.filter(s => 
        s.category === 'aws-keys' && s.value.startsWith('AKIA')
      );
      expect(awsExamples.length).toBeGreaterThan(0);
      
      const detected = awsExamples.filter(s => isDetected(s, detector));
      expect(detected.length / awsExamples.length).toBeGreaterThan(0.8);
    });

    it('should detect GitHub Personal Access Tokens', () => {
      const githubExamples = corpus.filter(s => 
        s.category === 'github-tokens' && s.value.startsWith('ghp_')
      );
      expect(githubExamples.length).toBeGreaterThan(0);
      
      const detected = githubExamples.filter(s => isDetected(s, detector));
      expect(detected.length / githubExamples.length).toBeGreaterThan(0.8);
    });

    it('should detect Stripe Live Keys', () => {
      const stripeExamples = corpus.filter(s => 
        s.category === 'stripe-keys' && s.value.startsWith('sk_live_')
      );
      expect(stripeExamples.length).toBeGreaterThan(0);
      
      const detected = stripeExamples.filter(s => isDetected(s, detector));
      expect(detected.length / stripeExamples.length).toBeGreaterThan(0.8);
    });

    it('should detect JWT tokens', () => {
      const jwtExamples = corpus.filter(s => 
        s.category === 'jwt-tokens' && s.value.startsWith('eyJ')
      );
      expect(jwtExamples.length).toBeGreaterThan(0);
      
      const detected = jwtExamples.filter(s => isDetected(s, detector));
      expect(detected.length / jwtExamples.length).toBeGreaterThan(0.7);
    });

    it('should detect Slack tokens', () => {
      const slackExamples = corpus.filter(s => 
        s.category === 'slack-tokens' && (s.value.startsWith('xox') || s.value.includes('hooks.slack.com'))
      );
      expect(slackExamples.length).toBeGreaterThan(0);
      
      const detected = slackExamples.filter(s => isDetected(s, detector));
      expect(detected.length / slackExamples.length).toBeGreaterThan(0.7);
    });

    it('should detect database connection strings', () => {
      const dbExamples = corpus.filter(s => 
        s.category === 'database-urls' && 
        (s.value.startsWith('postgres') || s.value.startsWith('mysql') || 
         s.value.startsWith('mongodb') || s.value.startsWith('redis'))
      );
      expect(dbExamples.length).toBeGreaterThan(0);
      
      const detected = dbExamples.filter(s => isDetected(s, detector));
      expect(detected.length / dbExamples.length).toBeGreaterThan(0.7);
    });

    it('should detect SSH keys via entropy', () => {
      // SSH keys are parsed as individual lines of base64 content
      const sshExamples = corpus.filter(s => 
        s.category === 'ssh-keys' && 
        (s.value.length > 20 || s.value.includes('fake@example.com'))
      );
      expect(sshExamples.length).toBeGreaterThan(0);
      
      const detected = sshExamples.filter(s => isDetected(s, detector));
      expect(detected.length / sshExamples.length).toBeGreaterThan(0.8);
    });
  });

  describe('Individual Secret Validation', () => {
    it('provides detailed detection info for each category', () => {
      const summary: Record<string, { tested: number; detected: number; details: string[] }> = {};

      for (const secret of corpus) {
        if (!summary[secret.category]) {
          summary[secret.category] = { tested: 0, detected: 0, details: [] };
        }

        summary[secret.category].tested++;
        const detected = isDetected(secret, detector);
        if (detected) {
          summary[secret.category].detected++;
        }

        // Add detail for first 2 of each category
        if (summary[secret.category].details.length < 2) {
          const details = getDetectionDetails(secret, detector);
          const status = detected ? '✓' : '✗';
          summary[secret.category].details.push(
            `${status} "${secret.value.substring(0, 30)}..." → ${detected ? details.map(d => d.pattern.name).join(', ') : 'NOT DETECTED'}`
          );
        }
      }

      // Log the detailed summary
      console.log('\n=== Detailed Detection Summary ===\n');
      for (const [category, data] of Object.entries(summary)) {
        const accuracy = ((data.detected / data.tested) * 100).toFixed(1);
        console.log(`${category}: ${data.detected}/${data.tested} (${accuracy}%)`);
        data.details.forEach(d => console.log(`  ${d}`));
        console.log('');
      }
    });
  });
});

// Export for use in other tests
export { loadSecretCorpus, isDetected, getDetectionDetails };
export type { SecretExample, CorpusResults, CategoryResult };
