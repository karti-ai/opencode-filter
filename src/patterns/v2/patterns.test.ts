import { describe, it, expect } from 'vitest';
import {
  BUILTIN_PATTERNS,
  V2_PATTERNS,
  PATTERN_STATS,
  getV2Patterns,
  getV1Patterns,
} from '../builtin.js';

describe('V2 Patterns', () => {
  it('should have correct total pattern count', () => {
    expect(PATTERN_STATS.v1).toBe(20);
    expect(PATTERN_STATS.v2).toBeGreaterThan(200);
    expect(PATTERN_STATS.total).toBe(PATTERN_STATS.v1 + PATTERN_STATS.v2);
  });

  it('should have V2 patterns loaded', () => {
    const v2Patterns = getV2Patterns();
    expect(v2Patterns.length).toBe(PATTERN_STATS.v2);
  });

  it('should have V1 patterns loaded', () => {
    const v1Patterns = getV1Patterns();
    expect(v1Patterns.length).toBe(20);
  });

  it('should have cloud patterns', () => {
    expect(PATTERN_STATS.v2Breakdown.cloud).toBe(30);
  });

  it('should have code hosting patterns', () => {
    expect(PATTERN_STATS.v2Breakdown.codeHosting).toBe(15);
  });

  it('should have communication patterns', () => {
    expect(PATTERN_STATS.v2Breakdown.communication).toBe(20);
  });

  it('should have payment patterns', () => {
    expect(PATTERN_STATS.v2Breakdown.payment).toBe(15);
  });

  it('should have authentication patterns', () => {
    expect(PATTERN_STATS.v2Breakdown.authentication).toBe(25);
  });

  it('should have SaaS patterns', () => {
    expect(PATTERN_STATS.v2Breakdown.saas).toBe(60);
  });

  it('should have infrastructure patterns', () => {
    expect(PATTERN_STATS.v2Breakdown.infrastructure).toBe(30);
  });

  it('should have generic patterns', () => {
    expect(PATTERN_STATS.v2Breakdown.generic).toBe(15);
  });

  it('should have valid regex patterns', () => {
    for (const pattern of V2_PATTERNS) {
      expect(pattern.regex).toBeInstanceOf(RegExp);
      expect(pattern.name).toBeTruthy();
      expect(pattern.category).toBeTruthy();
      expect(pattern.description).toBeTruthy();
      expect(pattern.severity).toMatch(/^(low|medium|high|critical)$/);
      expect(pattern.example).toBeTruthy();
    }
  });

  it('should detect AWS access key ID', () => {
    const awsPattern = V2_PATTERNS.find((p) => p.name === 'aws_access_key_id');
    expect(awsPattern).toBeDefined();
    expect(awsPattern?.regex.test('AKIAIOSFODNN7EXAMPLE')).toBe(true);
  });

  it('should detect GitHub personal access token', () => {
    const githubPattern = V2_PATTERNS.find(
      (p) => p.name === 'github_personal_access_token'
    );
    expect(githubPattern).toBeDefined();
    expect(
      githubPattern?.regex.test('ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890')
    ).toBe(true);
  });

  it('should detect Slack bot token', () => {
    const slackPattern = V2_PATTERNS.find((p) => p.name === 'slack_bot_token');
    expect(slackPattern).toBeDefined();
    expect(
      slackPattern?.regex.test(
        'xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX'
      )
    ).toBe(true);
  });

  it('should detect Stripe live key', () => {
    const stripePattern = V2_PATTERNS.find(
      (p) => p.name === 'stripe_live_secret_key'
    );
    expect(stripePattern).toBeDefined();
    expect(
      stripePattern?.regex.test('sk_live_abcdefghijklmnopqrstuvwxyz1234')
    ).toBe(true);
  });

  it('should detect JWT token', () => {
    const jwtPattern = V2_PATTERNS.find(
      (p) => p.name === 'jwt_token_standard'
    );
    expect(jwtPattern).toBeDefined();
    expect(
      jwtPattern?.regex.test(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMe'
      )
    ).toBe(true);
  });

  it('should detect Twilio account SID', () => {
    const twilioPattern = V2_PATTERNS.find(
      (p) => p.name === 'twilio_account_sid'
    );
    expect(twilioPattern).toBeDefined();
    expect(twilioPattern?.regex.test('ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')).toBe(
      true
    );
  });

  it('should detect PostgreSQL connection string', () => {
    const pgPattern = V2_PATTERNS.find(
      (p) => p.name === 'postgres_connection_string'
    );
    expect(pgPattern).toBeDefined();
    expect(
      pgPattern?.regex.test(
        'postgresql://admin:password123@localhost:5432/mydb'
      )
    ).toBe(true);
  });

  it('should detect generic password assignment', () => {
    const pwdPattern = V2_PATTERNS.find(
      (p) => p.name === 'generic_password_assignment'
    );
    expect(pwdPattern).toBeDefined();
    expect(pwdPattern?.regex.test('password = "MySecretPassword123!"')).toBe(
      true
    );
  });

  it('all patterns should have unique names', () => {
    const names = V2_PATTERNS.map((p) => p.name);
    const uniqueNames = new Set(names);
    expect(uniqueNames.size).toBe(names.length);
  });

  it('combined patterns should include both V1 and V2', () => {
    const combinedNames = BUILTIN_PATTERNS.map((p) => p.name);
    const v1Names = getV1Patterns().map((p) => p.name);
    const v2Names = getV2Patterns().map((p) => p.name);

    for (const v1Name of v1Names) {
      expect(combinedNames).toContain(v1Name);
    }

    for (const v2Name of v2Names) {
      expect(combinedNames).toContain(v2Name);
    }
  });
});
