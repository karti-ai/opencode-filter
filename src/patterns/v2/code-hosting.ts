/**
 * Code Hosting Secret Patterns (V2)
 *
 * 15 patterns covering GitHub, GitLab, Bitbucket, and other code hosting services.
 * Based on patterns from TruffleHog, GitHub Secret Scanning, and GitLeaks.
 */

import type { SecretPattern } from '../../types.js';

/**
 * Code hosting secret patterns
 * Total: 15 patterns
 * - GitHub: 8 patterns
 * - GitLab: 4 patterns
 * - Bitbucket: 3 patterns
 */
export const CODE_HOSTING_PATTERNS: SecretPattern[] = [
  // ============================================================================
  // GitHub (8 patterns)
  // ============================================================================

  {
    name: 'github_personal_access_token',
    regex: /ghp_[a-zA-Z0-9]{36}/,
    category: 'token',
    description: 'GitHub Personal Access Token starting with ghp_',
    severity: 'critical',
    example: 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  {
    name: 'github_oauth_token',
    regex: /gho_[a-zA-Z0-9]{36}/,
    category: 'token',
    description: 'GitHub OAuth Token starting with gho_',
    severity: 'critical',
    example: 'gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  {
    name: 'github_user_token',
    regex: /ghu_[a-zA-Z0-9]{36}/,
    category: 'token',
    description: 'GitHub User Token starting with ghu_',
    severity: 'critical',
    example: 'ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  {
    name: 'github_app_token',
    regex: /ghs_[a-zA-Z0-9]{36}/,
    category: 'token',
    description: 'GitHub App Token starting with ghs_',
    severity: 'critical',
    example: 'ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  {
    name: 'github_refresh_token',
    regex: /ghr_[a-zA-Z0-9]{36}/,
    category: 'token',
    description: 'GitHub Refresh Token starting with ghr_',
    severity: 'critical',
    example: 'ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  {
    name: 'github_ssh_private_key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    category: 'private_key',
    description: 'GitHub SSH Private Key (OpenSSH format)',
    severity: 'critical',
    example: '-----BEGIN OPENSSH PRIVATE KEY-----',
  },

  {
    name: 'github_gist_secret',
    regex: /https:\/\/gist\.github\.com\/[^\/]+\/[a-f0-9]{32}/,
    category: 'credential',
    description: 'GitHub Gist URL with potential secret content',
    severity: 'medium',
    example: 'https://gist.github.com/user/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'github_actions_secret',
    regex: /GITHUB_TOKEN|github_token\s*[=:]\s*['"][a-zA-Z0-9_]+['"]/i,
    category: 'token',
    description: 'GitHub Actions workflow token reference',
    severity: 'high',
    example: 'GITHUB_TOKEN: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  // ============================================================================
  // GitLab (4 patterns)
  // ============================================================================

  {
    name: 'gitlab_personal_access_token',
    regex: /glpat-[a-zA-Z0-9\-]{20}/,
    category: 'token',
    description: 'GitLab Personal Access Token starting with glpat-',
    severity: 'critical',
    example: 'glpat-abcdefghij12345678',
  },

  {
    name: 'gitlab_runner_token',
    regex: /GR1348941[a-zA-Z0-9_-]{20}/,
    category: 'token',
    description: 'GitLab Runner Registration Token',
    severity: 'critical',
    example: 'GR1348941abcdefghij12345678',
  },

  {
    name: 'gitlab_deploy_token',
    regex: /gldt-[a-zA-Z0-9\-]{20}/,
    category: 'token',
    description: 'GitLab Deploy Token starting with gldt-',
    severity: 'critical',
    example: 'gldt-abcdefghij12345678',
  },

  {
    name: 'gitlab_ci_token',
    regex: /CI_JOB_TOKEN|CI_JOB_TOKEN\s*[=:]\s*['"][a-zA-Z0-9_-]+['"]/i,
    category: 'token',
    description: 'GitLab CI/CD Job Token reference',
    severity: 'high',
    example: 'CI_JOB_TOKEN=glpat-abcdefghij12345678',
  },

  // ============================================================================
  // Bitbucket (3 patterns)
  // ============================================================================

  {
    name: 'bitbucket_app_password',
    regex: /[a-zA-Z0-9]{32}@[a-zA-Z0-9_-]+/,
    category: 'password',
    description: 'Bitbucket App Password with username suffix',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6@username',
  },

  {
    name: 'bitbucket_access_token',
    regex: /[a-zA-Z0-9_\-]{40}/,
    category: 'token',
    description: 'Bitbucket OAuth Access Token (40 characters)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'bitbucket_ssh_key',
    regex: /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/,
    category: 'private_key',
    description: 'Bitbucket SSH Private Key',
    severity: 'critical',
    example: '-----BEGIN RSA PRIVATE KEY-----',
  },
];

export default CODE_HOSTING_PATTERNS;
