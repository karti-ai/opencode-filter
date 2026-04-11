/**
 * Communication Platform Secret Patterns (V2)
 *
 * 20 patterns covering Slack, Discord, Microsoft Teams, and Telegram.
 * Based on patterns from TruffleHog, GitHub Secret Scanning, and GitLeaks.
 */

import type { SecretPattern } from '../../types.js';

/**
 * Communication platform secret patterns
 * Total: 20 patterns
 * - Slack: 8 patterns
 * - Discord: 4 patterns
 * - Teams: 4 patterns
 * - Telegram: 4 patterns
 */
export const COMMUNICATION_PATTERNS: SecretPattern[] = [
  // ============================================================================
  // Slack (8 patterns)
  // ============================================================================

  {
    name: 'slack_bot_token',
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/,
    category: 'token',
    description: 'Slack Bot Token (OAuth bot access token)',
    severity: 'critical',
    example: 'xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX',
  },

  {
    name: 'slack_user_token',
    regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}/,
    category: 'token',
    description: 'Slack User Token (OAuth user access token)',
    severity: 'critical',
    example: 'xoxp-1234567890123-1234567890123-1234567890123-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'slack_app_token',
    regex: /xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{64}/,
    category: 'token',
    description: 'Slack App Token (for Socket Mode)',
    severity: 'critical',
    example: 'xapp-1-A1234567890-1234567890-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8',
  },

  {
    name: 'slack_legacy_token',
    regex: /xox[a-z]-[a-zA-Z0-9-]+/,
    category: 'token',
    description: 'Slack Legacy Token (deprecated but still in use)',
    severity: 'critical',
    example: 'xoxo-1234567890-1234567890-1234567890-a1b2c3d4',
  },

  {
    name: 'slack_webhook_url',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{10}\/[a-zA-Z0-9_]{24}/,
    category: 'credential',
    description: 'Slack Incoming Webhook URL',
    severity: 'high',
    example: 'https://hooks.slack.com/services/T12345678/B1234567890/a1b2c3d4e5f6g7h8i9j0k1l2m',
  },

  {
    name: 'slack_signing_secret',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'Slack App Signing Secret (32-character hex)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'slack_config_token',
    regex: /xoxe\.xox[bp]-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+/,
    category: 'token',
    description: 'Slack Configuration Token',
    severity: 'critical',
    example: 'xoxe.xoxb-1234567890-1234567890-1234567890-aBcDeFgHiJkLmNoPqRsTuVwX',
  },

  {
    name: 'slack_heroku_token',
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/,
    category: 'token',
    description: 'Slack token commonly used in Heroku configs',
    severity: 'critical',
    example: 'xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX',
  },

  // ============================================================================
  // Discord (4 patterns)
  // ============================================================================

  {
    name: 'discord_bot_token',
    regex: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/,
    category: 'token',
    description: 'Discord Bot Token (OAuth2 bot token)',
    severity: 'critical',
    example: 'NzA1MTYwNjE4NjQxMzY4NTc0.a1b2c3.d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'discord_webhook_url',
    regex: /https:\/\/(discord\.com|discordapp\.com)\/api\/webhooks\/[0-9]{18,20}\/[A-Za-z0-9_-]{68}/,
    category: 'credential',
    description: 'Discord Webhook URL',
    severity: 'high',
    example: 'https://discord.com/api/webhooks/1234567890123456789/aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJkLmNoPqRsTuVwXyZ12345',
  },

  {
    name: 'discord_client_secret',
    regex: /[a-zA-Z0-9_-]{32}/,
    category: 'credential',
    description: 'Discord OAuth2 Client Secret',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'discord_nitro_code',
    regex: /https:\/\/(discord\.gift|discord\.com\/gifts)\/[a-zA-Z0-9]{16,24}/,
    category: 'credential',
    description: 'Discord Nitro Gift Code',
    severity: 'medium',
    example: 'https://discord.gift/a1b2c3d4e5f6g7h8',
  },

  // ============================================================================
  // Microsoft Teams (4 patterns)
  // ============================================================================

  {
    name: 'teams_webhook_url',
    regex: /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9-]+@[a-z0-9-]+\/IncomingWebhook\/[a-z0-9]+\/[a-z0-9-]+/,
    category: 'credential',
    description: 'Microsoft Teams Incoming Webhook URL',
    severity: 'high',
    example: 'https://mycompany.webhook.office.com/webhookb2/a1b2c3d4@a1b2c3d4/IncomingWebhook/a1b2c3d4/a1b2c3d4',
  },

  {
    name: 'teams_bot_framework_token',
    regex: /[a-zA-Z0-9_.-]{100,200}/,
    category: 'token',
    description: 'Microsoft Bot Framework Token for Teams',
    severity: 'critical',
    example: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjdkRC1nZWNOZ1gxWmY3R0xrT3ZwT0IyZDdjWSJ9',
  },

  {
    name: 'teams_app_password',
    regex: /[a-zA-Z0-9]{32,64}/,
    category: 'password',
    description: 'Microsoft Teams App Password',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'teams_graph_api_token',
    regex: /eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'Microsoft Graph API Token for Teams integration',
    severity: 'critical',
    example: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjdkRC1nZWNOZ1gxWmY3R0xrT3ZwT0IyZDdjWSJ9',
  },

  // ============================================================================
  // Telegram (4 patterns)
  // ============================================================================

  {
    name: 'telegram_bot_token',
    regex: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/,
    category: 'token',
    description: 'Telegram Bot Token (bot ID + secret)',
    severity: 'critical',
    example: '123456789:ABCdefGHIjklMNOpqrSTUvwxyz123456789',
  },

  {
    name: 'telegram_api_id',
    regex: /api_id\s*[=:]\s*['"]?[0-9]{5,8}['"]?/i,
    category: 'api_key',
    description: 'Telegram API ID',
    severity: 'medium',
    example: 'api_id=12345678',
  },

  {
    name: 'telegram_api_hash',
    regex: /api_hash\s*[=:]\s*['"]?[a-f0-9]{32}['"]?/i,
    category: 'api_key',
    description: 'Telegram API Hash',
    severity: 'critical',
    example: 'api_hash=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'telegram_mtproto_secret',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'Telegram MTProto Proxy Secret',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },
];

export default COMMUNICATION_PATTERNS;
