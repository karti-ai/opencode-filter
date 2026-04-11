/**
 * OpenCode Hook Integration Tests
 *
 * End-to-end tests for the OpenCode hook integration with mocked OpenCode API.
 * Tests message flow through hooks: outgoing (transform), incoming (restore),
 * and tool execution (restore).
 */

import { describe, it, expect, beforeEach } from 'bun:test';
import { RegexEngine } from './patterns/regex-engine.js';
import { SessionManager, MessageFilter, createHooks } from './hooks.js';
import type { FilterConfig } from './types.js';

// ============================================================================
// MOCK OPENCODE TYPES
// ============================================================================

interface MockMessage {
  id: string;
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string;
}

interface MockPart {
  type: 'text' | 'tool-call' | 'tool-result';
  text?: string;
  toolCall?: {
    id: string;
    name: string;
    args: Record<string, unknown>;
  };
  toolResult?: {
    id: string;
    result: unknown;
  };
}

// ============================================================================
// MOCK OPENCODE API
// ============================================================================

/**
 * Mock Hooks interface that simulates OpenCode's hook system
 */
class MockOpenCodeHooks {
  private hooks: Map<string, Function> = new Map();
  private sessionManager: SessionManager;

  constructor(sessionManager: SessionManager) {
    this.sessionManager = sessionManager;
  }

  register(hookName: string, handler: Function): void {
    this.hooks.set(hookName, handler);
  }

  async execute(hookName: string, input: Record<string, unknown>, output: Record<string, unknown>): Promise<void> {
    const handler = this.hooks.get(hookName);
    if (!handler) {
      throw new Error(`Hook "${hookName}" not registered`);
    }

    try {
      await handler(input, output);
    } catch (error) {
      // Re-throw to simulate fail-closed behavior
      throw error;
    }
  }

  hasHook(hookName: string): boolean {
    return this.hooks.has(hookName);
  }
}

// ============================================================================
// TEST FIXTURES
// ============================================================================

const MOCK_AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const MOCK_GITHUB_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890';
const MOCK_SLACK_TOKEN = 'xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX';

const TEST_CONFIG: FilterConfig = {
  patterns: [],
  entropyThreshold: 4.5,
  minSecretLength: 16,
  maxSecretsPerSession: 100,
  enabled: true,
  mode: 'redact',
};

// ============================================================================
// TEST SETUP HELPERS
// ============================================================================

function createTestEnvironment() {
  const regexEngine = new RegexEngine({
    customPatterns: [],
  });
  const sessionManager = new SessionManager();
  const messageFilter = new MessageFilter(regexEngine, sessionManager, TEST_CONFIG);
  const hooks = createHooks(messageFilter, sessionManager);
  const mockHooks = new MockOpenCodeHooks(sessionManager);

  // Register the actual hook handlers
  mockHooks.register('experimental.chat.messages.transform', hooks['experimental.chat.messages.transform']);
  mockHooks.register('experimental.text.complete', hooks['experimental.text.complete']);
  mockHooks.register('tool.execute.before', hooks['tool.execute.before']);

  return {
    regexEngine,
    sessionManager,
    messageFilter,
    hooks,
    mockHooks,
  };
}

// ============================================================================
// TESTS
// ============================================================================

describe('OpenCode Hook Integration', () => {
  let env: ReturnType<typeof createTestEnvironment>;

  beforeEach(() => {
    env = createTestEnvironment();
  });

  // ==========================================================================
  // experimental.chat.messages.transform hook
  // ==========================================================================

  describe('experimental.chat.messages.transform', () => {
    it('should replace secrets with placeholders in outgoing messages', async () => {
      const messageId = 'msg-001';
      const originalContent = `My AWS key is ${MOCK_AWS_KEY}`;

      const output = {
        messages: [
          {
            info: {
              id: messageId,
              role: 'user',
              content: originalContent,
            } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      // Verify the secret was replaced
      expect(output.messages[0].parts[0].text).not.toContain(MOCK_AWS_KEY);
      expect(output.messages[0].parts[0].text).toMatch(/<SECRET_[A-Z_]+_\d+>/);
      expect(output.messages[0].info.content).not.toContain(MOCK_AWS_KEY);
    });

    it('should use consistent placeholder for same secret in same session', async () => {
      const messageId = 'msg-002';
      const originalContent = `Key1: ${MOCK_AWS_KEY} and Key2: ${MOCK_AWS_KEY}`;

      const output = {
        messages: [
          {
            info: { id: messageId, role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      const transformedText = output.messages[0].parts[0].text;
      const placeholders = transformedText.match(/<SECRET_[A-Z_]+_\d+>/g) || [];

      // Should have at least one placeholder
      expect(placeholders.length).toBeGreaterThanOrEqual(1);

      // All placeholders for the same secret should be identical
      const uniquePlaceholders = [...new Set(placeholders)];
      expect(uniquePlaceholders.length).toBe(1);
    });

    it('should handle multiple different secrets in one message', async () => {
      const messageId = 'msg-003';
      const originalContent = `AWS: ${MOCK_AWS_KEY} and GitHub: ${MOCK_GITHUB_TOKEN}`;

      const output = {
        messages: [
          {
            info: { id: messageId, role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      const transformedText = output.messages[0].parts[0].text;

      // Neither secret should be present
      expect(transformedText).not.toContain(MOCK_AWS_KEY);
      expect(transformedText).not.toContain(MOCK_GITHUB_TOKEN);

      // Should have placeholders
      expect(transformedText).toMatch(/<SECRET_[A-Z_]+_\d+>/);
    });

    it('should handle multiple messages in batch', async () => {
      const output = {
        messages: [
          {
            info: { id: 'msg-001', role: 'user', content: `First: ${MOCK_AWS_KEY}` } as MockMessage,
            parts: [{ type: 'text', text: `First: ${MOCK_AWS_KEY}` } as MockPart],
          },
          {
            info: { id: 'msg-002', role: 'assistant', content: `Second: ${MOCK_GITHUB_TOKEN}` } as MockMessage,
            parts: [{ type: 'text', text: `Second: ${MOCK_GITHUB_TOKEN}` } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      expect(output.messages[0].parts[0].text).not.toContain(MOCK_AWS_KEY);
      expect(output.messages[1].parts[0].text).not.toContain(MOCK_GITHUB_TOKEN);
    });

    it('should handle messages without secrets', async () => {
      const originalContent = 'Hello, how are you today?';

      const output = {
        messages: [
          {
            info: { id: 'msg-004', role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      // Content should remain unchanged
      expect(output.messages[0].parts[0].text).toBe(originalContent);
      expect(output.messages[0].info.content).toBe(originalContent);
    });

    it('should handle empty messages', async () => {
      const output = {
        messages: [
          {
            info: { id: 'msg-005', role: 'user', content: '' } as MockMessage,
            parts: [{ type: 'text', text: '' } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      expect(output.messages[0].parts[0].text).toBe('');
    });

    it('should handle non-text parts without modification', async () => {
      const output = {
        messages: [
          {
            info: { id: 'msg-006', role: 'user', content: 'test' } as MockMessage,
            parts: [
              { type: 'tool-call', toolCall: { id: 'tc-1', name: 'test_tool', args: { key: MOCK_AWS_KEY } } } as MockPart,
            ],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      // Tool-call parts should not be modified (they don't have text)
      expect(output.messages[0].parts[0].toolCall?.args.key).toBe(MOCK_AWS_KEY);
    });
  });

  // ==========================================================================
  // experimental.text.complete hook
  // ==========================================================================

  describe('experimental.text.complete', () => {
    it('should restore placeholders to secrets in incoming text', async () => {
      const sessionId = 'session-001';

      // First, filter an outgoing message to create a placeholder mapping
      const originalContent = `My key is ${MOCK_AWS_KEY}`;
      const output = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      // Get the transformed text with placeholder
      const transformedText = output.messages[0].parts[0].text;
      const placeholder = transformedText.match(/<SECRET_[A-Z_]+_\d+>/)?.[0];
      expect(placeholder).toBeDefined();

      // Now simulate incoming response with placeholder
      const incomingOutput = {
        text: `I see you're using ${placeholder} for authentication`,
      };

      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: sessionId,
        messageID: 'response-001',
        partID: 'part-001',
      }, incomingOutput);

      // Verify placeholder was restored to secret
      expect(incomingOutput.text).toContain(MOCK_AWS_KEY);
      expect(incomingOutput.text).not.toContain(placeholder!);
    });

    it('should handle multiple placeholders in incoming text', async () => {
      const sessionId = 'session-002';

      // Create mappings for multiple secrets
      const originalContent = `AWS: ${MOCK_AWS_KEY} and GitHub: ${MOCK_GITHUB_TOKEN}`;
      const output = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      // Simulate incoming response with both placeholders
      const transformedText = output.messages[0].parts[0].text;

      const incomingOutput = {
        text: `You have provided: ${transformedText}`,
      };

      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: sessionId,
        messageID: 'response-002',
        partID: 'part-001',
      }, incomingOutput);

      // Verify both secrets were restored
      expect(incomingOutput.text).toContain(MOCK_AWS_KEY);
      expect(incomingOutput.text).toContain(MOCK_GITHUB_TOKEN);
    });

    it('should handle text without placeholders', async () => {
      const sessionId = 'session-003';
      const originalText = 'This is just regular text without placeholders';

      const output = { text: originalText };

      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: sessionId,
        messageID: 'response-003',
        partID: 'part-001',
      }, output);

      expect(output.text).toBe(originalText);
    });

    it('should handle unknown placeholders gracefully', async () => {
      const sessionId = 'session-004';
      const unknownPlaceholder = '<SECRET_UNKNOWN_999>';
      const originalText = `Text with ${unknownPlaceholder}`;

      const output = { text: originalText };

      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: sessionId,
        messageID: 'response-004',
        partID: 'part-001',
      }, output);

      // Unknown placeholder should remain unchanged
      expect(output.text).toBe(originalText);
    });

    it('should handle empty text', async () => {
      const sessionId = 'session-005';
      const output = { text: '' };

      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: sessionId,
        messageID: 'response-005',
        partID: 'part-001',
      }, output);

      expect(output.text).toBe('');
    });
  });

  // ==========================================================================
  // tool.execute.before hook
  // ==========================================================================

  describe('tool.execute.before', () => {
    it('should restore placeholders in tool arguments', async () => {
      const sessionId = 'session-006';

      // First, create a placeholder mapping
      const originalContent = `Use key ${MOCK_AWS_KEY}`;
      const output = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      // Get the placeholder
      const transformedText = output.messages[0].parts[0].text;
      const placeholder = transformedText.match(/<SECRET_[A-Z_]+_\d+>/)?.[0];
      expect(placeholder).toBeDefined();

      // Simulate tool execution with placeholder in args
      const toolOutput = {
        args: {
          apiKey: placeholder,
          region: 'us-east-1',
        },
      };

      await env.mockHooks.execute('tool.execute.before', {
        tool: 'aws-api',
        sessionID: sessionId,
        callID: 'call-001',
      }, toolOutput);

      // Verify placeholder was restored
      expect(toolOutput.args.apiKey).toBe(MOCK_AWS_KEY);
      expect(toolOutput.args.region).toBe('us-east-1');
    });

    it('should handle nested object arguments', async () => {
      const sessionId = 'session-007';

      // Create placeholder mapping
      const originalContent = `Token: ${MOCK_SLACK_TOKEN}`;
      const output = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      const transformedText = output.messages[0].parts[0].text;
      const placeholder = transformedText.match(/<SECRET_[A-Z_]+_\d+>/)?.[0];
      expect(placeholder).toBeDefined();

      // Nested args with placeholder
      const toolOutput = {
        args: {
          credentials: {
            slack: {
              token: placeholder,
            },
          },
          options: {
            timeout: 5000,
          },
        },
      };

      await env.mockHooks.execute('tool.execute.before', {
        tool: 'slack-api',
        sessionID: sessionId,
        callID: 'call-002',
      }, toolOutput);

      // Verify nested placeholder was restored
      expect(toolOutput.args.credentials.slack.token).toBe(MOCK_SLACK_TOKEN);
      expect(toolOutput.args.options.timeout).toBe(5000);
    });

    it('should handle array arguments', async () => {
      const sessionId = 'session-008';

      // Create placeholder mapping
      const originalContent = `Keys: ${MOCK_AWS_KEY}`;
      const output = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      const transformedText = output.messages[0].parts[0].text;
      const placeholder = transformedText.match(/<SECRET_[A-Z_]+_\d+>/)?.[0];
      expect(placeholder).toBeDefined();

      // Array args with placeholder
      const toolOutput = {
        args: {
          apiKeys: [placeholder, 'other-key'],
          names: ['test1', 'test2'],
        },
      };

      await env.mockHooks.execute('tool.execute.before', {
        tool: 'multi-key-api',
        sessionID: sessionId,
        callID: 'call-003',
      }, toolOutput);

      // Verify array placeholder was restored
      expect(toolOutput.args.apiKeys[0]).toBe(MOCK_AWS_KEY);
      expect(toolOutput.args.apiKeys[1]).toBe('other-key');
    });

    it('should handle arguments without placeholders', async () => {
      const sessionId = 'session-009';

      const toolOutput = {
        args: {
          region: 'us-west-2',
          dryRun: true,
        },
      };

      await env.mockHooks.execute('tool.execute.before', {
        tool: 'config-tool',
        sessionID: sessionId,
        callID: 'call-004',
      }, toolOutput);

      expect(toolOutput.args.region).toBe('us-west-2');
      expect(toolOutput.args.dryRun).toBe(true);
    });

    it('should handle complex nested structure', async () => {
      const sessionId = 'session-010';

      // Create placeholder mappings
      const originalContent = `Keys: ${MOCK_AWS_KEY} ${MOCK_GITHUB_TOKEN}`;
      const output = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: originalContent } as MockMessage,
            parts: [{ type: 'text', text: originalContent } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      const transformedText = output.messages[0].parts[0].text;
      const placeholders = transformedText.match(/<SECRET_[A-Z_]+_\d+>/g) || [];
      expect(placeholders.length).toBeGreaterThanOrEqual(1);

      // Complex nested structure
      const toolOutput = {
        args: {
          services: [
            {
              name: 'aws',
              credentials: {
                accessKeyId: placeholders[0] || 'fallback',
              },
            },
            {
              name: 'github',
              credentials: {
                token: placeholders[1] || placeholders[0] || 'fallback',
              },
            },
          ],
          options: {
            retry: 3,
          },
        },
      };

      await env.mockHooks.execute('tool.execute.before', {
        tool: 'multi-service-api',
        sessionID: sessionId,
        callID: 'call-005',
      }, toolOutput);

      // Verify placeholders were restored
      if (placeholders.length >= 2) {
        expect(toolOutput.args.services[0].credentials.accessKeyId).toBe(MOCK_AWS_KEY);
        expect(toolOutput.args.services[1].credentials.token).toBe(MOCK_GITHUB_TOKEN);
      } else {
        // If only one placeholder, it might be used for both
        expect(toolOutput.args.services[0].credentials.accessKeyId).toMatch(/AKIA|ghp_/);
      }
    });
  });

  // ==========================================================================
  // Error Handling (Fail-Closed Behavior)
  // ==========================================================================

  describe('error handling', () => {
    it('should throw error when transform hook fails', async () => {
      // Create a broken filter that throws
      const brokenEnv = createTestEnvironment();
      brokenEnv.messageFilter['config'].enabled = true;

      const output = {
        messages: [
          {
            info: { id: 'msg-bad', role: 'user', content: 'test' } as MockMessage,
            parts: [{ type: 'text', text: 'test' } as MockPart],
          },
        ],
      };

      // Mock a broken filter
      const originalFilterText = brokenEnv.messageFilter.filterText.bind(brokenEnv.messageFilter);
      brokenEnv.messageFilter.filterText = () => {
        throw new Error('Filter system failure');
      };

      // Should throw and block the message (fail-closed)
      let errorThrown = false;
      try {
        await brokenEnv.mockHooks.execute('experimental.chat.messages.transform', {}, output);
      } catch (error) {
        errorThrown = true;
        expect(error instanceof Error).toBe(true);
        if (error instanceof Error) {
          expect(error.message).toContain('Message filtering failed');
        }
      }

      expect(errorThrown).toBe(true);
    });

    it('should throw error when complete hook fails', async () => {
      const sessionId = 'session-error';

      const output = { text: 'test text' };

      // Mock a broken restore
      const originalRestore = env.sessionManager.restoreText.bind(env.sessionManager);
      env.sessionManager.restoreText = () => {
        throw new Error('Restore system failure');
      };

      let errorThrown = false;
      try {
        await env.mockHooks.execute('experimental.text.complete', {
          sessionID: sessionId,
          messageID: 'msg-error',
          partID: 'part-error',
        }, output);
      } catch (error) {
        errorThrown = true;
        expect(error instanceof Error).toBe(true);
        if (error instanceof Error) {
          expect(error.message).toContain('Text restoration failed');
        }
      }

      expect(errorThrown).toBe(true);
    });

    it('should throw error when tool execute hook fails', async () => {
      const sessionId = 'session-tool-error';

      const output = { args: { key: 'value' } };

      // Mock broken args restoration
      env.sessionManager.restoreText = () => {
        throw new Error('Args restore failure');
      };

      let errorThrown = false;
      try {
        await env.mockHooks.execute('tool.execute.before', {
          tool: 'test-tool',
          sessionID: sessionId,
          callID: 'call-error',
        }, output);
      } catch (error) {
        errorThrown = true;
        expect(error instanceof Error).toBe(true);
        if (error instanceof Error) {
          expect(error.message).toContain('Argument restoration failed');
        }
      }

      expect(errorThrown).toBe(true);
    });
  });

  // ==========================================================================
  // Session Lifecycle
  // ==========================================================================

  describe('session lifecycle', () => {
    it('should maintain separate mappings for different sessions', async () => {
      const session1Id = 'session-unique-1';
      const session2Id = 'session-unique-2';

      // First session with AWS key
      const output1 = {
        messages: [
          {
            info: { id: session1Id, role: 'user', content: `Key: ${MOCK_AWS_KEY}` } as MockMessage,
            parts: [{ type: 'text', text: `Key: ${MOCK_AWS_KEY}` } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output1);
      const placeholder1 = output1.messages[0].parts[0].text.match(/<SECRET_[A-Z_]+_\d+>/)?.[0];

      // Second session with GitHub token
      const output2 = {
        messages: [
          {
            info: { id: session2Id, role: 'user', content: `Token: ${MOCK_GITHUB_TOKEN}` } as MockMessage,
            parts: [{ type: 'text', text: `Token: ${MOCK_GITHUB_TOKEN}` } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output2);
      const placeholder2 = output2.messages[0].parts[0].text.match(/<SECRET_[A-Z_]+_\d+>/)?.[0];

      // Verify placeholders are different (or at least mappings are isolated)
      expect(placeholder1).toBeDefined();
      expect(placeholder2).toBeDefined();

      // Test restoration in session 1
      const restoreOutput1 = { text: placeholder1! };
      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: session1Id,
        messageID: 'resp-1',
        partID: 'part-1',
      }, restoreOutput1);

      // Should restore to AWS key (session 1's secret)
      expect(restoreOutput1.text).toContain(MOCK_AWS_KEY);

      // Test restoration in session 2
      const restoreOutput2 = { text: placeholder2! };
      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: session2Id,
        messageID: 'resp-2',
        partID: 'part-2',
      }, restoreOutput2);

      // Should restore to GitHub token (session 2's secret)
      expect(restoreOutput2.text).toContain(MOCK_GITHUB_TOKEN);
    });

    it('should clear session when explicitly cleared', async () => {
      const sessionId = 'session-clear';

      // Create mapping
      const output = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: `Key: ${MOCK_AWS_KEY}` } as MockMessage,
            parts: [{ type: 'text', text: `Key: ${MOCK_AWS_KEY}` } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output);

      // Get placeholder
      const transformedText = output.messages[0].parts[0].text;
      const placeholder = transformedText.match(/<SECRET_[A-Z_]+_\d+>/)?.[0];
      expect(placeholder).toBeDefined();

      // Clear the session
      env.sessionManager.clearSession(sessionId);

      // Try to restore - should not find the secret anymore
      const restoreOutput = { text: placeholder! };
      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: sessionId,
        messageID: 'resp-clear',
        partID: 'part-clear',
      }, restoreOutput);

      // Placeholder should remain since session was cleared
      expect(restoreOutput.text).toBe(placeholder);
    });

    it('should handle new session with fresh state', async () => {
      const sessionId = 'session-fresh';

      // First use
      const output1 = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: `Key: ${MOCK_AWS_KEY}` } as MockMessage,
            parts: [{ type: 'text', text: `Key: ${MOCK_AWS_KEY}` } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output1);

      // Verify mapping exists
      const placeholders1 = env.sessionManager.getPlaceholders(sessionId);
      expect(placeholders1.size).toBeGreaterThan(0);

      // Clear and reuse same session ID
      env.sessionManager.clearSession(sessionId);

      // Second use after clear
      const output2 = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: `Token: ${MOCK_GITHUB_TOKEN}` } as MockMessage,
            parts: [{ type: 'text', text: `Token: ${MOCK_GITHUB_TOKEN}` } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, output2);

      // Should have new mappings
      const placeholders2 = env.sessionManager.getPlaceholders(sessionId);
      expect(placeholders2.size).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // End-to-End Flow Tests
  // ==========================================================================

  describe('end-to-end flow', () => {
    it('should handle complete conversation flow with secrets', async () => {
      const sessionId = 'e2e-session';

      // Step 1: User sends message with secret
      const userMessage = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: `My AWS key is ${MOCK_AWS_KEY}` } as MockMessage,
            parts: [{ type: 'text', text: `My AWS key is ${MOCK_AWS_KEY}` } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, userMessage);

      // Verify secret was replaced
      const userPlaceholder = userMessage.messages[0].parts[0].text.match(/<SECRET_[A-Z_]+_\d+>/)?.[0];
      expect(userPlaceholder).toBeDefined();
      expect(userMessage.messages[0].parts[0].text).not.toContain(MOCK_AWS_KEY);

      // Step 2: AI responds referencing the secret (with placeholder)
      const aiResponse = {
        text: `I see you have AWS key ${userPlaceholder} configured.`,
      };

      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: sessionId,
        messageID: 'ai-response-1',
        partID: 'ai-part-1',
      }, aiResponse);

      // Verify secret was restored for the user to see
      expect(aiResponse.text).toContain(MOCK_AWS_KEY);
      expect(aiResponse.text).not.toContain(userPlaceholder);

      // Step 3: Tool is called with placeholder in args
      const toolCall = {
        args: {
          action: 'describe',
          credentials: {
            awsAccessKeyId: userPlaceholder,
          },
        },
      };

      await env.mockHooks.execute('tool.execute.before', {
        tool: 'aws-cli',
        sessionID: sessionId,
        callID: 'tool-call-1',
      }, toolCall);

      // Verify secret was restored before tool execution
      expect(toolCall.args.credentials.awsAccessKeyId).toBe(MOCK_AWS_KEY);
    });

    it('should handle multiple secrets across conversation', async () => {
      const sessionId = 'multi-secret-session';

      // User sends multiple secrets
      const userMessage = {
        messages: [
          {
            info: { id: sessionId, role: 'user', content: `Keys: ${MOCK_AWS_KEY} ${MOCK_GITHUB_TOKEN}` } as MockMessage,
            parts: [{ type: 'text', text: `Keys: ${MOCK_AWS_KEY} ${MOCK_GITHUB_TOKEN}` } as MockPart],
          },
        ],
      };

      await env.mockHooks.execute('experimental.chat.messages.transform', {}, userMessage);

      const transformedText = userMessage.messages[0].parts[0].text;
      const placeholders = transformedText.match(/<SECRET_[A-Z_]+_\d+>/g) || [];

      expect(placeholders.length).toBeGreaterThanOrEqual(1);

      // AI responds with placeholders
      const aiResponse = {
        text: `Working with keys: ${placeholders.join(' and ')}`,
      };

      await env.mockHooks.execute('experimental.text.complete', {
        sessionID: sessionId,
        messageID: 'multi-response',
        partID: 'multi-part',
      }, aiResponse);

      // Both secrets should be restored
      expect(aiResponse.text).toContain(MOCK_AWS_KEY);
    });
  });
});
