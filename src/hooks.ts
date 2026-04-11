/**
 * OpenCode Plugin Hooks Implementation
 *
 * Integrates with OpenCode plugin API to filter messages before sending to LLM
 * and restore placeholders after receiving responses.
 */

import type { Hooks, Plugin, PluginInput, PluginOptions } from '@opencode-ai/plugin';
import type { Message, Part } from '@opencode-ai/sdk';
import { RegexEngine } from './patterns/regex-engine.js';
import { loadConfig } from './config.js';
import type { FilterConfig, SecretPattern, DetectedSecret, DetectionMethod } from './types.js';
import { getBuiltinPatterns } from './patterns/builtin.js';
import { AuditLogger, getAuditLogger } from './audit.js';
import { getFeedbackManager } from './visual/feedback-manager.js';

/**
 * Session manager for tracking secrets and placeholders across multiple operations
 */
export class SessionManager {
  private sessions: Map<string, Map<string, string>> = new Map();
  private placeholderCounter: Map<string, number> = new Map();

  /**
   * Get or create a session map for the given session ID
   */
  getSession(sessionId: string): Map<string, string> {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, new Map());
      this.placeholderCounter.set(sessionId, 0);
    }
    return this.sessions.get(sessionId)!;
  }

  /**
   * Generate a unique placeholder for a secret
   */
  generatePlaceholder(sessionId: string, category: string): string {
    const counter = this.placeholderCounter.get(sessionId) || 0;
    this.placeholderCounter.set(sessionId, counter + 1);
    return `<SECRET_${category.toUpperCase()}_${counter + 1}>`;
  }

  /**
   * Store a secret with its placeholder in the session
   */
  storeSecret(sessionId: string, secret: string, placeholder: string): void {
    const session = this.getSession(sessionId);
    session.set(placeholder, secret);
  }

  /**
   * Get the original secret for a placeholder
   */
  getSecret(sessionId: string, placeholder: string): string | undefined {
    const session = this.getSession(sessionId);
    return session.get(placeholder);
  }

  /**
   * Get all placeholders for a session
   */
  getPlaceholders(sessionId: string): Map<string, string> {
    return this.getSession(sessionId);
  }

  /**
   * Clear a session
   */
  clearSession(sessionId: string): void {
    this.sessions.delete(sessionId);
    this.placeholderCounter.delete(sessionId);
  }

  /**
   * Restore all placeholders in text to their original secrets
   */
  restoreText(sessionId: string, text: string): string {
    const session = this.getSession(sessionId);
    let restored = text;

    // Sort placeholders by length (longest first) to avoid partial replacements
    const entries = Array.from(session.entries()).sort(
      (a, b) => b[0].length - a[0].length
    );

    for (const [placeholder, secret] of entries) {
      // Escape special regex characters in placeholder
      const escaped = placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escaped, 'g');
      restored = restored.replace(regex, secret);
    }

    return restored;
  }

  /**
   * Check if text contains any placeholders from this session
   */
  hasPlaceholders(sessionId: string, text: string): boolean {
    const session = this.getSession(sessionId);
    for (const [placeholder] of session) {
      if (text.includes(placeholder)) {
        return true;
      }
    }
    return false;
  }
}

/**
 * Message filter for filtering secrets in messages
 */
export class MessageFilter {
  private regexEngine: RegexEngine;
  private sessionManager: SessionManager;
  private config: FilterConfig;
  private auditLogger: AuditLogger;

  constructor(
    regexEngine: RegexEngine,
    sessionManager: SessionManager,
    config: FilterConfig
  ) {
    this.regexEngine = regexEngine;
    this.sessionManager = sessionManager;
    this.config = config;
    this.auditLogger = getAuditLogger(config.audit);
  }

  /**
   * Filter text by replacing secrets with placeholders
   * @param sessionId - Session identifier for tracking
   * @param text - Text to filter
   * @returns Filtered text with placeholders
   */
  filterText(sessionId: string, text: string): string {
    if (!this.config.enabled) {
      return text;
    }

    try {
      // Detect secrets in the text
      const detected = this.regexEngine.detect(text);

      if (detected.length === 0) {
        return text;
      }

      // Sort by position (descending) so we can replace from end to start
      // without affecting indices of earlier matches
      const sorted = [...detected].sort((a, b) => b.position.start - a.position.start);

      let filtered = text;
      const session = this.sessionManager.getSession(sessionId);

      const feedbackManager = getFeedbackManager();
      const categories: string[] = [];

      for (const secret of sorted) {
        let placeholder: string | undefined;
        for (const [ph, val] of session) {
          if (val === secret.value) {
            placeholder = ph;
            break;
          }
        }

        if (!placeholder) {
          placeholder = this.sessionManager.generatePlaceholder(
            sessionId,
            secret.category
          );
          this.sessionManager.storeSecret(sessionId, secret.value, placeholder);
        }

        filtered =
          filtered.substring(0, secret.position.start) +
          placeholder +
          filtered.substring(secret.position.end);

        categories.push(secret.category);
        const confidenceValue = secret.confidence === 'high' ? 0.9 : secret.confidence === 'medium' ? 0.6 : 0.3;
        const auditEntry = {
          action: 'FILTERED' as const,
          category: secret.category,
          placeholder,
          confidence: confidenceValue,
          method: 'regex' as DetectionMethod,
          pattern: secret.pattern.name,
          sessionId,
        };
        this.auditLogger.logFiltered(
          secret.category,
          placeholder,
          confidenceValue,
          'regex' as DetectionMethod,
          {
            pattern: secret.pattern.name,
            sessionId,
          }
        );
        feedbackManager.addAuditEntry({
          ...auditEntry,
          timestamp: new Date().toISOString(),
        });
      }

      if (sorted.length > 0) {
        feedbackManager.recordSecretsDetected({
          count: sorted.length,
          categories: [...new Set(categories)],
          sessionId,
          timestamp: new Date().toISOString(),
        });
      }

      return filtered;
    } catch (error) {
      this.auditLogger.logError(error instanceof Error ? error : String(error), { sessionId });
      throw new Error(
        `Secret filtering failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Restore placeholders in text to their original secrets
   * @param sessionId - Session identifier for tracking
   * @param text - Text with placeholders
   * @returns Text with secrets restored
   */
  restoreText(sessionId: string, text: string): string {
    const session = this.sessionManager.getSession(sessionId);
    const entries = Array.from(session.entries()).sort((a, b) => b[0].length - a[0].length);

    let restored = text;
    for (const [placeholder, secret] of entries) {
      const escaped = placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escaped, 'g');
      if (regex.test(restored)) {
        restored = restored.replace(regex, secret);
        this.auditLogger.logRestored('restored', placeholder, { sessionId });
      }
    }

    return restored;
  }

  /**
   * Filter a Part by processing any text content
   */
  filterPart(sessionId: string, part: Part): Part {
    if (part.type === 'text' && 'text' in part && typeof part.text === 'string') {
      const filtered = this.filterText(sessionId, part.text);
      if (filtered !== part.text) {
        return { ...part, text: filtered };
      }
    }

    return part;
  }

  /**
   * Restore placeholders in a Part
   */
  restorePart(sessionId: string, part: Part): Part {
    // Handle text parts
    if (part.type === 'text' && 'text' in part && typeof part.text === 'string') {
      const restored = this.restoreText(sessionId, part.text);
      if (restored !== part.text) {
        return { ...part, text: restored };
      }
    }

    return part;
  }

  /**
   * Get filter statistics
   */
  getStats(): { totalSessions: number; totalSecrets: number } {
    let totalSecrets = 0;
    for (const session of this.sessionManager['sessions'].values()) {
      totalSecrets += session.size;
    }

    return {
      totalSessions: this.sessionManager['sessions'].size,
      totalSecrets,
    };
  }
}

/**
 * Create the plugin hooks implementation
 */
export function createHooks(
  messageFilter: MessageFilter,
  sessionManager: SessionManager
): Hooks {
  return {
    /**
     * Transform outgoing messages before sending to LLM
     * Replace secrets with placeholders
     */
    'experimental.chat.messages.transform': async (
      _input: {},
      output: {
        messages: {
          info: Message;
          parts: Part[];
        }[];
      }
    ) => {
      try {
        console.log('[FILTER DEBUG] Hook called');
        console.log('[FILTER DEBUG] Messages count:', output?.messages?.length);
        if (output?.messages?.[0]) {
          console.log('[FILTER DEBUG] Message info keys:', Object.keys(output.messages[0].info || {}));
          console.log('[FILTER DEBUG] Message info:', JSON.stringify(output.messages[0].info));
          console.log('[FILTER DEBUG] Parts[0] keys:', Object.keys(output.messages[0].parts?.[0] || {}));
          console.log('[FILTER DEBUG] Parts[0]:', JSON.stringify(output.messages[0].parts?.[0]));
        }
        for (const message of output.messages) {
          // Get sessionID from message info or parts (OpenCode uses 'id', not 'sessionID')
          const sessionID = (message.info as any)?.id ?? (message.parts?.[0] as any)?.sessionID;
          console.log('[FILTER DEBUG] Extracted sessionID:', sessionID);
          if (!sessionID) {
            console.log('[FILTER DEBUG] No sessionID found, returning early');
            return;
          }

          for (let i = 0; i < message.parts.length; i++) {
            const part = message.parts[i];
            const originalText = part.type === 'text' && 'text' in part ? (part as any).text : null;
            message.parts[i] = messageFilter.filterPart(sessionID, part);
            const newPart = message.parts[i];
            const newText = newPart.type === 'text' && 'text' in newPart ? (newPart as any).text : null;
            if (originalText && newText && originalText !== newText) {
              console.log('[FILTER DEBUG] Part', i, 'filtered:', originalText.substring(0, 50), '->', newText.substring(0, 50));
            }
          }

          // Also filter message content if it has text
          if ('content' in message.info && typeof message.info.content === 'string') {
            const originalContent = message.info.content;
            (message.info as Message & { content: string }).content =
              messageFilter.filterText(sessionID, message.info.content);
            if (originalContent !== (message.info as Message & { content: string }).content) {
              console.log('[FILTER DEBUG] Message info.content filtered');
            }
          }
        }
      } catch (error) {
        // Fail-closed: throw error to block message if filter fails
        throw new Error(
          `Message filtering failed in experimental.chat.messages.transform: ${
            error instanceof Error ? error.message : 'Unknown error'
          }`
        );
      }
    },

    /**
     * Handle chat messages (TUI flow)
     * Filter secrets when messages are sent via chat interface
     */
    'chat.message': async (
      input: { sessionID: string },
      output: { parts: Part[] }
    ) => {
      try {
        console.log('[FILTER DEBUG] chat.message hook called');
        console.log('[FILTER DEBUG] SessionID:', input.sessionID);
        console.log('[FILTER DEBUG] Parts count:', output?.parts?.length);
        
        if (!output?.parts) return;
        
        for (let i = 0; i < output.parts.length; i++) {
          const part = output.parts[i];
          const originalText = part.type === 'text' && 'text' in part ? (part as any).text : null;
          output.parts[i] = messageFilter.filterPart(input.sessionID, part);
          const newPart = output.parts[i];
          const newText = newPart.type === 'text' && 'text' in newPart ? (newPart as any).text : null;
          if (originalText && newText && originalText !== newText) {
            console.log('[FILTER DEBUG] chat.message Part', i, 'filtered:', originalText.substring(0, 50), '->', newText.substring(0, 50));
          }
        }
      } catch (error) {
        throw new Error(
          `Message filtering failed in chat.message: ${
            error instanceof Error ? error.message : 'Unknown error'
          }`
        );
      }
    },

    /**
     * Transform incoming text responses from LLM
     * Restore placeholders to original secrets
     */
    'experimental.text.complete': async (
      input: {
        sessionID: string;
        messageID: string;
        partID: string;
      },
      output: { text: string }
    ) => {
      try {
        output.text = messageFilter.restoreText(input.sessionID, output.text);
      } catch (error) {
        // Fail-closed: throw error if restore fails
        throw new Error(
          `Text restoration failed in experimental.text.complete: ${
            error instanceof Error ? error.message : 'Unknown error'
          }`
        );
      }
    },

    /**
     * Intercept and modify tool execution arguments
     * Restore placeholders before tool executes
     */
    'tool.execute.before': async (
      input: {
        tool: string;
        sessionID: string;
        callID: string;
      },
      output: { args: any }
    ) => {
      try {
        // Recursively restore placeholders in args
        output.args = restoreInObject(output.args, sessionManager, input.sessionID);
      } catch (error) {
        // Fail-closed: throw error if restore fails
        throw new Error(
          `Argument restoration failed in tool.execute.before for tool "${input.tool}": ${
            error instanceof Error ? error.message : 'Unknown error'
          }`
        );
      }
    },
  };
}

/**
 * Recursively restore placeholders in an object
 */
function restoreInObject(
  obj: unknown,
  sessionManager: SessionManager,
  sessionId: string
): unknown {
  if (typeof obj === 'string') {
    return sessionManager.restoreText(sessionId, obj);
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => restoreInObject(item, sessionManager, sessionId));
  }

  if (typeof obj === 'object' && obj !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = restoreInObject(value, sessionManager, sessionId);
    }
    return result;
  }

  return obj;
}

/**
 * Main plugin factory function
 * Creates and configures the OpenCode plugin
 */
export const secretFilterPlugin: Plugin = async (
  _input: PluginInput,
  options?: PluginOptions
) => {
  // Load configuration
  const { config: loadedConfig } = loadConfig();

  // Merge with any options passed to the plugin
  const config: FilterConfig = {
    ...loadedConfig,
    enabled: options?.enabled !== undefined ? (options.enabled as boolean) : loadedConfig.enabled,
    mode: (options?.mode as FilterConfig['mode']) || loadedConfig.mode,
  };

  // Add custom patterns if provided
  const customPatterns = (options?.customPatterns as SecretPattern[]) || [];
  const allPatterns = [...config.patterns, ...customPatterns];

  // If no patterns loaded, use built-in patterns
  const finalPatterns = allPatterns.length > 0 ? allPatterns : getBuiltinPatterns();

  // Create engines and managers
  const regexEngine = new RegexEngine({
    customPatterns: finalPatterns,
  });

  const sessionManager = new SessionManager();
  const messageFilter = new MessageFilter(regexEngine, sessionManager, config);

  // Create and return the hooks
  return createHooks(messageFilter, sessionManager);
};

export default secretFilterPlugin;
