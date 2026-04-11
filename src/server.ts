import type { Plugin } from '@opencode-ai/plugin';
import { loadConfig } from './config.js';
import { RegexEngine } from './patterns/regex-engine.js';
import { SessionManager } from './session.js';
import { MessageFilter } from './filter.js';
import { getBuiltinPatterns } from './patterns/builtin.js';
import type { FilterConfig, SecretPattern } from './types.js';
import { CryptoUtils } from './crypto.js';
import { SecretDetector, EntropyEngineStub } from './detector.js';

export const secretFilterPlugin: Plugin = async (_ctx, options) => {
  const { config: loadedConfig } = loadConfig();

  const config: FilterConfig = {
    ...loadedConfig,
    enabled: options?.enabled !== undefined ? (options.enabled as boolean) : loadedConfig.enabled,
    mode: (options?.mode as FilterConfig['mode']) || loadedConfig.mode,
  };

  const customPatterns = (options?.customPatterns as SecretPattern[]) || [];
  const allPatterns = [...config.patterns, ...customPatterns];
  const finalPatterns = allPatterns.length > 0 ? allPatterns : getBuiltinPatterns();

  const regexEngine = new RegexEngine({ customPatterns: finalPatterns });
  const entropyEngine = new EntropyEngineStub();
  const crypto = new CryptoUtils();
  const detector = new SecretDetector(regexEngine, entropyEngine);
  const sessionManager = new SessionManager();
  const messageFilter = new MessageFilter(detector, crypto);

  return {
    'experimental.chat.messages.transform': async (_input, output) => {
      if (!config.enabled || sessionManager.isDisabled()) return;
      
      for (const message of output.messages) {
        const textParts: Array<{ type: 'text'; text: string }> = message.parts.filter(
          (p: { type: string }) => p.type === 'text'
        ) as Array<{ type: 'text'; text: string }>;
        
        const textContent = textParts.map(p => p.text).join('');
        
        if (textContent) {
          const result = messageFilter.filterOutgoing(textContent, sessionManager);
          
          for (const part of textParts) {
            part.text = result.text;
          }
        }
      }
    },

    'experimental.chat.system.transform': async (_input, output) => {
      if (!config.enabled || sessionManager.isDisabled()) return;
      
      for (let i = 0; i < output.system.length; i++) {
        const result = messageFilter.filterOutgoing(output.system[i], sessionManager);
        output.system[i] = result.text;
      }
    },

    'tool.execute.before': async (input, output) => {
      if (!config.enabled || sessionManager.isDisabled()) return;
      
      if (output.args && typeof output.args === 'object') {
        const argsStr = JSON.stringify(output.args);
        const result = messageFilter.filterOutgoing(argsStr, sessionManager);
        
        if (result.replacedCount > 0) {
          console.log(`[opencode-filter] Filtered ${result.replacedCount} secrets from tool ${input.tool}`);
        }
      }
    },

    event: async ({ event }) => {
      if (event.type === 'session.created') {
        console.log(`[opencode-filter] Secret filter active for session (enabled: ${config.enabled})`);
      }
    },
  };
};

export default secretFilterPlugin;
