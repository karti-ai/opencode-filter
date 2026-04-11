/**
 * OpenCode Filter - TUI Plugin Entry Point
 *
 * Exports the TUI plugin for OpenCode terminal interface integration.
 */

import type { TuiPlugin } from '@opencode-ai/plugin/tui';
import type { AuditAction, SecretCategory } from './types.js';
import { getFeedbackManager, formatAuditEntryForDisplay } from './visual/feedback-manager.js';

export interface SecretsDetectedEvent {
  count: number;
  categories: string[];
  sessionId?: string;
  timestamp: string;
}

export interface FilterStatistics {
  totalSecretsFiltered: number;
  sessionSecretsFiltered: number;
  activeSessions: number;
  byCategory: Record<SecretCategory, number>;
  lastActivity: string | null;
  isEnabled: boolean;
  totalOperations: number;
}

export interface AuditEntry {
  timestamp: string;
  action: AuditAction;
  messageId?: string;
  category: string;
  placeholder: string;
  confidence: number;
  method: 'regex' | 'entropy';
  pattern?: string;
  sessionId?: string;
  metadata?: Record<string, string | number | boolean>;
}

type Signal<T> = [() => T, (value: T | ((prev: T) => T)) => void];

const tuiPlugin: TuiPlugin = async (api, _options, _meta) => {
  const feedbackManager = getFeedbackManager();

  const createSignal = <T>(initialValue: T): Signal<T> => {
    let value = initialValue;
    const listeners = new Set<() => void>();

    const getter = () => value;
    const setter = (newValue: T | ((prev: T) => T)) => {
      if (typeof newValue === 'function') {
        value = (newValue as (prev: T) => T)(value);
      } else {
        value = newValue;
      }
      listeners.forEach(listener => listener());
    };

    return [getter, setter];
  };

  const [filterEnabled, setFilterEnabled] = createSignal(true);
  const [secretsFiltered, setSecretsFiltered] = createSignal(0);
  const [lastFilterTime, setLastFilterTime] = createSignal<string | null>(null);
  const [auditEntries, setAuditEntries] = createSignal<AuditEntry[]>([]);

  const updateFromStats = (stats: FilterStatistics) => {
    setFilterEnabled(stats.isEnabled);
    setSecretsFiltered(stats.totalSecretsFiltered);
    setLastFilterTime(stats.lastActivity);
  };

  updateFromStats(feedbackManager.getStats() as FilterStatistics);

  const unsubscribeStats = feedbackManager.onSecretsDetected((event: SecretsDetectedEvent) => {
    setSecretsFiltered((prev: number) => prev + event.count);
    setLastFilterTime(event.timestamp);
    showFilterToast(event.count);
  });

  const unsubscribeAudit = feedbackManager.onAuditEntry((entry: AuditEntry) => {
    setAuditEntries((prev: AuditEntry[]) => {
      const updated = [entry, ...prev];
      return updated.slice(0, 50);
    });
  });

  const showFilterToast = (count: number) => {
    api.ui.toast({
      variant: 'success',
      title: 'Secrets Filtered',
      message: `${count} secret${count > 1 ? 's' : ''} protected`,
      duration: 3000,
    });
  };

  const slotId = api.slots.register({
    slot: 'sidebar_footer',
    render: () => {
      const enabled = filterEnabled();
      const count = secretsFiltered();
      return `${enabled ? '🔒' : '🔓'} ${enabled ? count + ' filtered' : 'Filter disabled'}`;
    },
  });

  const commands = [
    {
      title: 'Filter: Toggle Status',
      value: 'filter.toggle',
      description: 'Enable or disable secret filtering',
      category: 'Filter',
      slash: { name: 'filter', aliases: ['toggle-filter'] },
      onSelect: () => {
        const newState = !filterEnabled();
        setFilterEnabled(newState);
        feedbackManager.setFilterEnabled(newState, 'User toggled via command palette');
        api.ui.toast({
          variant: 'info',
          message: `Filter ${newState ? 'enabled' : 'disabled'}`,
        });
      },
    },
    {
      title: 'Filter: View Status',
      value: 'filter.status',
      description: 'Show filter statistics and status',
      category: 'Filter',
      onSelect: () => {
        api.route.navigate('filter-status');
      },
    },
    {
      title: 'Filter: View Audit Log',
      value: 'filter.audit',
      description: 'View recent filter activity',
      category: 'Filter',
      onSelect: () => {
        api.route.navigate('filter-audit');
      },
    },
    {
      title: 'Filter: Reset Session Stats',
      value: 'filter.reset',
      description: 'Reset statistics for current session',
      category: 'Filter',
      onSelect: () => {
        feedbackManager.resetSessionStats();
        setSecretsFiltered(0);
        api.ui.toast({
          variant: 'info',
          message: 'Session statistics reset',
        });
      },
    },
  ];

  const disposeCommand = api.command.register(() => commands);

  const routes = [
    {
      name: 'filter-status',
      render: () => {
        const stats = feedbackManager.getStats() as FilterStatistics;
        const message = `Status: ${stats.isEnabled ? '✅ Enabled' : '❌ Disabled'}
Secrets Filtered: ${stats.totalSecretsFiltered}
Session Filtered: ${stats.sessionSecretsFiltered}
Total Operations: ${stats.totalOperations}
Last Activity: ${stats.lastActivity ? new Date(stats.lastActivity).toLocaleString() : 'Never'}`;

        return api.ui.Dialog({
          onClose: () => api.route.navigate('home'),
          children: api.ui.DialogAlert({
            title: '🔒 Filter Status',
            message,
          }),
        });
      },
    },
    {
      name: 'filter-audit',
      render: () => {
        const entries = auditEntries().length > 0
          ? auditEntries()
          : feedbackManager.getAuditEntries({ limit: 20 });

        const message = entries.length === 0
          ? 'No audit entries yet...'
          : entries.slice(0, 20).map((entry: AuditEntry) => formatAuditEntryForDisplay(entry)).join('\n');

        return api.ui.Dialog({
          onClose: () => api.route.navigate('home'),
          children: api.ui.DialogAlert({
            title: '📋 Filter Audit Log',
            message,
          }),
        });
      },
    },
  ];

  const disposeRoute = api.route.register(routes);

  api.lifecycle.onDispose(() => {
    disposeCommand();
    disposeRoute();
    unsubscribeStats();
    unsubscribeAudit();
  });
};

// TUI plugins must export: { id?, tui }
export default {
  id: 'opencode-filter-tui',
  tui: tuiPlugin,
};
