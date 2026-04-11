/**
 * OpenCode Filter - Visual Feedback Manager
 *
 * Central coordination for visual feedback in the TUI.
 * Manages state, events, and statistics for the secret filter.
 *
 * PRIVACY: Never stores or displays actual secret values.
 */

import type { AuditEntry, AuditAction, SecretCategory } from '../types.js';

export type { AuditEntry };

/**
 * Statistics for the filter state panel
 */
export interface FilterStatistics {
  /** Total secrets filtered across all sessions */
  totalSecretsFiltered: number;

  /** Secrets filtered in current session */
  sessionSecretsFiltered: number;

  /** Number of active sessions with filtered secrets */
  activeSessions: number;

  /** Breakdown by category (never contains actual values) */
  byCategory: Record<SecretCategory, number>;

  /** Last filter activity timestamp */
  lastActivity: string | null;

  /** Whether filtering is currently enabled */
  isEnabled: boolean;

  /** Total operations (filter/restore) performed */
  totalOperations: number;
}

/**
 * Event data for secrets detected
 */
export interface SecretsDetectedEvent {
  /** Number of secrets detected */
  count: number;

  /** Categories of detected secrets */
  categories: string[];

  /** Session ID where detection occurred */
  sessionId?: string;

  /** Timestamp of detection */
  timestamp: string;
}

/**
 * Event data for filter state change
 */
export interface FilterStateChangeEvent {
  /** Whether filter is now enabled */
  enabled: boolean;

  /** Timestamp of change */
  timestamp: string;

  /** Reason for change (if applicable) */
  reason?: string;
}

/**
 * Callback function types for event subscriptions
 */
export type SecretsDetectedCallback = (event: SecretsDetectedEvent) => void;
export type StateChangeCallback = (event: FilterStateChangeEvent) => void;
export type AuditEntryCallback = (entry: AuditEntry) => void;

/**
 * Feedback manager for coordinating visual feedback
 * across the TUI plugin components
 */
export class FeedbackManager {
  private stats: FilterStatistics;
  private auditLog: AuditEntry[] = [];
  private maxAuditEntries: number = 100;

  // Event subscribers
  private secretsDetectedCallbacks: SecretsDetectedCallback[] = [];
  private stateChangeCallbacks: StateChangeCallback[] = [];
  private auditEntryCallbacks: AuditEntryCallback[] = [];

  constructor() {
    this.stats = {
      totalSecretsFiltered: 0,
      sessionSecretsFiltered: 0,
      activeSessions: 0,
      byCategory: {
        api_key: 0,
        password: 0,
        token: 0,
        private_key: 0,
        credential: 0,
        certificate: 0,
        connection_string: 0,
        environment_variable: 0,
        personal_info: 0,
        other: 0,
      },
      lastActivity: null,
      isEnabled: true,
      totalOperations: 0,
    };
  }

  /**
   * Record a secrets detection event
   */
  recordSecretsDetected(event: SecretsDetectedEvent): void {
    this.stats.totalSecretsFiltered += event.count;
    this.stats.sessionSecretsFiltered += event.count;
    this.stats.totalOperations++;
    this.stats.lastActivity = event.timestamp;

    for (const category of event.categories) {
      if (category in this.stats.byCategory) {
        this.stats.byCategory[category as SecretCategory]++;
      }
    }

    for (const callback of this.secretsDetectedCallbacks) {
      try {
        callback(event);
      } catch (error) {
        console.error('Error in secrets detected callback:', error);
      }
    }
  }

  /**
   * Record a filter state change
   */
  setFilterEnabled(enabled: boolean, reason?: string): void {
    const previousState = this.stats.isEnabled;
    this.stats.isEnabled = enabled;

    if (previousState !== enabled) {
      const event: FilterStateChangeEvent = {
        enabled,
        timestamp: new Date().toISOString(),
        reason,
      };

      for (const callback of this.stateChangeCallbacks) {
        try {
          callback(event);
        } catch (error) {
          console.error('Error in state change callback:', error);
        }
      }
    }
  }

  /**
   * Get current filter statistics
   */
  getStats(): FilterStatistics {
    return { ...this.stats };
  }

  /**
   * Add an audit entry to the log
   * PRIVACY: Only placeholders and metadata are stored, never actual secrets
   */
  addAuditEntry(entry: AuditEntry): void {
    this.auditLog.push(entry);

    if (this.auditLog.length > this.maxAuditEntries) {
      this.auditLog = this.auditLog.slice(-this.maxAuditEntries);
    }

    for (const callback of this.auditEntryCallbacks) {
      try {
        callback(entry);
      } catch (error) {
        console.error('Error in audit entry callback:', error);
      }
    }

    if (entry.action === 'FILTERED') {
      this.stats.totalOperations++;
      this.stats.lastActivity = entry.timestamp;
    }
  }

  /**
   * Get recent audit entries
   */
  getAuditEntries(options?: {
    limit?: number;
    action?: AuditAction;
    category?: string;
  }): AuditEntry[] {
    let entries = [...this.auditLog];

    if (options?.action) {
      entries = entries.filter(e => e.action === options.action);
    }

    if (options?.category) {
      entries = entries.filter(e => e.category === options.category);
    }

    const limit = options?.limit ?? 50;
    return entries.slice(-limit);
  }

  /**
   * Clear audit log
   */
  clearAuditLog(): void {
    this.auditLog = [];
  }

  /**
   * Reset session-specific statistics
   */
  resetSessionStats(): void {
    this.stats.sessionSecretsFiltered = 0;
  }

  /**
   * Subscribe to secrets detected events
   * @returns Unsubscribe function
   */
  onSecretsDetected(callback: SecretsDetectedCallback): () => void {
    this.secretsDetectedCallbacks.push(callback);
    return () => {
      const index = this.secretsDetectedCallbacks.indexOf(callback);
      if (index > -1) {
        this.secretsDetectedCallbacks.splice(index, 1);
      }
    };
  }

  /**
   * Subscribe to filter state change events
   * @returns Unsubscribe function
   */
  onStateChange(callback: StateChangeCallback): () => void {
    this.stateChangeCallbacks.push(callback);
    return () => {
      const index = this.stateChangeCallbacks.indexOf(callback);
      if (index > -1) {
        this.stateChangeCallbacks.splice(index, 1);
      }
    };
  }

  /**
   * Subscribe to audit entry events
   * @returns Unsubscribe function
   */
  onAuditEntry(callback: AuditEntryCallback): () => void {
    this.auditEntryCallbacks.push(callback);
    return () => {
      const index = this.auditEntryCallbacks.indexOf(callback);
      if (index > -1) {
        this.auditEntryCallbacks.splice(index, 1);
      }
    };
  }

  /**
   * Reset all statistics and audit log
   */
  resetAll(): void {
    this.stats = {
      totalSecretsFiltered: 0,
      sessionSecretsFiltered: 0,
      activeSessions: 0,
      byCategory: {
        api_key: 0,
        password: 0,
        token: 0,
        private_key: 0,
        credential: 0,
        certificate: 0,
        connection_string: 0,
        environment_variable: 0,
        personal_info: 0,
        other: 0,
      },
      lastActivity: null,
      isEnabled: true,
      totalOperations: 0,
    };
    this.auditLog = [];
  }
}

/**
 * Global feedback manager instance for sharing state across components
 */
let globalFeedbackManager: FeedbackManager | null = null;

/**
 * Get or create the global feedback manager instance
 */
export function getFeedbackManager(): FeedbackManager {
  if (!globalFeedbackManager) {
    globalFeedbackManager = new FeedbackManager();
  }
  return globalFeedbackManager;
}

/**
 * Reset the global feedback manager instance
 */
export function resetFeedbackManager(): void {
  globalFeedbackManager = null;
}

/**
 * Format statistics for display in the TUI
 */
export function formatStatsForDisplay(stats: FilterStatistics): string {
  const lines = [
    `Status: ${stats.isEnabled ? '✅ Enabled' : '❌ Disabled'}`,
    `Total Filtered: ${stats.totalSecretsFiltered}`,
    `This Session: ${stats.sessionSecretsFiltered}`,
    `Operations: ${stats.totalOperations}`,
  ];

  if (stats.lastActivity) {
    const time = new Date(stats.lastActivity).toLocaleTimeString();
    lines.push(`Last Activity: ${time}`);
  }

  return lines.join('\n');
}

/**
 * Format an audit entry for display (privacy-safe)
 */
export function formatAuditEntryForDisplay(entry: AuditEntry): string {
  const timestamp = new Date(entry.timestamp).toLocaleTimeString();
  const action = entry.action;
  const category = entry.category;
  const placeholder = entry.placeholder.slice(0, 25);

  return `[${timestamp}] ${action} | ${category} | ${placeholder}`;
}
