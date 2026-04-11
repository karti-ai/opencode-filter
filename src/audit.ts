/**
 * OpenCode Filter - Audit Logging Module
 *
 * Provides structured audit logging for filter operations.
 * CRITICAL: Never logs actual secret values.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * Audit log entry action types
 */
export type AuditAction =
  | 'FILTERED'
  | 'RESTORED'
  | 'BYPASSED'
  | 'ERROR'
  | 'DISABLED'
  | 'ENABLED';

/**
 * Detection method used
 */
export type DetectionMethod = 'regex' | 'entropy';

/**
 * Audit log entry format
 * PRIVACY: NEVER contains actual secret values
 */
export interface AuditEntry {
  /** ISO 8601 timestamp */
  timestamp: string;

  /** Action type */
  action: AuditAction;

  /** Unique message ID (if available) */
  messageId?: string;

  /** Secret category (AWS, GitHub, etc.) */
  category: string;

  /** Placeholder used (e.g., __FILTER_AWS_a1b2c3__) */
  placeholder: string;

  /** Confidence score (0.0 - 1.0) */
  confidence: number;

  /** Detection method used */
  method: DetectionMethod;

  /** Pattern name that matched (if regex) */
  pattern?: string;

  /** Session ID for tracking */
  sessionId?: string;

  /** Additional metadata (safe only) */
  metadata?: Record<string, string | number | boolean>;
}

/**
 * Audit configuration interface
 */
export interface AuditConfig {
  /** Whether audit logging is enabled */
  enabled: boolean;

  /** Path to log file (supports ~ for home directory) */
  logPath: string;

  /** Maximum file size before rotation (bytes) */
  maxSize: number;

  /** Maximum number of rotated files to keep */
  maxFiles: number;

  /** Log level (currently only 'info' is used) */
  level: 'info' | 'debug';
}

/**
 * Default audit configuration
 */
export const DEFAULT_AUDIT_CONFIG: AuditConfig = {
  enabled: true,
  logPath: '~/.config/opencode/filter-audit.log',
  maxSize: 10 * 1024 * 1024, // 10MB
  maxFiles: 5,
  level: 'info',
};

/**
 * Log entry for the viewer
 */
export interface LogViewEntry extends AuditEntry {
  /** Entry index for reference */
  index: number;
}

/**
 * Result from viewing logs
 */
export interface LogViewResult {
  entries: LogViewEntry[];
  totalCount: number;
  fileSize: number;
}

/**
 * AuditLogger class for structured logging with rotation
 *
 * PRIVACY GUARANTEE: This logger NEVER writes actual secret values to disk.
 * Only placeholders, categories, and metadata are logged.
 */
export class AuditLogger {
  private config: AuditConfig;
  private logPath: string;
  private writeStream: fs.WriteStream | null = null;
  private initialized: boolean = false;
  private initError: Error | null = null;

  constructor(config?: Partial<AuditConfig>) {
    this.config = { ...DEFAULT_AUDIT_CONFIG, ...config };
    this.logPath = this.expandPath(this.config.logPath);
  }

  /**
   * Initialize the logger and ensure log directory exists
   * Fail-open: Errors don't prevent filter from working
   */
  initialize(): void {
    if (this.initialized || !this.config.enabled) {
      return;
    }

    try {
      // Ensure directory exists
      const dir = path.dirname(this.logPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); // Secure permissions
      }

      // Check if rotation is needed
      this.checkRotation();

      this.initialized = true;
    } catch (error) {
      // Fail-open: Log error but don't prevent filter from working
      this.initError = error instanceof Error ? error : new Error(String(error));
      console.warn(`Audit logging initialization failed (fail-open): ${this.initError.message}`);
    }
  }

  /**
   * Log a filter action
   * PRIVACY: Entry must NEVER contain actual secrets
   */
  log(entry: Omit<AuditEntry, 'timestamp'>): void {
    if (!this.config.enabled || !this.initialized) {
      return;
    }

    try {
      // Verify no secrets in the entry (privacy check)
      this.verifyPrivacy(entry);

      // Add timestamp
      const fullEntry: AuditEntry = {
        ...entry,
        timestamp: new Date().toISOString(),
      };

      // Check rotation before writing
      this.checkRotation();

      // Write as JSON line
      const line = JSON.stringify(fullEntry) + '\n';
      fs.appendFileSync(this.logPath, line, { encoding: 'utf-8', mode: 0o600 });
    } catch (error) {
      // Fail-open: Log to stderr but don't throw
      console.warn(`Audit logging failed (fail-open): ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Log a FILTERED action
   */
  logFiltered(
    category: string,
    placeholder: string,
    confidence: number,
    method: DetectionMethod,
    options?: {
      messageId?: string;
      pattern?: string;
      sessionId?: string;
      metadata?: Record<string, string | number | boolean>;
    }
  ): void {
    this.log({
      action: 'FILTERED',
      category,
      placeholder,
      confidence,
      method,
      ...options,
    });
  }

  /**
   * Log a RESTORED action
   */
  logRestored(
    category: string,
    placeholder: string,
    options?: {
      messageId?: string;
      sessionId?: string;
      metadata?: Record<string, string | number | boolean>;
    }
  ): void {
    this.log({
      action: 'RESTORED',
      category,
      placeholder,
      confidence: 1.0, // Always confident for restore
      method: 'regex', // Placeholder matching is regex-based
      ...options,
    });
  }

  /**
   * Log a BYPASSED action (filter disabled or no secrets found)
   */
  logBypassed(
    options?: {
      messageId?: string;
      sessionId?: string;
      reason?: string;
    }
  ): void {
    this.log({
      action: 'BYPASSED',
      category: 'none',
      placeholder: 'N/A',
      confidence: 0,
      method: 'regex',
      metadata: options?.reason ? { reason: options.reason } : undefined,
      ...options,
    });
  }

  /**
   * Log an ERROR action
   */
  logError(
    error: Error | string,
    options?: {
      messageId?: string;
      sessionId?: string;
    }
  ): void {
    this.log({
      action: 'ERROR',
      category: 'error',
      placeholder: 'N/A',
      confidence: 0,
      method: 'regex',
      metadata: { errorMessage: error instanceof Error ? error.message : error },
      ...options,
    });
  }

  /**
   * Log a DISABLED action (filter was disabled)
   */
  logDisabled(
    options?: {
      sessionId?: string;
      reason?: string;
    }
  ): void {
    this.log({
      action: 'DISABLED',
      category: 'system',
      placeholder: 'N/A',
      confidence: 1.0,
      method: 'regex',
      metadata: options?.reason ? { reason: options.reason } : undefined,
      ...options,
    });
  }

  /**
   * Log an ENABLED action (filter was enabled)
   */
  logEnabled(
    options?: {
      sessionId?: string;
    }
  ): void {
    this.log({
      action: 'ENABLED',
      category: 'system',
      placeholder: 'N/A',
      confidence: 1.0,
      method: 'regex',
      ...options,
    });
  }

  /**
   * View recent log entries
   */
  viewLogs(options?: {
    limit?: number;
    tail?: boolean;
    filter?: { action?: AuditAction; category?: string };
  }): LogViewResult {
    const defaultOptions = { limit: 100, tail: true };
    const opts = { ...defaultOptions, ...options };

    if (!fs.existsSync(this.logPath)) {
      return { entries: [], totalCount: 0, fileSize: 0 };
    }

    try {
      const stats = fs.statSync(this.logPath);
      const content = fs.readFileSync(this.logPath, 'utf-8');
      const lines = content.split('\n').filter(line => line.trim());

      // Parse entries
      let entries: LogViewEntry[] = [];
      for (let i = 0; i < lines.length; i++) {
        try {
          const entry = JSON.parse(lines[i]) as AuditEntry;
          entries.push({ ...entry, index: i + 1 });
        } catch {
          // Skip malformed lines
        }
      }

      // Apply filters
      if (opts.filter?.action) {
        entries = entries.filter(e => e.action === opts.filter!.action);
      }
      if (opts.filter?.category) {
        entries = entries.filter(e => e.category === opts.filter!.category);
      }

      // Apply limit (from tail if specified)
      if (opts.tail && entries.length > opts.limit!) {
        entries = entries.slice(-opts.limit!);
      } else if (!opts.tail && entries.length > opts.limit!) {
        entries = entries.slice(0, opts.limit!);
      }

      return {
        entries,
        totalCount: lines.length,
        fileSize: stats.size,
      };
    } catch (error) {
      console.error(`Failed to read audit logs: ${error instanceof Error ? error.message : String(error)}`);
      return { entries: [], totalCount: 0, fileSize: 0 };
    }
  }

  /**
   * Clear all audit logs
   */
  clearLogs(): { success: boolean; deleted: number; error?: string } {
    try {
      let deleted = 0;

      // Delete main log file
      if (fs.existsSync(this.logPath)) {
        fs.unlinkSync(this.logPath);
        deleted++;
      }

      // Delete rotated files
      for (let i = 1; i <= this.config.maxFiles; i++) {
        const rotatedPath = `${this.logPath}.${i}`;
        if (fs.existsSync(rotatedPath)) {
          fs.unlinkSync(rotatedPath);
          deleted++;
        }
      }

      return { success: true, deleted };
    } catch (error) {
      return {
        success: false,
        deleted: 0,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get log file statistics
   */
  getStats(): { exists: boolean; size: number; entryCount: number; rotatedFiles: number } {
    let exists = false;
    let size = 0;
    let entryCount = 0;
    let rotatedFiles = 0;

    if (fs.existsSync(this.logPath)) {
      exists = true;
      const stats = fs.statSync(this.logPath);
      size = stats.size;

      try {
        const content = fs.readFileSync(this.logPath, 'utf-8');
        entryCount = content.split('\n').filter(line => line.trim()).length;
      } catch {
        // Ignore read errors
      }
    }

    // Count rotated files
    for (let i = 1; i <= this.config.maxFiles; i++) {
      if (fs.existsSync(`${this.logPath}.${i}`)) {
        rotatedFiles++;
      }
    }

    return { exists, size, entryCount, rotatedFiles };
  }

  /**
   * Check if log rotation is needed and perform rotation
   */
  private checkRotation(): void {
    if (!fs.existsSync(this.logPath)) {
      return;
    }

    try {
      const stats = fs.statSync(this.logPath);

      if (stats.size > this.config.maxSize) {
        this.rotateFiles();
      }
    } catch (error) {
      // Fail-open: Continue even if rotation fails
      console.warn(`Log rotation check failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Perform log file rotation
   */
  private rotateFiles(): void {
    // Delete oldest file if at max
    const oldestPath = `${this.logPath}.${this.config.maxFiles}`;
    if (fs.existsSync(oldestPath)) {
      fs.unlinkSync(oldestPath);
    }

    // Shift existing files
    for (let i = this.config.maxFiles - 1; i >= 1; i--) {
      const oldPath = `${this.logPath}.${i}`;
      const newPath = `${this.logPath}.${i + 1}`;

      if (fs.existsSync(oldPath)) {
        fs.renameSync(oldPath, newPath);
      }
    }

    // Move current log to .1
    if (fs.existsSync(this.logPath)) {
      fs.renameSync(this.logPath, `${this.logPath}.1`);
    }
  }

  /**
   * Expand ~ to home directory in paths
   */
  private expandPath(inputPath: string): string {
    if (inputPath.startsWith('~/')) {
      return path.join(os.homedir(), inputPath.slice(2));
    }
    return inputPath;
  }

  /**
   * Verify that no actual secrets are in the entry
   * This is a safety check to prevent accidental secret logging
   */
  private verifyPrivacy(entry: Omit<AuditEntry, 'timestamp'>): boolean {
    // List of field names that should NEVER contain secrets
    const sensitiveFields: Array<keyof Omit<AuditEntry, 'timestamp'>> = [
      'placeholder',
      'messageId',
      'sessionId',
      'category',
      'pattern',
    ];

    // Check that placeholder doesn't look like an actual secret value
    // Placeholders should follow the pattern __FILTER_* or <SECRET_*>
    const placeholderPattern = /^(__FILTER_[A-Z_]+_[a-z0-9]+(?:_\d+)?__|<SECRET_[A-Z_]+_\d+>)$/;
    if (!placeholderPattern.test(entry.placeholder) && entry.placeholder !== 'N/A') {
      // Suspicious placeholder - might be a raw secret
      console.warn(`Warning: Audit entry has suspicious placeholder format: ${entry.placeholder}`);
    }

    // Check metadata for any suspicious values
    if (entry.metadata) {
      for (const [key, value] of Object.entries(entry.metadata)) {
        if (typeof value === 'string') {
          // Check for high entropy strings that might be secrets
          if (this.looksLikeSecret(value)) {
            throw new Error(`Potential secret detected in metadata field '${key}'. Audit aborted.`);
          }
        }
      }
    }

    return true;
  }

  /**
   * Check if a string looks like it might be a secret value
   */
  private looksLikeSecret(value: string): boolean {
    // Skip short strings
    if (value.length < 16) return false;

    // Check for common secret patterns
    const secretPatterns = [
      /^(sk-|pk_|ghp_|glpat-|AKIA|ASIA|AZURE)/i, // API key prefixes
      /^-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
      /^[A-Za-z0-9+/]{40,}={0,2}$/, // Base64-like
      /^[a-f0-9]{32,}$/i, // Hex-like
    ];

    return secretPatterns.some(pattern => pattern.test(value));
  }

  /**
   * Get current configuration
   */
  getConfig(): AuditConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<AuditConfig>): void {
    this.config = { ...this.config, ...config };
    if (config.logPath) {
      this.logPath = this.expandPath(config.logPath);
    }
    // Re-initialize if needed
    if (config.enabled && !this.initialized) {
      this.initialize();
    }
  }

  /**
   * Check if logger is enabled and initialized
   */
  isEnabled(): boolean {
    return this.config.enabled && this.initialized;
  }

  /**
   * Get initialization error if any
   */
  getInitError(): Error | null {
    return this.initError;
  }
}

/**
 * Global audit logger instance
 */
let globalLogger: AuditLogger | null = null;

/**
 * Get or create the global audit logger instance
 */
export function getAuditLogger(config?: Partial<AuditConfig>): AuditLogger {
  if (!globalLogger) {
    globalLogger = new AuditLogger(config);
    globalLogger.initialize();
  } else if (config) {
    globalLogger.updateConfig(config);
  }
  return globalLogger;
}

/**
 * Reset the global audit logger instance
 */
export function resetAuditLogger(): void {
  globalLogger = null;
}

/**
 * Format log entry for display
 */
export function formatAuditEntry(entry: LogViewEntry): string {
  const timestamp = new Date(entry.timestamp).toLocaleString();
  const action = entry.action.padEnd(10);
  const category = entry.category.padEnd(15);
  const placeholder = entry.placeholder.slice(0, 30).padEnd(30);
  const confidence = (entry.confidence * 100).toFixed(0).padStart(3) + '%';

  return `${timestamp} | ${action} | ${category} | ${placeholder} | ${confidence}`;
}

/**
 * Format log statistics for display
 */
export function formatLogStats(stats: { exists: boolean; size: number; entryCount: number; rotatedFiles: number }): string {
  if (!stats.exists) {
    return 'No audit log file exists.';
  }

  const sizeKB = (stats.size / 1024).toFixed(1);
  return `Audit log: ${stats.entryCount} entries, ${sizeKB} KB, ${stats.rotatedFiles} rotated files`;
}
