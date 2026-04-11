/**
 * OpenCode Filter - Type Definitions
 *
 * Comprehensive TypeScript type definitions for the OpenCode Secret Filter plugin.
 * All interfaces are designed with strict typing and readonly properties where applicable.
 */

// ============================================================================
// SECRET PATTERN DEFINITIONS
// ============================================================================

/**
 * Severity level for detected secrets
 */
export type SecretSeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Category of secret pattern for grouping and filtering
 */
export type SecretCategory =
  | 'api_key'
  | 'password'
  | 'token'
  | 'private_key'
  | 'credential'
  | 'certificate'
  | 'connection_string'
  | 'environment_variable'
  | 'personal_info'
  | 'other';

/**
 * Defines a pattern for detecting a specific type of secret
 */
export interface SecretPattern {
  /** Unique identifier for the pattern */
  readonly name: string;

  /** Regular expression to match the secret pattern */
  readonly regex: RegExp;

  /** Category for grouping similar patterns */
  readonly category: SecretCategory;

  /** Human-readable description of what this pattern detects */
  readonly description: string;

  /** Severity level indicating the risk of exposing this secret */
  readonly severity: SecretSeverity;

  /** Example of a string that would match this pattern (for testing/docs) */
  readonly example: string;
}

// ============================================================================
// FILTER CONFIGURATION
// ============================================================================

/**
 * Operating mode for the filter
 */
export type FilterMode = 'detect' | 'redact' | 'sanitize';

/**
 * Configuration options for the secret filter
 */
export interface FilterConfig {
  /** Array of secret patterns to detect */
  readonly patterns: readonly SecretPattern[];

  /** Minimum entropy threshold for considering a string a secret (0-1) */
  readonly entropyThreshold: number;

  /** Minimum length of a string to be considered a potential secret */
  readonly minSecretLength: number;

  /** Maximum number of unique secrets to track per session */
  readonly maxSecretsPerSession: number;

  /** Whether the filter is enabled and active */
  readonly enabled: boolean;

  /** Operating mode: detect (log only), redact (replace), or sanitize (remove) */
  readonly mode: FilterMode;

  /** Audit logging configuration */
  readonly audit?: AuditConfig;
}

// ============================================================================
// AUDIT LOGGING
// ============================================================================

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
 * Detection method used for secrets
 */
export type DetectionMethod = 'regex' | 'entropy';

/**
 * Audit log entry format
 * PRIVACY: NEVER contains actual secret values
 */
export interface AuditEntry {
  /** ISO 8601 timestamp */
  readonly timestamp: string;

  /** Action type */
  readonly action: AuditAction;

  /** Unique message ID (if available) */
  readonly messageId?: string;

  /** Secret category (AWS, GitHub, etc.) */
  readonly category: string;

  /** Placeholder used (e.g., __FILTER_AWS_a1b2c3__) */
  readonly placeholder: string;

  /** Confidence score (0.0 - 1.0) */
  readonly confidence: number;

  /** Detection method used */
  readonly method: DetectionMethod;

  /** Pattern name that matched (if regex) */
  readonly pattern?: string;

  /** Session ID for tracking */
  readonly sessionId?: string;

  /** Additional metadata (safe only) */
  readonly metadata?: Readonly<Record<string, string | number | boolean>>;
}

/**
 * Audit logging configuration
 */
export interface AuditConfig {
  /** Whether audit logging is enabled */
  readonly enabled: boolean;

  /** Path to log file (supports ~ for home directory) */
  readonly logPath: string;

  /** Maximum file size before rotation in bytes */
  readonly maxSize: number;

  /** Maximum number of rotated files to keep */
  readonly maxFiles: number;

  /** Log level */
  readonly level: 'info' | 'debug';
}

/**
 * Default filter configuration values
 */
export const DEFAULT_FILTER_CONFIG: Readonly<FilterConfig> = {
  patterns: [],
  entropyThreshold: 3.5,
  minSecretLength: 8,
  maxSecretsPerSession: 100,
  enabled: true,
  mode: 'redact',
} as const;

// ============================================================================
// DETECTED SECRET REPRESENTATION
// ============================================================================

/**
 * Position information for a detected secret within text
 */
export interface SecretPosition {
  /** Starting character index (inclusive) */
  readonly start: number;

  /** Ending character index (exclusive) */
  readonly end: number;

  /** Line number where the secret was found (1-indexed) */
  readonly line: number;

  /** Column number where the secret starts (0-indexed) */
  readonly column: number;
}

/**
 * Confidence score for a detection
 */
export type ConfidenceLevel = 'low' | 'medium' | 'high';

/**
 * Represents a detected secret within text content
 */
export interface DetectedSecret {
  /** The actual secret value that was detected */
  readonly value: string;

  /** Reference to the pattern that detected this secret */
  readonly pattern: SecretPattern;

  /** Category of the detected secret */
  readonly category: SecretCategory;

  /** Position information within the source text */
  readonly position: SecretPosition;

  /** Placeholder string used to replace this secret */
  readonly placeholder: string;

  /** Confidence level of the detection */
  readonly confidence: ConfidenceLevel;
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

/**
 * Mapping of secret values to their placeholder replacements for a session.
 * This ensures consistent replacement of the same secret across multiple messages.
 */
export type SessionMap = ReadonlyMap<string, string>;

/**
 * Session state for tracking secrets across multiple filter operations
 */
export interface FilterSession {
  /** Unique session identifier */
  readonly sessionId: string;

  /** Map of secrets to their placeholders */
  readonly secretMap: SessionMap;

  /** Number of unique secrets detected in this session */
  readonly secretCount: number;

  /** Timestamp when the session was created */
  readonly createdAt: Date;

  /** Timestamp of the last filter operation */
  readonly lastActivity: Date;
}

// ============================================================================
// FILTER RESULTS
// ============================================================================

/**
 * Result of filtering a message for secrets
 */
export interface FilteredMessage {
  /** The filtered text with secrets replaced by placeholders */
  readonly text: string;

  /** Number of secret occurrences that were replaced */
  readonly replacedCount: number;

  /** Array of placeholder strings used in the filtered text */
  readonly placeholders: readonly string[];

  /** Array of detected secrets (for logging/analysis) */
  readonly detectedSecrets: readonly DetectedSecret[];
}

/**
 * Statistics about filter operations
 */
export interface FilterStats {
  /** Total number of messages processed */
  readonly totalMessages: number;

  /** Total number of secrets detected */
  readonly totalSecretsDetected: number;

  /** Total number of secrets replaced */
  readonly totalSecretsReplaced: number;

  /** Breakdown by category */
  readonly byCategory: Readonly<Record<SecretCategory, number>>;

  /** Breakdown by severity */
  readonly bySeverity: Readonly<Record<SecretSeverity, number>>;
}

// ============================================================================
// OPENCODE HOOK INTERFACES
// ============================================================================

/**
 * Context object passed to hook handlers
 */
export interface HookContext {
  /** Session identifier for tracking across operations */
  readonly sessionId: string;

  /** Timestamp of the hook invocation */
  readonly timestamp: Date;

  /** Additional metadata from the OpenCode SDK */
  readonly metadata: Readonly<Record<string, unknown>>;
}

/**
 * Message object structure for OpenCode hooks
 */
export interface HookMessage {
  /** Message identifier */
  readonly id: string;

  /** Message role (user, assistant, system, tool) */
  readonly role: 'user' | 'assistant' | 'system' | 'tool';

  /** Message content text */
  readonly content: string;

  /** Optional message metadata */
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Request object for the beforeSend hook
 */
export interface BeforeSendRequest {
  /** Array of messages to be sent */
  readonly messages: readonly HookMessage[];

  /** Request metadata */
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Response for the beforeSend hook
 */
export interface BeforeSendResponse {
  /** Filtered messages */
  readonly messages: readonly HookMessage[];

  /** Whether the request should be blocked */
  readonly blocked: boolean;

  /** Optional reason for blocking */
  readonly blockReason?: string;
}

/**
 * Request object for the afterReceive hook
 */
export interface AfterReceiveRequest {
  /** Received message content */
  readonly message: HookMessage;

  /** Response metadata */
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Response for the afterReceive hook
 */
export interface AfterReceiveResponse {
  /** Filtered message */
  readonly message: HookMessage;

  /** Whether the response should be blocked/modified */
  readonly modified: boolean;
}

/**
 * BeforeSend hook interface - called before sending messages to AI
 * Allows filtering/redacting outgoing messages
 */
export interface BeforeSendHook {
  /**
   * Hook name for identification
   */
  readonly name: string;

  /**
   * Process messages before they are sent
   * @param request - The request containing messages to filter
   * @param context - Hook context with session info
   * @returns Response with filtered messages
   */
  process(
    request: BeforeSendRequest,
    context: HookContext
  ): Promise<BeforeSendResponse> | BeforeSendResponse;
}

/**
 * AfterReceive hook interface - called after receiving AI responses
 * Allows filtering/redacting incoming messages
 */
export interface AfterReceiveHook {
  /**
   * Hook name for identification
   */
  readonly name: string;

  /**
   * Process messages after they are received
   * @param request - The request containing the received message
   * @param context - Hook context with session info
   * @returns Response with filtered message
   */
  process(
    request: AfterReceiveRequest,
    context: HookContext
  ): Promise<AfterReceiveResponse> | AfterReceiveResponse;
}

/**
 * Combined hook interface for the secret filter plugin
 */
export interface SecretFilterHooks {
  /** Hook name for identification */
  readonly name: string;

  /**
   * Initialize the hook with configuration
   * @param config - Filter configuration
   */
  initialize(config: FilterConfig): void;

  /**
   * Get current filter statistics
   */
  getStats(): FilterStats;

  /**
   * Reset the filter session state
   */
  reset(): void;

  /**
   * Process messages before they are sent (implements BeforeSendHook)
   * @param request - The request containing messages to filter
   * @param context - Hook context with session info
   * @returns Response with filtered messages
   */
  processBeforeSend(
    request: BeforeSendRequest,
    context: HookContext
  ): Promise<BeforeSendResponse> | BeforeSendResponse;

  /**
   * Process messages after they are received (implements AfterReceiveHook)
   * @param request - The request containing the received message
   * @param context - Hook context with session info
   * @returns Response with filtered message
   */
  processAfterReceive(
    request: AfterReceiveRequest,
    context: HookContext
  ): Promise<AfterReceiveResponse> | AfterReceiveResponse;
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

/**
 * Configuration for entropy calculation
 */
export interface EntropyConfig {
  /** Character set size for calculation */
  readonly charset: 'alphanumeric' | 'hex' | 'base64' | 'binary' | 'full';

  /** Minimum entropy threshold */
  readonly threshold: number;
}

/**
 * Result of entropy calculation
 */
export interface EntropyResult {
  /** The calculated entropy value */
  readonly value: number;

  /** Whether the entropy exceeds the threshold */
  readonly passes: boolean;

  /** Character set used for calculation */
  readonly charset: string;
}

/**
 * Options for generating placeholder strings
 */
export interface PlaceholderOptions {
  /** Prefix for placeholder strings */
  readonly prefix: string;

  /** Whether to include a hash of the secret */
  readonly includeHash: boolean;

  /** Length of the random suffix */
  readonly suffixLength: number;
}

/**
 * Error types for filter operations
 */
export type FilterErrorType =
  | 'INVALID_CONFIG'
  | 'PATTERN_ERROR'
  | 'SESSION_FULL'
  | 'ENTROPY_CALCULATION_ERROR'
  | 'PLACEHOLDER_GENERATION_ERROR';

/**
 * Filter-specific error class
 */
export interface FilterError {
  /** Error type classification */
  readonly type: FilterErrorType;

  /** Human-readable error message */
  readonly message: string;

  /** Original error if available */
  readonly cause?: Error;

  /** Additional context data */
  readonly context?: Readonly<Record<string, unknown>>;
}

// ============================================================================
// PLUGIN API
// ============================================================================

/**
 * Plugin configuration options
 */
export interface PluginOptions {
  /** Filter configuration */
  readonly filterConfig: FilterConfig;

  /** Custom patterns to add to defaults */
  readonly customPatterns?: readonly SecretPattern[];

  /** Callback for filter events */
  readonly onDetection?: (secret: DetectedSecret) => void;

  /** Callback for blocked messages */
  readonly onBlocked?: (reason: string, count: number) => void;
}

/**
 * Main plugin interface exposed to consumers
 */
export interface SecretFilterPlugin {
  /**
   * Filter text for secrets
   * @param text - Text to filter
   * @returns Filtered message result
   */
  filter(text: string): FilteredMessage;

  /**
   * Filter text asynchronously
   * @param text - Text to filter
   * @returns Promise of filtered message result
   */
  filterAsync(text: string): Promise<FilteredMessage>;

  /**
   * Check if text contains secrets without replacing them
   * @param text - Text to check
   * @returns Array of detected secrets
   */
  detect(text: string): readonly DetectedSecret[];

  /**
   * Add a custom pattern at runtime
   * @param pattern - Pattern to add
   */
  addPattern(pattern: SecretPattern): void;

  /**
   * Remove a pattern by name
   * @param name - Pattern name to remove
   */
  removePattern(name: string): void;

  /**
   * Get current filter statistics
   */
  getStats(): FilterStats;

  /**
   * Reset the plugin state
   */
  reset(): void;

  /**
   * Create a new filter session
   * @returns Session identifier
   */
  createSession(): string;

  /**
   * Get the OpenCode hooks interface
   */
  getHooks(): SecretFilterHooks;
}

// ============================================================================
// EXPORT TYPE ALIASES (for cleaner imports)
// ============================================================================

/** @deprecated Use SecretCategory instead */
export type PatternCategory = SecretCategory;

/** @deprecated Use FilteredMessage instead */
export type FilterResult = FilteredMessage;
