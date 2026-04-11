import type { SecretCategory } from './types.js';

const CATEGORY_NORMALIZATION: Record<SecretCategory, string> = {
  api_key: 'API_KEY',
  password: 'PASSWORD',
  token: 'TOKEN',
  private_key: 'PRIVATE_KEY',
  credential: 'CREDENTIAL',
  certificate: 'CERTIFICATE',
  connection_string: 'CONNECTION_STRING',
  environment_variable: 'ENV_VAR',
  personal_info: 'PERSONAL_INFO',
  other: 'OTHER',
};

export interface SessionState {
  placeholderToSecret: Map<string, string>;
  secretToPlaceholder: Map<string, string>;
  placeholders: Set<string>;
  disabled: boolean;
}

export class SessionManager {
  private state: SessionState;

  constructor() {
    this.state = {
      placeholderToSecret: new Map(),
      secretToPlaceholder: new Map(),
      placeholders: new Set(),
      disabled: false,
    };
  }

  storeMapping(secret: string, placeholder: string): void {
    this.state.secretToPlaceholder.set(secret, placeholder);
    this.state.placeholderToSecret.set(placeholder, secret);
    this.state.placeholders.add(placeholder);
  }

  getPlaceholder(secret: string): string | undefined {
    return this.state.secretToPlaceholder.get(secret);
  }

  getSecret(placeholder: string): string | undefined {
    return this.state.placeholderToSecret.get(placeholder);
  }

  hasPlaceholder(placeholder: string): boolean {
    return this.state.placeholders.has(placeholder);
  }

  hasSecret(secret: string): boolean {
    return this.state.secretToPlaceholder.has(secret);
  }

  getAllPlaceholders(): string[] {
    return Array.from(this.state.placeholders);
  }

  getSecretCount(): number {
    return this.state.secretToPlaceholder.size;
  }

  disable(): void {
    this.state.disabled = true;
  }

  enable(): void {
    this.state.disabled = false;
  }

  isDisabled(): boolean {
    return this.state.disabled;
  }

  clear(): void {
    this.state.placeholderToSecret.clear();
    this.state.secretToPlaceholder.clear();
    this.state.placeholders.clear();
    this.state.disabled = false;
  }

  static normalizeCategory(category: SecretCategory): string {
    return CATEGORY_NORMALIZATION[category] || 'OTHER';
  }
}
