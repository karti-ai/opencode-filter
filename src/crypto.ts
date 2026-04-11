import { createHmac, randomBytes, createHash } from 'crypto';

export class CryptoUtils {
  private sessionKey: Buffer;

  constructor() {
    this.sessionKey = CryptoUtils.generateSessionKey();
  }

  static generateSessionKey(): Buffer {
    return randomBytes(32);
  }

  generatePlaceholder(secret: string, category: string): string {
    const hmac = createHmac('sha256', this.sessionKey);
    hmac.update(secret);
    const hash = hmac.digest('hex').slice(0, 12);
    return `__FILTER_${category.toUpperCase()}_${hash}__`;
  }

  hashSecret(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  getSessionKey(): Buffer {
    return this.sessionKey;
  }
}
