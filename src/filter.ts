import type { DetectedSecret, FilteredMessage, DetectionMethod } from './types.js';
import { SecretDetector } from './detector.js';
import { CryptoUtils } from './crypto.js';
import { SessionManager } from './session.js';
import { AuditLogger, getAuditLogger } from './audit.js';

export class MessageFilter {
  private detector: SecretDetector;
  private crypto: CryptoUtils;
  private auditLogger: AuditLogger;

  constructor(detector: SecretDetector, crypto: CryptoUtils) {
    this.detector = detector;
    this.crypto = crypto;
    this.auditLogger = getAuditLogger();
  }

  filterOutgoing(text: string, session: SessionManager): FilteredMessage {
    if (session.isDisabled() || !text) {
      return {
        text,
        replacedCount: 0,
        placeholders: [],
        detectedSecrets: [],
      };
    }

    const detectedSecrets = this.detector.detect(text);
    if (detectedSecrets.length === 0) {
      return {
        text,
        replacedCount: 0,
        placeholders: [],
        detectedSecrets: [],
      };
    }

    const sortedSecrets = this.sortSecretsByPriority(detectedSecrets);
    const usedRanges: Array<{ start: number; end: number }> = [];
    const replacements = new Map<number, { end: number; placeholder: string; secret: DetectedSecret }>();
    const placeholders: string[] = [];
    const processedSecrets: DetectedSecret[] = [];

    for (const secret of sortedSecrets) {
      const { start, end } = secret.position;

      if (this.isOverlapping(start, end, usedRanges)) {
        continue;
      }

      let placeholder = session.getPlaceholder(secret.value);
      if (!placeholder) {
        const normalizedCategory = SessionManager.normalizeCategory(secret.category);
        placeholder = this.crypto.generatePlaceholder(secret.value, normalizedCategory);
        session.storeMapping(secret.value, placeholder);
      }

      usedRanges.push({ start, end });
      replacements.set(start, { end, placeholder, secret });
      placeholders.push(placeholder);
      processedSecrets.push({
        ...secret,
        placeholder,
      }      );

      const confidenceValue = secret.confidence === 'high' ? 0.9 : secret.confidence === 'medium' ? 0.6 : 0.3;
      this.auditLogger.logFiltered(
        secret.category,
        placeholder,
        confidenceValue,
        'regex' as DetectionMethod,
        {
          pattern: secret.pattern.name,
          sessionId: session.getSecretCount().toString(),
        }
      );
    }

    const filteredText = this.applyReplacements(text, replacements);

    return {
      text: filteredText,
      replacedCount: placeholders.length,
      placeholders,
      detectedSecrets: processedSecrets,
    };
  }

  filterIncoming(text: string, session: SessionManager): string {
    if (session.isDisabled() || !text) {
      return text;
    }

    const allPlaceholders = session.getAllPlaceholders();
    if (allPlaceholders.length === 0) {
      return text;
    }

    let result = text;
    const sortedPlaceholders = allPlaceholders.sort((a, b) => b.length - a.length);

    for (const placeholder of sortedPlaceholders) {
      const secret = session.getSecret(placeholder);
      if (secret) {
        result = result.split(placeholder).join(secret);
        this.auditLogger.logRestored('restored', placeholder, { sessionId: session.getSecretCount().toString() });
      }
    }

    return result;
  }

  private sortSecretsByPriority(secrets: DetectedSecret[]): DetectedSecret[] {
    return [...secrets].sort((a, b) => {
      const lengthA = a.position.end - a.position.start;
      const lengthB = b.position.end - b.position.start;

      if (lengthB !== lengthA) {
        return lengthB - lengthA;
      }

      const confidenceOrder = { high: 0, medium: 1, low: 2 };
      return confidenceOrder[a.confidence] - confidenceOrder[b.confidence];
    });
  }

  private isOverlapping(start: number, end: number, usedRanges: Array<{ start: number; end: number }>): boolean {
    for (const range of usedRanges) {
      if (start < range.end && end > range.start) {
        return true;
      }
    }
    return false;
  }

  private applyReplacements(
    text: string,
    replacements: Map<number, { end: number; placeholder: string; secret: DetectedSecret }>
  ): string {
    const starts = Array.from(replacements.keys()).sort((a, b) => a - b);

    let result = '';
    let lastEnd = 0;

    for (const start of starts) {
      const { end, placeholder } = replacements.get(start)!;
      result += text.slice(lastEnd, start);
      result += placeholder;
      lastEnd = end;
    }

    result += text.slice(lastEnd);

    return result;
  }
}
