/**
 * Client-side Groq API key persistence.
 *
 * If the server has no GROQ_API_KEY configured, users can supply their own key
 * in the UI; it is persisted to localStorage and sent per-request as
 * `groqApiKey` in the JSON body. It is never stored server-side.
 */

const STORAGE_KEY = 'reposhield.groq_api_key';

export function getStoredGroqKey(): string {
  try {
    return window.localStorage.getItem(STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

export function setStoredGroqKey(key: string): void {
  try {
    if (key && key.trim()) {
      window.localStorage.setItem(STORAGE_KEY, key.trim());
    } else {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // localStorage unavailable (private mode / SSR) — key stays in memory only.
  }
}

export function clearStoredGroqKey(): void {
  setStoredGroqKey('');
}

export function maskGroqKey(key: string): string {
  if (!key) return '';
  if (key.length <= 8) return '•'.repeat(key.length);
  return `${key.slice(0, 4)}${'•'.repeat(Math.max(4, key.length - 8))}${key.slice(-4)}`;
}

/** Read-only probe used by the header button to badge the key state. */
export function hasStoredGroqKey(): boolean {
  return getStoredGroqKey().length > 0;
}
