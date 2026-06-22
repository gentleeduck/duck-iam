import { isCredentialExpired } from '../../core/credential-utils'
import type { AuthPasskeyTypes } from './types'

/**
 * Reference in-memory `AuthPasskeyTypes.IChallengeStore`. Suitable for
 * tests + single-process deploys; production wires a Redis-backed
 * implementation.
 */
export class AuthMemoryPasskeyChallengeStore implements AuthPasskeyTypes.IChallengeStore {
  private readonly _entries = new Map<string, { challenge: string; expiresAt: number }>()

  /**
   * Persist a challenge under `key` for `ttlMs`. Overwrites any prior
   * entry; only one challenge is live per key at a time.
   */
  async put(key: string, challenge: string, ttlMs: number): Promise<void> {
    this._entries.set(key, { challenge, expiresAt: Date.now() + ttlMs })
  }

  /**
   * Read + delete a challenge atomically. Returns null when missing,
   * expired, or already consumed.
   */
  async take(key: string): Promise<string | null> {
    const entry = this._entries.get(key)
    if (!entry) return null
    this._entries.delete(key)
    // Non-finite expiresAt would slip `NaN < now == false`; replay window.
    if (isCredentialExpired(entry)) return null
    return entry.challenge
  }
}
