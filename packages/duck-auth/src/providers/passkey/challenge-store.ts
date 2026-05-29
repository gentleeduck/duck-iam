/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { PasskeyChallengeStore } from './types'

/**
 * Reference in-memory `PasskeyChallengeStore`. Suitable for tests +
 * single-process deploys; production must wire a Redis-backed
 * implementation that survives pod restarts.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class MemoryPasskeyChallengeStore implements PasskeyChallengeStore {
  private readonly _entries = new Map<string, { challenge: string; expiresAt: number }>()

  /**
   * Persist a challenge under `key` for `ttlMs`. Overwrites any prior
   * entry — only one challenge is live per key at a time.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async put(key: string, challenge: string, ttlMs: number): Promise<void> {
    this._entries.set(key, { challenge, expiresAt: Date.now() + ttlMs })
  }

  /**
   * Read + delete a challenge atomically. Returns null when missing,
   * expired, or already consumed. Used by the passkey verify step.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async take(key: string): Promise<string | null> {
    const entry = this._entries.get(key)
    if (!entry) return null
    this._entries.delete(key)
    if (entry.expiresAt < Date.now()) return null
    return entry.challenge
  }
}
