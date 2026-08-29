import { isCredentialExpired } from '~/core/credentials/credentials'
import type { Passkey } from '../passkey.types'

/**
 * Reference in-memory `AuthPasskeyTypes.IChallengeStore`. Suitable for
 * tests + single-process deploys; production wires a Redis-backed
 * implementation.
 */
export class MemoryPasskeyChallengeStore implements Passkey.ChallengeStore {
  private readonly _entries = new Map<string, { challenge: string; expiresAt: Date }>()

  /**
   * Persist a challenge under `key` for `ttlMs`. Overwrites any prior
   * entry; only one challenge is live per key at a time.
   */
  async put(key: string, challenge: string, ttlMs: number): Promise<void> {
    this._entries.set(key, { challenge, expiresAt: new Date(Date.now() + ttlMs) })
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

/** Factory around {@link MemoryPasskeyChallengeStore}, for callers who prefer functions to `new`. */
export function memoryPasskeyChallengeStore(
  ...args: ConstructorParameters<typeof MemoryPasskeyChallengeStore>
): MemoryPasskeyChallengeStore {
  return new MemoryPasskeyChallengeStore(...args)
}
