import { isCredentialExpired } from '~/core/credentials/credentials'
import { AuthError } from '~/core/errors'
import type { Passkey } from '../passkey.types'

/** The reference in-memory store, for tests and single-process deploys; production wires a
 *  Redis-backed one. */
export class MemoryPasskeyChallengeStore implements Passkey.ChallengeStore {
  /** Read by `strict()` through the provider, which is the only handle it has on this store. */
  readonly __isInProcessChallengeStore = true as const
  private readonly _entries = new Map<string, { challenge: string; expiresAt: Date }>()

  /** Overwrites any prior entry: one challenge is live per key at a time. */
  async put(key: string, challenge: string, ttlMs: number): Promise<void> {
    // Nothing else drops an abandoned ceremony - `take` deletes only what it is asked for - and `begin`
    // takes a caller-chosen session id on an unauthenticated route, which the limiter buckets per id, so
    // a fresh id each request is a fresh bucket and the map grows for as long as the process runs.
    for (const [k, entry] of this._entries) {
      if (isCredentialExpired(entry)) this._entries.delete(k)
    }
    this._entries.set(key, { challenge, expiresAt: new Date(Date.now() + ttlMs) })
  }

  /** Reads and deletes atomically, rejecting `AUTH_CREDENTIAL_NOT_FOUND` when missing, expired or already
   *  consumed. */
  async take(key: string): Promise<string> {
    const entry = this._entries.get(key)
    if (!entry) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
    this._entries.delete(key)
    // A non-finite expiresAt slips `NaN < now === false`, which is a replay window.
    if (isCredentialExpired(entry)) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
    return entry.challenge
  }
}

/** In-process passkey challenge store. Single node only; a fleet needs a shared store. */
export function memoryPasskeyChallengeStore(
  ...args: ConstructorParameters<typeof MemoryPasskeyChallengeStore>
): MemoryPasskeyChallengeStore {
  return new MemoryPasskeyChallengeStore(...args)
}
