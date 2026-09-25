import { env } from 'node:process'
import { AuthError } from '~/core/errors'
import type { DPoPVerifier } from './dpop.transport'
import type { RedisDPoPNonceStore } from './dpop-nonce.redis'

/** Single-process only: a multi-pod deploy needs {@link RedisDPoPNonceStore}, whose `SETNX` claim is
 *  atomic across pods. */
export class MemoryDPoPNonceStore implements DPoPVerifier.NonceStore {
  private readonly _seen = new Map<string, number>()

  constructor(
    private readonly cfg?: {
      /** Escape hatch to allow this store under `NODE_ENV=production`. */
      development?: boolean
    },
  ) {
    // `DPoPVerifier` is built outside the engine, so `strict()` cannot see this store at all and the
    // refusal has to live here - the same reason `MemoryIdempotency` refuses itself. A per-node replay
    // cache is no replay cache: the proof a pod rejects is accepted by every other pod in the fleet.
    if (env.NODE_ENV === 'production' && !this.cfg?.development) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'MemoryDPoPNonceStore is not production ready; pass `nonceStore: redisDPoPNonceStore({ redis })`',
      })
    }
  }

  /** The lazy prune assumes a uniform TTL, so a cross-TTL straggler fails closed as a false positive. */
  async recordSeen(jti: string, ttlMs: number): Promise<boolean> {
    const now = Date.now()
    for (const [k, expiresAt] of this._seen) {
      if (expiresAt < now) {
        this._seen.delete(k)
        continue
      }
      break
    }
    if (this._seen.has(jti)) return false
    this._seen.set(jti, now + ttlMs)
    return true
  }
}

/** In-process DPoP nonce store. Single node only; a fleet needs the Redis store. */
export function memoryDPoPNonceStore(): MemoryDPoPNonceStore {
  return new MemoryDPoPNonceStore()
}
