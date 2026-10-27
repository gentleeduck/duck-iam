import { isProduction } from '~/core/env'
import { AuthError } from '~/core/errors'
import type { DPoPVerifier } from './dpop.transport'
import type { RedisDPoPNonceStore } from './dpop-nonce.redis'

/** Development and test only, and refused in production: a multi-pod deploy needs
 *  {@link RedisDPoPNonceStore}, whose `SETNX` claim is atomic across pods. */
export class MemoryDPoPNonceStore implements DPoPVerifier.NonceStore {
  private readonly _seen = new Map<string, number>()

  constructor() {
    // A per-node replay cache is no replay cache: the proof a pod rejects is accepted by every other pod.
    if (isProduction()) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'MemoryDPoPNonceStore is refused in production; pass `nonceStore: redisDPoPNonceStore({ redis })`',
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

/** In-process DPoP nonce store, for development and test. A fleet needs the Redis store. */
export function memoryDPoPNonceStore(): MemoryDPoPNonceStore {
  return new MemoryDPoPNonceStore()
}
