import type { DPoPVerifier } from './dpop.transport'
import type { RedisDPoPNonceStore } from './dpop-nonce.redis'

/**
 * In-memory nonce store. Single-process only; multi-pod deploys must
 * wire a Redis-backed store {@link RedisDPoPNonceStore} using `SETNX` for true atomic claim.
 */
export class MemoryDPoPNonceStore implements DPoPVerifier.NonceStore {
  private readonly _seen = new Map<string, number>()

  /** Mark `jti`. Lazy prune assumes uniform TTL; cross-TTL stragglers fail closed (false-positive). */
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

/** Factory around {@link MemoryDPoPNonceStore} for functional-style config. */
export function memoryDPoPNonceStore(): MemoryDPoPNonceStore {
  return new MemoryDPoPNonceStore()
}
