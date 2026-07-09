import type { Limiter } from '../limiters.types'

/**
 * No-op limiter used when no Limiter adapter is configured. Always allows.
 * `strict({ env: 'production' })` rejects this - production must supply a real
 * Limiter (redis/upstash) for brute-force protection.
 */
export class NoopLimiter implements Limiter.Me {
  /** Brand consumed by `AuthEngine.strict({ env: 'production' })` to
   * detect "explicit AuthNoopLimiter" - class-identity comparison breaks
   * across bundler rewrites (treeshaken duplicates / nested workspaces)
   * so we tag every instance and check the tag instead. */
  readonly __isNoopLimiter = true as const
  async consume(_key: string, _weight = 1): Promise<Limiter.Result> {
    return { ok: true, remaining: Number.POSITIVE_INFINITY, resetAt: new Date(Date.now() + 60_000) }
  }
  async reset(_key: string): Promise<void> {}
}
