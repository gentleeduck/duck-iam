// Re-exported so a consumer can type the limiter they supply. `strict()` refuses to
// boot production without one, so the interface has to be reachable.
export type { Limiter } from '../limiters.types'

import type { Limiter } from '../limiters.types'

/** Allows everything, for when no limiter is configured. `strict({ env: 'production' })` rejects it:
 *  production needs a real limiter for brute-force protection. */
export class NoopLimiter implements Limiter.Me {
  /** Read by `AuthEngine.strict({ env: 'production' })` to recognise this class. A tag, not a
   *  class-identity compare, which breaks across bundler rewrites: treeshaken duplicates and
   *  nested workspaces each produce their own copy of the class. */
  readonly __isNoopLimiter = true as const
  /** Always allows, with an unbounded remainder. */
  async consume(_key: string, _weight = 1): Promise<Limiter.Result> {
    return { ok: true, remaining: Number.POSITIVE_INFINITY, resetAt: new Date(Date.now() + 60_000) }
  }
  /** Does nothing; there is no budget to clear. */
  async reset(_key: string): Promise<void> {}
}

/** Limiter that never refuses. For tests. */
export function noopLimiter(): NoopLimiter {
  return new NoopLimiter()
}
