/**
 * Rate-limit + lockout adapter. Brute-force protection is non-optional; strict()
 * refuses production boot without one wired. The caller names the key. Reference
 * impls: memory and redis, both fixed-window counters.
 */
export namespace Limiter {
  /** One `consume`: whether it fit, what is left, and when the window resets. */
  export type Result = {
    ok: boolean
    remaining: number
    resetAt: Date
  }

  /** A rate limiter keyed by caller-chosen strings. */
  export type Me = {
    /** Spends `weight` (default 1) from `key`'s window. */
    consume(key: string, weight?: number): Promise<Result>
    /** Empties `key`'s window. */
    reset(key: string): Promise<void>
  }
}
