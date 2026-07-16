/**
 * Rate-limit + lockout adapter. Brute-force protection is non-optional; strict()
 * refuses production boot without one wired. Dimensions configurable per app
 * (identity, ip, composite). Reference impls: memory (token bucket), redis (Lua).
 */
export namespace Limiter {
  export type Result = {
    ok: boolean
    remaining: number
    resetAt: Date
  }

  export type Me = {
    consume(key: string, weight?: number): Promise<Result>
    reset(key: string): Promise<void>
  }
}
