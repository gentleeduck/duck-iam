/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

/**
 * Rate-limit + lockout adapter. Brute-force protection is non-optional; strict()
 * refuses production boot without one wired. Dimensions configurable per app
 * (identity, ip, composite). Reference impls: memory (token bucket), redis (Lua).
 */
export namespace Limiter {
  export interface IResult {
    ok: boolean
    remaining: number
    resetAt: number
  }

  export interface ILimiter {
    consume(key: string, weight?: number): Promise<IResult>
    reset(key: string): Promise<void>
  }
}
