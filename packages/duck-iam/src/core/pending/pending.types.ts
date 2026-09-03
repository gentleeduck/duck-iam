/**
 * Cache invalidations a transaction-bound admin would have applied and
 * broadcast immediately, held until the caller's transaction commits.
 *
 * A rollback discards them: a transaction that never committed never made the
 * shared cache wrong, and broadcasting anyway would evict every node's cache
 * for a write that did not happen.
 */
export namespace Pending {
  export type Invalidation<TRole extends string = string> =
    | { kind: 'subject'; subjectId: string }
    | { kind: 'policies' }
    | { kind: 'roles'; roleId?: TRole }

  /**
   * The structural shape `createAdmin` expects for its second argument's
   * `cache`. Matching it exactly is what lets a buffering sink stand in for a
   * real engine with no change to `createAdmin`.
   */
  export interface ICacheSink<TRole extends string = string> {
    invalidatePolicies(): void
    invalidateRoles(roleId?: TRole): void
    invalidateSubject(subjectId: string): void
  }

  export interface Effects<TRole extends string = string> {
    /** Number of distinct buffered invalidations. */
    readonly size: number
    /** Applies everything buffered against the target, in record order, then empties. Idempotent. */
    flush(): Promise<void>
    /** Drops everything buffered, for an explicit rollback path. */
    discard(): void
    /** Inspects the buffer without draining it. */
    peek(): readonly Invalidation<TRole>[]
  }
}
