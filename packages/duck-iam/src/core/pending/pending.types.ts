import type { IamEngineTypes } from '../engine/engine.types'

/**
 * Cache invalidations - and mutation events - a transaction-bound admin would
 * have applied, broadcast and emitted immediately, held until the caller's
 * transaction commits.
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

  /**
   * The structural shape `createAdmin` expects for its mutation sink - the
   * same substitution trick as {@link ICacheSink}, so a buffering sink stands
   * in for the engine's hook with no change to `createAdmin`.
   */
  export interface IMutationSink<TRole extends string = string, TScope extends string = string> {
    emit(event: IamEngineTypes.IMutationEvent<TRole, TScope>): void
  }

  export interface Effects<TRole extends string = string, TScope extends string = string> {
    /** Number of distinct buffered invalidations. Mutation events are counted by {@link mutationSize}. */
    readonly size: number
    /**
     * Number of buffered mutation events. Not de-duplicated: two grants of the
     * same role are two entries in the history, unlike two invalidations of the
     * same cache key, which are one job.
     */
    readonly mutationSize: number
    /**
     * Applies everything buffered against the target, in record order, and
     * removes each entry as it succeeds. Entries whose target threw stay
     * buffered and an `AggregateError` is raised, so a retry re-applies exactly
     * those. Idempotent: a flush with nothing buffered is a no-op.
     *
     * Buffered mutation events are emitted after the invalidations, so a
     * consumer reacting to an event already reads post-invalidation caches. A
     * throwing `onMutation` is logged and skipped rather than left buffered:
     * the hook is an observer, and retrying a flush for it would re-apply
     * nothing else.
     */
    flush(): Promise<void>
    /** Drops everything buffered - invalidations and mutation events - for an explicit rollback path. */
    discard(): void
    /** Inspects the invalidation buffer without draining it. */
    peek(): readonly Invalidation<TRole>[]
    /** Inspects the mutation-event buffer without draining it. */
    peekMutations(): readonly IamEngineTypes.IMutationEvent<TRole, TScope>[]
  }
}
