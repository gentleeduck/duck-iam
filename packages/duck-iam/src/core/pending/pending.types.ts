import type { IamEngineTypes } from '../engine/engine.types'

/**
 * Cache invalidations and mutation events a transaction-bound admin holds until the caller's transaction commits.
 * A rollback discards them, so no node's cache is evicted for a write that never happened.
 */
export namespace Pending {
  export type Invalidation<TRole extends string = string> =
    | { kind: 'subject'; subjectId: string }
    | { kind: 'policies' }
    | { kind: 'roles'; roleId?: TRole }

  /** The structural shape of `createAdmin`'s `cache`, so a buffering sink can stand in for a real engine. */
  export interface ICacheSink<TRole extends string = string> {
    invalidatePolicies(): void
    invalidateRoles(roleId?: TRole): void
    invalidateSubject(subjectId: string): void
  }

  /** The structural shape of `createAdmin`'s mutation sink, so a buffering sink can stand in for the engine's hook. */
  export interface IMutationSink<TRole extends string = string, TScope extends string = string> {
    emit(event: IamEngineTypes.IMutationEvent<TRole, TScope>): void
  }

  export interface Effects<TRole extends string = string, TScope extends string = string> {
    /** Number of distinct buffered invalidations. Mutation events are counted by {@link Pending.Effects.mutationSize}. */
    readonly size: number
    /** Number of buffered mutation events; not de-duplicated, since each is a distinct history entry. */
    readonly mutationSize: number
    /**
     * Applies buffered invalidations in record order, then emits buffered mutation events; a no-op when empty.
     * Failed invalidations stay buffered behind an `AggregateError` for retry; a throwing `onMutation` is only logged.
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
