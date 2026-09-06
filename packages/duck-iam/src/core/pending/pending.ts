import type { IamEngineTypes } from '../engine/engine.types'
import type { Pending } from './pending.types'

/** Two invalidations are the same entry when they name the same cache key. */
function sameEntry<TRole extends string>(a: Pending.Invalidation<TRole>, b: Pending.Invalidation<TRole>): boolean {
  if (a.kind === 'subject') return b.kind === 'subject' && a.subjectId === b.subjectId
  if (a.kind === 'roles') return b.kind === 'roles' && a.roleId === b.roleId
  return b.kind === 'policies'
}

/**
 * Builds a buffering cache sink over `target`, a buffering mutation sink over
 * `onMutation`, plus the {@link Pending.Effects} handle that drains both. Pass
 * `cache` and `mutations` where `createAdmin` expects an engine and hand
 * `pending` to the caller to flush after commit.
 *
 * Invalidations de-duplicate, so a long transaction touching one subject a
 * thousand times flushes one invalidation rather than a thousand. Mutation
 * events do not: each write is a distinct entry in the consumer's history, and
 * collapsing two grants into one would misreport what happened.
 */
export function createPending<TRole extends string = string, TScope extends string = string>(
  target: Pending.ICacheSink<TRole>,
  onMutation?: (event: IamEngineTypes.IMutationEvent<TRole, TScope>) => void | Promise<void>,
): {
  cache: Pending.ICacheSink<TRole>
  mutations: Pending.IMutationSink<TRole, TScope>
  pending: Pending.Effects<TRole, TScope>
} {
  let buffer: Pending.Invalidation<TRole>[] = []
  let mutationBuffer: IamEngineTypes.IMutationEvent<TRole, TScope>[] = []

  const record = (entry: Pending.Invalidation<TRole>): void => {
    if (!buffer.some((b) => sameEntry(b, entry))) buffer.push(entry)
  }

  return {
    cache: {
      invalidatePolicies: () => record({ kind: 'policies' }),
      invalidateRoles: (roleId) => record({ kind: 'roles', ...(roleId !== undefined && { roleId }) }),
      invalidateSubject: (subjectId) => record({ kind: 'subject', subjectId }),
    },
    mutations: {
      emit: (event) => {
        // Buffered even with no handler wired, so `peekMutations()` reports what
        // the transaction did and a handler attached before flush still sees it.
        mutationBuffer.push(event)
      },
    },
    pending: {
      discard: () => {
        buffer = []
        mutationBuffer = []
      },
      flush: async () => {
        // Take the buffer before applying, so an invalidation triggered during
        // the drain lands in the next batch rather than appending to this one.
        const draining = buffer
        buffer = []
        const failed: Pending.Invalidation<TRole>[] = []
        const errors: unknown[] = []
        for (const entry of draining) {
          try {
            if (entry.kind === 'subject') target.invalidateSubject(entry.subjectId)
            else if (entry.kind === 'policies') target.invalidatePolicies()
            else target.invalidateRoles(entry.roleId)
          } catch (err) {
            // The target fans out to the fleet invalidator, so this is a
            // network call. The entries belong to a transaction that has
            // already committed: dropping one leaves every node's cache
            // answering from pre-commit state, so keep it and apply the rest.
            failed.push(entry)
            errors.push(err)
          }
        }
        // Mutation events drain after the invalidations, so a consumer reacting
        // to one already reads post-invalidation caches. They drain even when
        // an invalidation failed: the transaction committed, so the history is
        // true whatever the cache fan-out did.
        const emitting = mutationBuffer
        mutationBuffer = []
        if (onMutation) {
          for (const event of emitting) {
            // Swallowed, not re-buffered. The hook is an observer; a retry of
            // flush() exists to re-apply invalidations, and dragging a buggy
            // handler through every retry would block them.
            try {
              await onMutation(event)
            } catch (err) {
              try {
                console.error('[@gentleduck/iam:pending] onMutation hook threw - swallowed on flush', err)
              } catch {
                /* last-resort: give up logging */
              }
            }
          }
        }
        if (failed.length > 0) {
          buffer = [...failed, ...buffer.filter((b) => !failed.some((f) => sameEntry(f, b)))]
          throw new AggregateError(
            errors,
            `[@gentleduck/iam:pending] ${failed.length} of ${draining.length} invalidations could not be applied and remain buffered - retry flush()`,
          )
        }
      },
      get mutationSize() {
        return mutationBuffer.length
      },
      // A copy: the declared `readonly` erases, and the live array is about
      // to be flushed - a caller could inject or reorder entries in it.
      peek: () => [...buffer],
      peekMutations: () => [...mutationBuffer],
      get size() {
        return buffer.length
      },
    },
  }
}
