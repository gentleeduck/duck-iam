import type { IamEngineTypes } from '../engine/engine.types'
import type { Pending } from './pending.types'

/** Two invalidations are the same entry when they name the same cache key. */
function sameEntry<TRole extends string>(a: Pending.Invalidation<TRole>, b: Pending.Invalidation<TRole>): boolean {
  if (a.kind === 'subject') return b.kind === 'subject' && a.subjectId === b.subjectId
  if (a.kind === 'roles') return b.kind === 'roles' && a.roleId === b.roleId
  return b.kind === 'policies'
}

/**
 * Buffering `cache` and `mutations` sinks for `createAdmin`, plus the {@link Pending.Effects} to flush after commit.
 * Invalidations de-duplicate; mutation events do not, since each write is a distinct history entry.
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
        // Buffered even with no handler, so `peekMutations()` still reports what the transaction did.
        mutationBuffer.push(event)
      },
    },
    pending: {
      discard: () => {
        buffer = []
        mutationBuffer = []
      },
      flush: async () => {
        // Swap the buffer out first, so an invalidation recorded during the drain lands in the next batch.
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
            // SECURITY: the transaction already committed, so a dropped entry leaves every node's cache on
            // pre-commit state. Keep it and apply the rest.
            failed.push(entry)
            errors.push(err)
          }
        }
        // Events drain after invalidations so consumers read fresh caches, and drain even if one failed: the
        // transaction committed.
        const emitting = mutationBuffer
        mutationBuffer = []
        if (onMutation) {
          for (const event of emitting) {
            // Logged, not re-buffered: retries exist for invalidations, and a buggy observer must not block them.
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
      // A copy: `readonly` erases at runtime, so a caller could otherwise mutate the live buffer.
      peek: () => [...buffer],
      peekMutations: () => [...mutationBuffer],
      get size() {
        return buffer.length
      },
    },
  }
}
