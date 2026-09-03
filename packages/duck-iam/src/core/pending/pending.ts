import type { Pending } from './pending.types'

/** Two invalidations are the same entry when they name the same cache key. */
function sameEntry<TRole extends string>(a: Pending.Invalidation<TRole>, b: Pending.Invalidation<TRole>): boolean {
  if (a.kind === 'subject') return b.kind === 'subject' && a.subjectId === b.subjectId
  if (a.kind === 'roles') return b.kind === 'roles' && a.roleId === b.roleId
  return b.kind === 'policies'
}

/**
 * Builds a buffering cache sink over `target`, plus the {@link Pending.Effects}
 * handle that drains it. Pass `cache` where `createAdmin` expects an engine and
 * hand `pending` to the caller to flush after commit.
 *
 * De-duplicates, so a long transaction touching one subject a thousand times
 * flushes one invalidation rather than a thousand.
 */
export function createPending<TRole extends string = string>(
  target: Pending.ICacheSink<TRole>,
): { cache: Pending.ICacheSink<TRole>; pending: Pending.Effects<TRole> } {
  let buffer: Pending.Invalidation<TRole>[] = []

  const record = (entry: Pending.Invalidation<TRole>): void => {
    if (!buffer.some((b) => sameEntry(b, entry))) buffer.push(entry)
  }

  return {
    cache: {
      invalidatePolicies: () => record({ kind: 'policies' }),
      invalidateRoles: (roleId) => record({ kind: 'roles', ...(roleId !== undefined && { roleId }) }),
      invalidateSubject: (subjectId) => record({ kind: 'subject', subjectId }),
    },
    pending: {
      discard: () => {
        buffer = []
      },
      flush: async () => {
        // Take the buffer before applying, so an invalidation triggered during
        // the drain lands in the next batch rather than appending to this one.
        const draining = buffer
        buffer = []
        for (const entry of draining) {
          if (entry.kind === 'subject') target.invalidateSubject(entry.subjectId)
          else if (entry.kind === 'policies') target.invalidatePolicies()
          else target.invalidateRoles(entry.roleId)
        }
      },
      peek: () => buffer,
      get size() {
        return buffer.length
      },
    },
  }
}
