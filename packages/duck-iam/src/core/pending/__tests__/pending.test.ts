import { describe, expect, it, vi } from 'vitest'
import { createPending } from '../pending'
import type { Pending } from '../pending.types'

function sink() {
  return {
    invalidatePolicies: vi.fn(),
    invalidateRoles: vi.fn(),
    invalidateSubject: vi.fn(),
  }
}

describe('createPending', () => {
  it('records instead of invalidating', () => {
    const target = sink()
    const { cache, pending } = createPending(target)

    cache.invalidateSubject('u1')
    cache.invalidatePolicies()

    expect(target.invalidateSubject).not.toHaveBeenCalled()
    expect(target.invalidatePolicies).not.toHaveBeenCalled()
    expect(pending.size).toBe(2)
  })

  it('flush applies in record order, then empties', async () => {
    const target = sink()
    const order: string[] = []
    target.invalidateSubject.mockImplementation(() => order.push('subject'))
    target.invalidatePolicies.mockImplementation(() => order.push('policies'))
    const { cache, pending } = createPending(target)

    cache.invalidateSubject('u1')
    cache.invalidatePolicies()
    await pending.flush()

    expect(order).toEqual(['subject', 'policies'])
    expect(pending.size).toBe(0)
  })

  it('flush is idempotent', async () => {
    const target = sink()
    const { cache, pending } = createPending(target)

    cache.invalidateSubject('u1')
    await pending.flush()
    await pending.flush()

    expect(target.invalidateSubject).toHaveBeenCalledTimes(1)
  })

  it('de-duplicates the same subject recorded twice', async () => {
    const target = sink()
    const { cache, pending } = createPending(target)

    cache.invalidateSubject('u1')
    cache.invalidateSubject('u1')
    cache.invalidateSubject('u2')

    expect(pending.size).toBe(2)
    await pending.flush()
    expect(target.invalidateSubject).toHaveBeenCalledTimes(2)
  })

  it('keeps distinct role ids apart, and a bare invalidateRoles separate from a keyed one', () => {
    const { cache, pending } = createPending(sink())

    cache.invalidateRoles('admin')
    cache.invalidateRoles('editor')
    cache.invalidateRoles()
    cache.invalidateRoles()

    expect(pending.size).toBe(3)
  })

  it('passes the role id through on flush, and undefined for the bare form', async () => {
    const target = sink()
    const { cache, pending } = createPending(target)

    cache.invalidateRoles('admin')
    cache.invalidateRoles()
    await pending.flush()

    expect(target.invalidateRoles.mock.calls).toEqual([['admin'], [undefined]])
  })

  it('discard drops everything without applying', async () => {
    const target = sink()
    const { cache, pending } = createPending(target)

    cache.invalidateSubject('u1')
    pending.discard()
    await pending.flush()

    expect(target.invalidateSubject).not.toHaveBeenCalled()
    expect(pending.size).toBe(0)
  })

  it('peek exposes the buffer without draining it', () => {
    const { cache, pending } = createPending(sink())

    cache.invalidateSubject('u1')

    expect(pending.peek()).toEqual([{ kind: 'subject', subjectId: 'u1' }])
    expect(pending.size).toBe(1)
  })

  it('an invalidation recorded during flush survives into the next flush', async () => {
    // A target that re-enters the sink must not append to the batch currently
    // draining - that would either lose the entry or loop forever.
    const target = sink()
    const { cache, pending } = createPending(target)
    target.invalidatePolicies.mockImplementation(() => cache.invalidateSubject('late'))

    cache.invalidatePolicies()
    await pending.flush()

    expect(target.invalidateSubject).not.toHaveBeenCalled()
    expect(pending.peek()).toEqual([{ kind: 'subject', subjectId: 'late' }])
  })
})

/**
 * The buffered entries belong to a transaction that has already committed, and
 * the target fans out to the fleet invalidator - a network call. `flush()` used
 * to empty the buffer before applying and abandon the loop on the first throw,
 * so a broadcast failure silently dropped every remaining invalidation and the
 * retry the "Idempotent" contract invites was a no-op. Every node then kept
 * answering `allow` for a subject the committed transaction had revoked.
 */
describe('flush() with a throwing target', () => {
  function throwingOn(kind: Pending.Invalidation['kind'] | 'none') {
    const applied: string[] = []
    const target: Pending.ICacheSink = {
      invalidatePolicies: () => {
        if (kind === 'policies') throw new Error('broadcast failed')
        applied.push('policies')
      },
      invalidateRoles: (roleId) => {
        if (kind === 'roles') throw new Error('broadcast failed')
        applied.push(`roles:${roleId}`)
      },
      invalidateSubject: (subjectId) => {
        if (kind === 'subject') throw new Error('broadcast failed')
        applied.push(`subject:${subjectId}`)
      },
    }
    return { applied, target }
  }

  function record(cache: Pending.ICacheSink) {
    cache.invalidateSubject('u1')
    cache.invalidatePolicies()
    cache.invalidateRoles('admin')
  }

  it('applies the entries after the failure instead of abandoning them', async () => {
    const { applied, target } = throwingOn('subject')
    const { cache, pending } = createPending(target)
    record(cache)
    await expect(pending.flush()).rejects.toThrow(AggregateError)
    expect(applied).toEqual(['policies', 'roles:admin'])
  })

  it('keeps the failed entry buffered so a retry re-applies exactly it', async () => {
    let fail = true
    const applied: string[] = []
    const { cache, pending } = createPending({
      invalidatePolicies: () => applied.push('policies'),
      invalidateRoles: (roleId) => applied.push(`roles:${roleId}`),
      invalidateSubject: (subjectId) => {
        if (fail) throw new Error('broadcast failed')
        applied.push(`subject:${subjectId}`)
      },
    })
    record(cache)
    await expect(pending.flush()).rejects.toThrow(/remain buffered/)
    expect(pending.size).toBe(1)
    expect(pending.peek()).toEqual([{ kind: 'subject', subjectId: 'u1' }])

    fail = false
    await pending.flush()
    // The retry applies the dropped entry and nothing else - the two that
    // already succeeded are not re-broadcast.
    expect(applied).toEqual(['policies', 'roles:admin', 'subject:u1'])
    expect(pending.size).toBe(0)
  })

  it('reports every failure, not only the first', async () => {
    const { cache, pending } = createPending({
      invalidatePolicies: () => {
        throw new Error('policies failed')
      },
      invalidateRoles: () => {
        throw new Error('roles failed')
      },
      invalidateSubject: () => {
        throw new Error('subject failed')
      },
    })
    record(cache)
    const err = await pending.flush().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(AggregateError)
    expect(err instanceof AggregateError ? err.errors.map((e) => String(e)) : []).toEqual([
      'Error: subject failed',
      'Error: policies failed',
      'Error: roles failed',
    ])
    expect(pending.size).toBe(3)
  })

  // An entry recorded during the drain must not be lost when a sibling throws,
  // and must not jump ahead of the retry of the failed one.
  it('preserves record order across a partial failure', async () => {
    let cacheRef: Pending.ICacheSink | undefined
    const { cache, pending } = createPending({
      invalidatePolicies: () => cacheRef?.invalidateRoles('late'),
      invalidateRoles: () => {},
      invalidateSubject: () => {
        throw new Error('broadcast failed')
      },
    })
    cacheRef = cache
    cache.invalidateSubject('u1')
    cache.invalidatePolicies()
    await expect(pending.flush()).rejects.toThrow(AggregateError)
    expect(pending.peek()).toEqual([
      { kind: 'subject', subjectId: 'u1' },
      { kind: 'roles', roleId: 'late' },
    ])
  })

  // Control: with a target that never throws, flush still drains completely and
  // raises nothing. Without this the assertions above would pass on a flush
  // that simply never cleared the buffer.
  it('control: a healthy target drains the whole buffer', async () => {
    const { applied, target } = throwingOn('none')
    const { cache, pending } = createPending(target)
    record(cache)
    await pending.flush()
    expect(applied).toEqual(['subject:u1', 'policies', 'roles:admin'])
    expect(pending.size).toBe(0)
  })
})

/**
 * The entries belong to a transaction that has already committed, so a failed
 * invalidation must stay buffered - dropping it leaves every node's cache
 * answering from pre-commit state, which is a stale allow after a revoke.
 * Ten cases covered the happy path; none covered a throwing target.
 */
describe('flush() when the target throws', () => {
  function failingSink(failOn: (entry: string) => boolean) {
    const seen: string[] = []
    return {
      invalidatePolicies: vi.fn(() => {
        seen.push('policies')
        if (failOn('policies')) throw new Error('policies down')
      }),
      invalidateRoles: vi.fn((roleId?: string) => {
        seen.push(`roles:${roleId ?? ''}`)
        if (failOn(`roles:${roleId ?? ''}`)) throw new Error('roles down')
      }),
      invalidateSubject: vi.fn((subjectId: string) => {
        seen.push(`subject:${subjectId}`)
        if (failOn(`subject:${subjectId}`)) throw new Error('subject down')
      }),
      seen,
    }
  }

  it('rejects with an AggregateError naming the counts', async () => {
    const target = failingSink((e) => e === 'subject:u1')
    const { cache, pending } = createPending(target)
    cache.invalidateSubject('u1')
    cache.invalidatePolicies()
    await expect(pending.flush()).rejects.toThrow(/1 of 2 invalidations could not be applied/)
  })

  it('applies the entries that did not throw', async () => {
    const target = failingSink((e) => e === 'subject:u1')
    const { cache, pending } = createPending(target)
    cache.invalidateSubject('u1')
    cache.invalidatePolicies()
    await pending.flush().catch(() => {})
    expect(target.invalidatePolicies).toHaveBeenCalledOnce()
  })

  it('retains only the failed entry for a retry', async () => {
    const target = failingSink((e) => e === 'subject:u1')
    const { cache, pending } = createPending(target)
    cache.invalidateSubject('u1')
    cache.invalidatePolicies()
    await pending.flush().catch(() => {})
    expect(pending.peek()).toEqual([{ kind: 'subject', subjectId: 'u1' }])
  })

  it('a retry against a healthy target applies the tail and empties the buffer', async () => {
    const target = failingSink((e) => e === 'subject:u1')
    const { cache, pending } = createPending(target)
    cache.invalidateSubject('u1')
    cache.invalidatePolicies()
    await pending.flush().catch(() => {})

    const healthy = sink()
    const retry = createPending(healthy)
    for (const entry of pending.peek()) {
      if (entry.kind === 'subject') retry.cache.invalidateSubject(entry.subjectId)
      else if (entry.kind === 'policies') retry.cache.invalidatePolicies()
      else retry.cache.invalidateRoles(entry.roleId)
    }
    await retry.pending.flush()
    expect(healthy.invalidateSubject).toHaveBeenCalledWith('u1')
    expect(retry.pending.size).toBe(0)
  })

  it('does not double-buffer an entry recorded again during the drain', async () => {
    const target = failingSink((e) => e === 'subject:u1')
    const { cache, pending } = createPending(target)
    cache.invalidateSubject('u1')
    await pending.flush().catch(() => {})
    cache.invalidateSubject('u1')
    expect(pending.size).toBe(1)
  })

  // Control: with a healthy target nothing is retained, so the assertions
  // above are about the failure and not about flush() never draining.
  it('retains nothing when every entry applies', async () => {
    const target = failingSink(() => false)
    const { cache, pending } = createPending(target)
    cache.invalidateSubject('u1')
    cache.invalidatePolicies()
    await pending.flush()
    expect(pending.size).toBe(0)
  })
})

describe('peek() is a copy', () => {
  function pushInto(arr: unknown, value: unknown): void {
    if (Array.isArray(arr)) arr.push(value)
  }

  it('injecting into the peeked array does not reach the buffer', () => {
    const { cache, pending } = createPending(sink())
    cache.invalidateSubject('u1')
    const peeked = pending.peek()
    pushInto(peeked, { kind: 'policies' })
    expect(peeked).toHaveLength(2)
    expect(pending.size).toBe(1)
  })

  it('hands out a fresh array each read', () => {
    const { cache, pending } = createPending(sink())
    cache.invalidateSubject('u1')
    expect(pending.peek()).not.toBe(pending.peek())
  })

  // Control: the copy carries the buffered entries.
  it('returns what was recorded', () => {
    const { cache, pending } = createPending(sink())
    cache.invalidateSubject('u1')
    expect(pending.peek()).toEqual([{ kind: 'subject', subjectId: 'u1' }])
  })
})
