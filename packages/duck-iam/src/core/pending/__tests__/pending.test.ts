import { describe, expect, it, vi } from 'vitest'
import { createPending } from '../pending'

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
