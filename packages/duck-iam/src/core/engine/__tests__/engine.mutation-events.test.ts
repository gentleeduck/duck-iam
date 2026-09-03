import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

/**
 * `engine.admin` hard-deletes assignment rows and overwrites policies in place,
 * so for most of its writes the `onMutation` event is the only evidence the
 * write ever happened. The library deliberately ships no history table -
 * retention, redaction and erasure belong to the consuming application - which
 * makes the completeness of this event stream the whole contract.
 *
 * These tests pin three things the surface would otherwise lose quietly: that
 * every write emits, that the caller's `actor` reaches the event, and that a
 * rolled-back transaction emits nothing.
 */

/** Collects every event the engine emits, in order. */
function recorder() {
  const events: IamEngineTypes.IMutationEvent[] = []
  return { events, onMutation: (e: IamEngineTypes.IMutationEvent) => void events.push(e) }
}

/**
 * A memory adapter that also answers `withClient`, so the facade can bind it.
 * The copy shares the original's Maps - what matters here is which events
 * escape the buffer, not real transactional isolation.
 */
function bindable(adapter: IamMemoryAdapter): IamMemoryAdapter {
  const copy: IamMemoryAdapter = Object.assign(Object.create(Object.getPrototypeOf(adapter)), adapter)
  return Object.assign(copy, { withClient: () => bindable(adapter) })
}

/**
 * `assignRole` refuses a role id nothing is stored under, so the adapters below
 * are built holding the roles these cases grant.
 */
const GRANTABLE = [
  { id: 'admin', name: 'Admin', permissions: [] },
  { id: 'editor', name: 'Editor', permissions: [] },
]

describe('engine.admin emits a mutation event per write', () => {
  it('assignRole and revokeRole both emit, carrying subject, role and scope', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }), hooks: { onMutation } })

    await engine.admin.assignRole('u1', 'admin', 'org-1')
    await engine.admin.revokeRole('u1', 'admin', 'org-1')

    expect(events.map((e) => e.type)).toEqual(['role.assigned', 'role.revoked'])
    for (const e of events) {
      expect(e).toMatchObject({ roleId: 'admin', scope: 'org-1', subjectId: 'u1' })
      expect(e.at).toBeGreaterThan(0)
    }
  })

  it('carries the actor the caller supplied, on the grant and on the revoke', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }), hooks: { onMutation } })

    await engine.admin.assignRole('u1', 'admin', undefined, { actor: 'admin-7' })
    await engine.admin.revokeRole('u1', 'admin', undefined, { actor: 'admin-9' })

    expect(events.map((e) => e.actor)).toEqual(['admin-7', 'admin-9'])
  })

  it('leaves actor absent rather than inventing one when the caller omits it', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }), hooks: { onMutation } })

    await engine.admin.assignRole('u1', 'admin')

    expect(events[0]?.actor).toBeUndefined()
  })

  it('bulk writes emit one event per row, each carrying that row own actor', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }), hooks: { onMutation } })

    await engine.admin.assignRoles([
      { opts: { actor: 'admin-1' }, roleId: 'admin', subjectId: 'u1' },
      { opts: { actor: 'admin-2' }, roleId: 'editor', subjectId: 'u2' },
    ])

    expect(events).toHaveLength(2)
    expect(events.map((e) => e.actor)).toEqual(['admin-1', 'admin-2'])
    expect(events.every((e) => e.type === 'role.assigned')).toBe(true)
  })

  it('revokeRoles emits one role.revoked per row', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }), hooks: { onMutation } })

    await engine.admin.assignRoles([
      { roleId: 'admin', subjectId: 'u1' },
      { roleId: 'admin', subjectId: 'u2' },
    ])
    events.length = 0
    await engine.admin.revokeRoles([
      { opts: { actor: 'admin-3' }, roleId: 'admin', subjectId: 'u1' },
      { opts: { actor: 'admin-3' }, roleId: 'admin', subjectId: 'u2' },
    ])

    expect(events.map((e) => e.type)).toEqual(['role.revoked', 'role.revoked'])
    expect(events.every((e) => e.actor === 'admin-3')).toBe(true)
  })

  it('policy and role definition writes emit their own types', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }), hooks: { onMutation } })

    await engine.admin.saveRole({ id: 'reader', name: 'Reader', permissions: [] }, { actor: 'admin-1' })
    await engine.admin.savePolicy({ algorithm: 'first-match', id: 'p1', name: 'P', rules: [] }, { actor: 'admin-1' })
    await engine.admin.deletePolicy('p1', { actor: 'admin-1' })
    await engine.admin.deleteRole('reader', { actor: 'admin-1' })

    expect(events.map((e) => e.type)).toEqual(['role.saved', 'policy.saved', 'policy.deleted', 'role.deleted'])
    expect(events.every((e) => e.actor === 'admin-1')).toBe(true)
  })

  it('attributes.set carries the key names and never the values', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }), hooks: { onMutation } })

    await engine.admin.setAttributes('u1', { email: 'someone@example.com', tier: 'gold' }, { actor: 'admin-1' })

    const event = events[0]
    expect(event?.type).toBe('attributes.set')
    expect(event).toMatchObject({ keys: ['email', 'tier'], subjectId: 'u1' })
    // The bag routinely holds personal data and a consumer will very likely
    // write this event to a durable log. Values must not ride along.
    expect(JSON.stringify(event)).not.toContain('someone@example.com')
  })

  it('a hook that throws does not fail the write it is reporting on', async () => {
    const consoleErr = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const engine = new IamEngine({
        adapter: new IamMemoryAdapter({ roles: GRANTABLE }),
        hooks: {
          onMutation: () => {
            throw new Error('history-store-down')
          },
        },
      })

      await expect(engine.admin.assignRole('u1', 'admin')).resolves.not.toThrow()
      expect(await engine.getEffectiveRoles('u1')).toContain('admin')
      expect(consoleErr).toHaveBeenCalled()
    } finally {
      consoleErr.mockRestore()
    }
  })

  it('emits nothing at all when no onMutation hook is wired', async () => {
    // The sink is only built when the hook exists, so an unhooked engine must
    // not pay for events nobody reads.
    const engine = new IamEngine({ adapter: new IamMemoryAdapter({ roles: GRANTABLE }) })
    await expect(engine.admin.assignRole('u1', 'admin')).resolves.not.toThrow()
  })
})

describe('mutation events under a transaction', () => {
  it('buffers until flush, so a committed write reports once', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({
      adapter: bindable(new IamMemoryAdapter({ roles: GRANTABLE })),
      hooks: { onMutation },
    })

    const perms = engine.withTransaction({})
    await perms.admin.assignRole('u1', 'admin', undefined, { actor: 'admin-1' })
    expect(events).toEqual([])

    await perms.pending.flush()
    expect(events.map((e) => e.type)).toEqual(['role.assigned'])
  })

  it('discard drops them, so a rolled-back grant leaves no history', async () => {
    const { events, onMutation } = recorder()
    const engine = new IamEngine({
      adapter: bindable(new IamMemoryAdapter({ roles: GRANTABLE })),
      hooks: { onMutation },
    })

    const perms = engine.withTransaction({})
    await perms.admin.assignRole('u1', 'admin')
    perms.pending.discard()
    await perms.pending.flush()

    expect(events).toEqual([])
  })

  it('does not de-duplicate: two writes of the same grant are two history entries', async () => {
    // Invalidations collapse - replaying one twice is wasted work, not a wrong
    // answer. Events must not: each write is a distinct thing that happened.
    const { events, onMutation } = recorder()
    const engine = new IamEngine({
      adapter: bindable(new IamMemoryAdapter({ roles: GRANTABLE })),
      hooks: { onMutation },
    })

    const perms = engine.withTransaction({})
    await perms.admin.assignRole('u1', 'admin')
    await perms.admin.assignRole('u1', 'admin')
    await perms.pending.flush()

    expect(events).toHaveLength(2)
  })
})
