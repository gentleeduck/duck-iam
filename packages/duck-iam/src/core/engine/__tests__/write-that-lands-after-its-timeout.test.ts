import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl, IamAdapter } from '../../types'
import { IamEngine } from '../engine'

// `adapterTimeoutMs` bounds how long the caller waits, not how long the store takes. A write that lands after the
// race has already rejected used to skip its own invalidation, so the revoked grant answered from cache until the
// TTL expired - the store said no and the engine said yes.

const POST = { attributes: {}, id: 'p1', type: 'post' }
const ROLES: AccessControl.IRole[] = [
  { id: 'reader', name: 'R', permissions: [{ action: 'read', resource: 'post' }] },
  { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
]
const POLICY: AccessControl.IPolicy = {
  algorithm: 'deny-overrides',
  id: 'blocker',
  name: 'blocker',
  rules: [{ actions: ['delete'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 1, resources: ['post'] }],
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))
const LATE = 60
const TIMEOUT = 15

/** The real write runs, then the call resolves late - a store that finished after the caller stopped waiting. */
function lateAdapter(
  method: string,
  seed: ConstructorParameters<typeof IamMemoryAdapter>[0],
): IamAdapter.IAdapter<string, string, string, string> {
  const inner = new IamMemoryAdapter(seed)
  return new Proxy(inner, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver)
      if (prop !== method || typeof value !== 'function') return value
      return async (...args: unknown[]) => {
        const out = await Reflect.apply(value, inner, args)
        await sleep(LATE)
        return out
      }
    },
  })
}

function engineOver(adapter: IamAdapter.IAdapter<string, string, string, string>, timeoutMs = TIMEOUT) {
  const events: string[] = []
  const engine = new IamEngine({
    adapter,
    adapterTimeoutMs: timeoutMs,
    hooks: { onMutation: (e: { type: string }) => void events.push(e.type) },
    mode: 'production',
  })
  return { engine, events }
}

/** Runs the write, swallows the timeout, and waits for the store to finish. */
async function timeOutOn(write: () => Promise<unknown>): Promise<string> {
  let message = '<resolved>'
  try {
    await write()
  } catch (err) {
    message = (err as Error).message
  }
  await sleep(LATE)
  return message
}

describe('a write that lands after its own timeout', () => {
  it('denies after a revoke that landed late, instead of serving the revoked grant from cache', async () => {
    const adapter = lateAdapter('revokeRole', { assignments: { u1: ['writer'] }, policies: [], roles: ROLES })
    const { engine, events } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST)).toBe(true)

    const message = await timeOutOn(() => engine.admin.revokeRole('u1', 'writer'))
    expect(message).toContain('timed out')
    expect(await adapter.getSubjectRoles('u1')).toEqual([])
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    // The write's outcome was unknown, so nothing is claimed about it: invalidation is safe to do speculatively,
    // an audit event is not.
    expect(events).toEqual([])
  })

  it('denies after a fast revoke too, so the case above is not passing for want of a grant', async () => {
    const adapter = lateAdapter('revokeRole', { assignments: { u1: ['writer'] }, policies: [], roles: ROLES })
    const { engine, events } = engineOver(adapter, 5000)
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    await engine.admin.revokeRole('u1', 'writer')
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(events).toEqual(['role.revoked'])
  })

  it('still allows when the write truly did not land, so the invalidation alone decides nothing', async () => {
    const inner = new IamMemoryAdapter({ assignments: { u1: ['writer'] }, policies: [], roles: ROLES })
    const adapter = new Proxy(inner, {
      get(target, prop, receiver) {
        if (prop === 'revokeRole') {
          return async () => {
            throw new Error('store unreachable')
          }
        }
        return Reflect.get(target, prop, receiver)
      },
    })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(await timeOutOn(() => engine.admin.revokeRole('u1', 'writer'))).toBe('store unreachable')
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
  })

  it('sees a grant that landed late', async () => {
    const adapter = lateAdapter('assignRole', { assignments: {}, policies: [], roles: ROLES })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(await timeOutOn(() => engine.admin.assignRole('u1', 'writer'))).toContain('timed out')
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
  })

  it('applies a deny policy that landed late', async () => {
    const adapter = lateAdapter('savePolicy', { assignments: { u1: ['writer'] }, policies: [], roles: ROLES })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(await timeOutOn(() => engine.admin.savePolicy(POLICY))).toContain('timed out')
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
  })

  it('drops a deny policy that was deleted late', async () => {
    const adapter = lateAdapter('deletePolicy', { assignments: { u1: ['writer'] }, policies: [POLICY], roles: ROLES })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(await timeOutOn(() => engine.admin.deletePolicy('blocker'))).toContain('timed out')
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
  })

  it('applies a role whose permissions were narrowed late', async () => {
    const adapter = lateAdapter('saveRole', { assignments: { u1: ['writer'] }, policies: [], roles: ROLES })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    const narrowed: AccessControl.IRole = { id: 'writer', name: 'W', permissions: [] }
    expect(await timeOutOn(() => engine.admin.saveRole(narrowed))).toContain('timed out')
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
  })

  it('applies a role deleted late, including for a subject that held it by inheritance', async () => {
    const chain: AccessControl.IRole[] = [
      { id: 'base', name: 'B', permissions: [{ action: 'delete', resource: 'post' }] },
      { id: 'mid', inherits: ['base'], name: 'M', permissions: [] },
    ]
    const adapter = lateAdapter('deleteRole', { assignments: { u1: ['mid'] }, policies: [], roles: chain })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(await timeOutOn(() => engine.admin.deleteRole('base'))).toContain('timed out')
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
  })

  it('reflects the store after a scope move that landed late', async () => {
    const scoped: AccessControl.IRole[] = [
      { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
    ]
    const adapter = lateAdapter('updateAssignmentScope', { assignments: {}, policies: [], roles: scoped })
    await adapter.assignRole('u1', 'writer', 'org-1')
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1')).toBe(true)

    const message = await timeOutOn(() => engine.admin.updateAssignmentScope('u1', 'writer', 'org-1', 'org-2'))
    expect(message).toContain('timed out')
    expect(await adapter.getSubjectScopedRoles?.('u1')).toEqual([{ role: 'writer', scope: 'org-2' }])
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1')).toBe(false)
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-2')).toBe(true)
  })

  it('reflects the store when a read lands between the emulated move\u2019s revoke and its assign', async () => {
    // The revoke dropped the cache, so a concurrent request repopulates it with "holds nothing" - and the assign
    // that lands afterwards is the only thing that can correct it.
    const scoped: AccessControl.IRole[] = [
      { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
    ]
    const inner = new IamMemoryAdapter({ assignments: {}, policies: [], roles: scoped })
    await inner.assignRole('u1', 'writer', 'org-1')
    let readDuringMove: (() => Promise<unknown>) | null = null
    const adapter = new Proxy(inner, {
      get(target, prop, receiver) {
        if (prop === 'updateAssignmentScope') return undefined
        const value = Reflect.get(target, prop, receiver)
        if (prop !== 'assignRole' || typeof value !== 'function') return value
        return async (...args: unknown[]) => {
          await readDuringMove?.()
          const out = await Reflect.apply(value, inner, args)
          await sleep(LATE)
          return out
        }
      },
    })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1')).toBe(true)
    readDuringMove = () => engine.can('u1', 'delete', POST, undefined, 'org-2')

    expect(await timeOutOn(() => engine.admin.updateAssignmentScope('u1', 'writer', 'org-1', 'org-2'))).toContain(
      'timed out',
    )
    expect(await adapter.getSubjectScopedRoles?.('u1')).toEqual([{ role: 'writer', scope: 'org-2' }])
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-2')).toBe(true)
  })

  it('reflects the store when the emulated move times out on the revoke itself', async () => {
    const scoped: AccessControl.IRole[] = [
      { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
    ]
    const late = lateAdapter('revokeRole', { assignments: {}, policies: [], roles: scoped })
    await late.assignRole('u1', 'writer', 'org-1')
    const adapter = new Proxy(late, {
      get: (target, prop, receiver) =>
        prop === 'updateAssignmentScope' ? undefined : Reflect.get(target, prop, receiver),
    })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1')).toBe(true)

    // The revoke's fate is unknown and the assign never runs, so the subject is left holding nothing at all.
    expect(await timeOutOn(() => engine.admin.updateAssignmentScope('u1', 'writer', 'org-1', 'org-2'))).toContain(
      'timed out',
    )
    expect(await adapter.getSubjectScopedRoles?.('u1')).toEqual([])
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1')).toBe(false)
  })

  it('reflects the store when the emulated move revokes, then times out on the assign', async () => {
    const scoped: AccessControl.IRole[] = [
      { id: 'writer', name: 'W', permissions: [{ action: 'delete', resource: 'post' }] },
    ]
    const late = lateAdapter('assignRole', { assignments: {}, policies: [], roles: scoped })
    await late.assignRole('u1', 'writer', 'org-1')
    // Without `updateAssignmentScope` the admin emulates the move as revoke + assign, which is the path where the
    // revoke has certainly landed and the assign's fate is unknown.
    const adapter = new Proxy(late, {
      get: (target, prop, receiver) =>
        prop === 'updateAssignmentScope' ? undefined : Reflect.get(target, prop, receiver),
    })
    const { engine } = engineOver(adapter)
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1')).toBe(true)

    const message = await timeOutOn(() => engine.admin.updateAssignmentScope('u1', 'writer', 'org-1', 'org-2'))
    expect(message).toContain('timed out')
    expect(await adapter.getSubjectScopedRoles?.('u1')).toEqual([{ role: 'writer', scope: 'org-2' }])
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-1')).toBe(false)
    expect(await engine.can('u1', 'delete', POST, undefined, 'org-2')).toBe(true)
  })
})
