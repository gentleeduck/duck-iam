import { describe, expect, it, vi } from 'vitest'
import { IamError, metaOf } from '../../core/errors'
import { IamEngine } from '../../core/engine/engine'
import { iamAssertNoAssignOptions, iamAssertValidAssignWindow } from '../../shared/assign-options'
import { iamAssertAttributesParam } from '../../shared/attributes'
import { iamAssertAssignableScope } from '../../shared/scope'
import { IamDrizzleAdapter } from '../drizzle'
import { IamFileAdapter } from '../file'
import { IamHttpAdapter } from '../http'
import { IamMemoryAdapter } from '../memory'
import { IamPrismaAdapter } from '../prisma'
import { IamRedisAdapter } from '../redis'

// Pins that the six adapters answer the same call the same way: authorization must not depend on the storage choice.

/** `assignRole` refuses an unstored role id, so every adapter below is built holding this role. */
const ADMIN = { id: 'admin', name: 'Admin', permissions: [] }

describe('assignRole options are refused, not discarded', () => {
  // SECURITY: only drizzle stores a grant window; any adapter that dropped `expiresAt` would make the grant permanent.
  it.each(['startsAt', 'expiresAt', 'attributes'] as const)('refuses %s', (field) => {
    const opts = field === 'attributes' ? { attributes: { a: 1 } } : { [field]: new Date() }
    try {
      iamAssertNoAssignOptions('memory', opts)
      expect.unreachable()
    } catch (err) {
      expect(
        metaOf(err as IamError<'IAM_ASSIGN_OPTIONS_UNSUPPORTED'>, 'IAM_ASSIGN_OPTIONS_UNSUPPORTED').fields,
      ).toContain(field)
    }
  })

  it('names every unsupported field it was given', () => {
    try {
      iamAssertNoAssignOptions('memory', { expiresAt: new Date(), startsAt: new Date() })
      expect.unreachable()
    } catch (err) {
      expect(
        metaOf(err as IamError<'IAM_ASSIGN_OPTIONS_UNSUPPORTED'>, 'IAM_ASSIGN_OPTIONS_UNSUPPORTED').fields,
      ).toEqual(['startsAt', 'expiresAt'])
    }
  })

  // Control: an absent options object, or one whose fields are all `undefined`, is the ordinary call.
  it('allows an absent or empty options object', () => {
    expect(() => iamAssertNoAssignOptions('memory', undefined)).not.toThrow()
    expect(() => iamAssertNoAssignOptions('memory', {})).not.toThrow()
    expect(() => iamAssertNoAssignOptions('memory', { expiresAt: undefined })).not.toThrow()
  })

  it('reaches the caller through a real adapter', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await expect(adapter.assignRole('u1', 'admin', undefined, { expiresAt: new Date(0) })).rejects.toThrow(
      'IAM_ASSIGN_OPTIONS_UNSUPPORTED',
    )
    await expect(adapter.assignRole('u1', 'admin')).resolves.toBeUndefined()
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin'])
  })
})

// A non-object `attrs` must throw on every adapter instead of spreading into per-character keys.
describe('setSubjectAttributes rejects a non-object payload', () => {
  it.each([
    ['a string', 'abc'],
    ['an array', [1, 2]],
    ['null', null],
    ['a number', 7],
  ])('rejects %s', (_label, value) => {
    for (const adapter of ['prisma', 'drizzle', 'memory', 'file', 'redis', 'http']) {
      expect(() => iamAssertAttributesParam(adapter, 'u1', value)).toThrow('IAM_ATTRIBUTES_INVALID')
    }
  })

  it('control: a plain object passes', () => {
    expect(() => iamAssertAttributesParam('prisma', 'u1', { tier: 'gold' })).not.toThrow()
  })
})

// An empty-string scope is refused at the shared boundary, so every backend gives the same answer.
// SECURITY: redis encodes "no scope" as `''`, so a stored empty scope would decode as a global grant there.
describe('an empty-string scope is refused by every adapter', () => {
  const ADAPTERS = ['memory', 'file', 'redis', 'prisma', 'drizzle', 'http'] as const

  it.each(ADAPTERS)('%s refuses it', (adapter) => {
    expect(() => iamAssertAssignableScope(adapter, '')).toThrow('IAM_SCOPE_INVALID')
  })

  it('names the adapter, so the caller can tell which backend refused', () => {
    try {
      iamAssertAssignableScope('redis', '')
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_SCOPE_INVALID'>, 'IAM_SCOPE_INVALID').adapter).toBe('redis')
    }
  })

  // Controls: `undefined` (global) and an ordinary scope pass, so the guard cannot be "throw on everything".
  it('allows an absent scope, which is the global grant', () => {
    expect(() => iamAssertAssignableScope('memory', undefined)).not.toThrow()
  })

  it('allows an ordinary scope', () => {
    expect(() => iamAssertAssignableScope('memory', 'org-1')).not.toThrow()
  })

  it('reaches the caller through a real adapter, on assign and on revoke', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await expect(adapter.assignRole('u1', 'admin', '')).rejects.toThrow('IAM_SCOPE_INVALID')
    await expect(adapter.revokeRole('u1', 'admin', '')).rejects.toThrow('IAM_SCOPE_INVALID')
    await expect(adapter.assignRole('u1', 'admin', 'org-1')).resolves.toBeUndefined()
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'admin', scope: 'org-1' }])
  })

  it('leaves no grant behind when it refuses', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await expect(adapter.assignRole('u1', 'admin', '')).rejects.toThrow()
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    expect(await adapter.getSubjectRoles('u1')).toEqual([])
  })
})

// `'*'` means "every scope" on a role or permission, but assignment scopes compare literally, so a `'*'` grant matches
// nothing. Refused on a grant; allowed on a lookup so existing `'*'` rows can still be revoked.
describe('a "*" scope is refused on a grant and allowed on a lookup', () => {
  const ADAPTERS = ['memory', 'file', 'redis', 'prisma', 'drizzle', 'http'] as const

  it.each(ADAPTERS)('%s refuses it on a grant', (adapter) => {
    expect(() => iamAssertAssignableScope(adapter, '*')).toThrow('IAM_SCOPE_INVALID')
  })

  it('reason "wildcard-on-grant" replaces the old prose explanation', () => {
    try {
      iamAssertAssignableScope('memory', '*')
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_SCOPE_INVALID'>, 'IAM_SCOPE_INVALID').reason).toBe('wildcard-on-grant')
    }
  })

  it('allows it on a lookup, so an existing row can be revoked', () => {
    expect(() => iamAssertAssignableScope('memory', '*', 'lookup')).not.toThrow()
  })

  // No legitimate row holds an empty scope, so there is nothing to look up.
  it('still refuses the empty string on a lookup', () => {
    expect(() => iamAssertAssignableScope('memory', '', 'lookup')).toThrow('IAM_SCOPE_INVALID')
  })

  it('reaches the caller through a real adapter, and leaves no grant behind', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await expect(adapter.assignRole('u1', 'admin', '*')).rejects.toThrow('IAM_SCOPE_INVALID')
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([])
    expect(await adapter.getSubjectRoles('u1')).toEqual([])
  })

  // On the engine, an assignment scope matches only the request scope it names, which is why `'*'` would match nothing.
  it('is the grant that would have applied to nothing', async () => {
    const adapter = new IamMemoryAdapter<string, string, string, string>({
      roles: [{ id: 'reader', name: 'Reader', permissions: [{ action: 'read', resource: 'post' }] }],
    })
    await adapter.assignRole('u1', 'reader', 'org-1')
    const scoped = await adapter.getSubjectScopedRoles('u1')
    expect(scoped).toEqual([{ role: 'reader', scope: 'org-1' }])
    // The control: an ordinary scope does reach the request it names.
    const engine = new IamEngine({ adapter, mode: 'development' })
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' }, undefined, 'org-1')).toBe(true)
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('revoking a legacy "*" row still works', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await expect(adapter.revokeRole('u1', 'admin', '*')).resolves.toBeUndefined()
  })
})

// The http id cap lives in `segment()`, shared by reads and writes, so no write stores an id no read can fetch.
// `savePolicy`/`saveRole` carry the id in the body, not the URL, so they check it explicitly.
describe('the http adapter refuses an id it could not read back', () => {
  const OVERSIZED = 'u'.repeat(1025)

  function httpAdapter() {
    const fetchSpy = vi.fn(async () => new Response('[]', { headers: { 'content-type': 'application/json' } }))
    const adapter = new IamHttpAdapter({ baseUrl: 'https://api.test/access', fetch: fetchSpy, retries: 0 })
    return { adapter, fetchSpy }
  }

  it('refuses the write rather than accepting one no read can surface', async () => {
    const { adapter, fetchSpy } = httpAdapter()
    await expect(adapter.assignRole(OVERSIZED, 'admin')).rejects.toThrow(/over the 1024/)
    await expect(adapter.revokeRole(OVERSIZED, 'admin')).rejects.toThrow(/over the 1024/)
    await expect(adapter.setSubjectAttributes(OVERSIZED, { a: 1 })).rejects.toThrow(/over the 1024/)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('refuses the read too, rather than answering an empty result', async () => {
    const { adapter } = httpAdapter()
    await expect(adapter.getSubjectRoles(OVERSIZED)).rejects.toThrow(/over the 1024/)
    await expect(adapter.getSubjectScopedRoles(OVERSIZED)).rejects.toThrow(/over the 1024/)
    await expect(adapter.getPolicy(OVERSIZED)).rejects.toThrow(/over the 1024/)
    await expect(adapter.getRole(OVERSIZED)).rejects.toThrow(/over the 1024/)
  })

  // SECURITY: `{}` reads as "no attributes", which is exactly what stops an ABAC deny rule from firing.
  it('does not answer `{}` for attributes, which would retire an attribute deny', async () => {
    const { adapter } = httpAdapter()
    await expect(adapter.getSubjectAttributes(OVERSIZED)).rejects.toThrow(/over the 1024/)
  })

  it('refuses a body-carried id that the read path could never fetch', async () => {
    const { adapter, fetchSpy } = httpAdapter()
    const policy = { algorithm: 'deny-overrides' as const, id: OVERSIZED, name: 'P', rules: [] }
    await expect(adapter.savePolicy(policy)).rejects.toThrow(/over the 1024/)
    await expect(adapter.saveRole({ id: OVERSIZED, name: 'R', permissions: [] })).rejects.toThrow(/over the 1024/)
    // A path separator in a body-carried id is refused too, since every read of it would be.
    await expect(adapter.saveRole({ id: 'a/b', name: 'R', permissions: [] })).rejects.toThrow(/path separator/)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  // Controls: an id at the cap works, and an empty id is still a miss that never reaches the network.
  it('allows an id exactly at the cap', async () => {
    const { adapter, fetchSpy } = httpAdapter()
    await expect(adapter.getSubjectRoles('u'.repeat(1024))).resolves.toEqual([])
    expect(fetchSpy).toHaveBeenCalledOnce()
  })

  it('still treats an empty id as a miss rather than a throw', async () => {
    const { adapter, fetchSpy } = httpAdapter()
    expect(await adapter.getSubjectRoles('')).toEqual([])
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})

// Deleting a missing row and repeating a grant are idempotent on every adapter.
// Prisma's own suite pins its P2025/P2002 handling; this states the contract on the two driverless adapters.
describe('delete and assign are idempotent', () => {
  it('memory: deleting a policy that never existed is not an error', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await expect(adapter.deletePolicy('never-existed')).resolves.toBeUndefined()
    await expect(adapter.deleteRole('never-existed')).resolves.toBeUndefined()
  })

  it('memory: assigning the same grant twice leaves one grant', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await adapter.assignRole('u1', 'admin', 'org-1')
    await adapter.assignRole('u1', 'admin', 'org-1')
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'admin', scope: 'org-1' }])
  })

  it('memory: an unscoped repeat does not accumulate either', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await adapter.assignRole('u1', 'admin')
    await adapter.assignRole('u1', 'admin')
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin'])
  })

  // Control: idempotence must not collapse grants that genuinely differ.
  it('memory: a scoped and an unscoped grant of one role stay distinct', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await adapter.assignRole('u1', 'admin')
    await adapter.assignRole('u1', 'admin', 'org-1')
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin'])
    expect(await adapter.getSubjectScopedRoles('u1')).toEqual([{ role: 'admin', scope: 'org-1' }])
  })

  it('http: a delete of a missing row is whatever the API says, not a client-side throw', async () => {
    const fetchSpy = vi.fn(async () => new Response(null, { status: 204 }))
    const adapter = new IamHttpAdapter({ baseUrl: 'https://api.test/access', fetch: fetchSpy, retries: 0 })
    await expect(adapter.deletePolicy('never-existed')).resolves.toBeUndefined()
    expect(fetchSpy).toHaveBeenCalledOnce()
  })
})

// Every adapter accepts `IReadOptions.signal`, but only http cancels upstream.
// INFO: the engine's `_withTimeout` still bounds every adapter call by `adapterTimeoutMs`.
describe('read options are accepted by every adapter', () => {
  it('takes a signal on the reads the engine makes', async () => {
    // No seeded role: this case asserts the empty answers.
    const adapter = new IamMemoryAdapter({ roles: [] })
    const signal = new AbortController().signal
    // An adapter that ignores the signal must neither throw on it nor treat it as a filter.
    await expect(adapter.listPolicies({ signal })).resolves.toEqual([])
    await expect(adapter.listRoles({ signal })).resolves.toEqual([])
    await expect(adapter.getSubjectRoles('u1', { signal })).resolves.toEqual([])
    await expect(adapter.getSubjectAttributes('u1', { signal })).resolves.toEqual({})
  })

  it('answers the same with and without one', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await adapter.assignRole('u1', 'admin')
    const withSignal = await adapter.getSubjectRoles('u1', { signal: new AbortController().signal })
    expect(withSignal).toEqual(await adapter.getSubjectRoles('u1'))
  })

  // http is the one adapter that uses it: an aborted signal must reach `fetch`, not be replaced by its own timeout.
  it('forwards an aborted signal to fetch from the http adapter', async () => {
    let sawAborted: boolean | undefined
    const adapter = new IamHttpAdapter({
      baseUrl: 'https://iam.example',
      fetch: vi.fn(async (_url: URL | RequestInfo, init?: RequestInit) => {
        sawAborted = init?.signal?.aborted
        return new Response('[]', { headers: { 'content-type': 'application/json' }, status: 200 })
      }),
    })

    const ctrl = new AbortController()
    ctrl.abort()
    await adapter.listPolicies({ signal: ctrl.signal })

    expect(sawAborted).toBe(true)
  })
})

// `getSubjectGrantBoundary` and `assignRole`'s window options are one feature, present or absent together.
// NOTE: the boundary tells the engine when a cached subject goes stale; an adapter storing no window has none.
describe('the grant boundary is implemented exactly where the bounds are stored', () => {
  const ADAPTERS = [
    ['memory', IamMemoryAdapter, false],
    ['file', IamFileAdapter, false],
    ['redis', IamRedisAdapter, false],
    ['prisma', IamPrismaAdapter, false],
    ['http', IamHttpAdapter, false],
    ['drizzle', IamDrizzleAdapter, true],
  ] as const

  it.each(ADAPTERS)('%s', (_name, ctor, stores) => {
    const proto: unknown = ctor.prototype
    const has =
      typeof proto === 'object' && proto !== null && typeof Reflect.get(proto, 'getSubjectGrantBoundary') === 'function'
    expect(has).toBe(stores)
  })

  it('the five that refuse the options are exactly the five without the method', () => {
    // Reads both facts off one list instead of trusting the table above to track the guard.
    for (const [name, ctor, stores] of ADAPTERS) {
      const refuses = (() => {
        try {
          iamAssertNoAssignOptions(name, { expiresAt: new Date(0) })
          return false
        } catch {
          return true
        }
      })()
      // `iamAssertNoAssignOptions` is name-agnostic, so this pins only that no adapter name is exempt.
      expect(refuses).toBe(true)
      const hasMethod = typeof Reflect.get(ctor.prototype, 'getSubjectGrantBoundary') === 'function'
      expect(hasMethod, `${name} must ${stores ? 'implement' : 'omit'} getSubjectGrantBoundary`).toBe(stores)
    }
  })
})

// The window guard is drizzle-only for the same reason: no other adapter accepts a window.
describe('an empty window is refused before it reaches any driver', () => {
  it('throws IAM_ASSIGN_WINDOW_EMPTY, which echoes neither instant', () => {
    const startsAt = new Date('2030-01-01T00:00:00.000Z')
    try {
      iamAssertValidAssignWindow('drizzle', { expiresAt: new Date('2029-01-01T00:00:00.000Z'), startsAt })
      expect.unreachable('an empty window must not be accepted')
    } catch (err) {
      expect(err).toBeInstanceOf(IamError)
      expect((err as IamError).code).toBe('IAM_ASSIGN_WINDOW_EMPTY')
      const wire = JSON.stringify((err as IamError).toJSON())
      expect(wire, 'an authorization error must not echo its input').not.toContain(startsAt.toISOString())
      expect(wire).not.toContain('2029')
    }
  })

  it('accepts every window a store could honour', () => {
    const t = new Date('2030-01-01T00:00:00.000Z')
    const later = new Date(t.getTime() + 1)
    expect(() => iamAssertValidAssignWindow('drizzle', undefined)).not.toThrow()
    expect(() => iamAssertValidAssignWindow('drizzle', {})).not.toThrow()
    expect(() => iamAssertValidAssignWindow('drizzle', { startsAt: t })).not.toThrow()
    expect(() => iamAssertValidAssignWindow('drizzle', { expiresAt: t })).not.toThrow()
    expect(() => iamAssertValidAssignWindow('drizzle', { expiresAt: later, startsAt: t })).not.toThrow()
  })

  it('refuses a bound that is not a usable Date', () => {
    try {
      iamAssertValidAssignWindow('drizzle', { startsAt: new Date('nope') })
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_ASSIGN_WINDOW_INVALID_DATE'>, 'IAM_ASSIGN_WINDOW_INVALID_DATE').field).toBe(
        'startsAt',
      )
    }
    try {
      iamAssertValidAssignWindow('drizzle', { expiresAt: new Date('nope') })
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_ASSIGN_WINDOW_INVALID_DATE'>, 'IAM_ASSIGN_WINDOW_INVALID_DATE').field).toBe(
        'expiresAt',
      )
    }
  })
})
