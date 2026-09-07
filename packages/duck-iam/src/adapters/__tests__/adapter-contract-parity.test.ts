import { describe, expect, it, vi } from 'vitest'
import { iamAssertNoAssignOptions, iamAssertValidAssignWindow } from '../../shared/assign-options'
import { iamAssertAttributesParam } from '../../shared/attributes'
import { iamAssertAssignableScope } from '../../shared/scope'
import { IamDrizzleAdapter } from '../drizzle'
import { IamFileAdapter } from '../file'
import { IamHttpAdapter } from '../http'
import { IamMemoryAdapter } from '../memory'
import { IamPrismaAdapter } from '../prisma'
import { IamRedisAdapter } from '../redis'

/**
 * The six adapters implement one interface, and an audit matrix found three
 * places where they answered the same call differently. A deployment's
 * authorization behaviour must not change with its storage choice.
 */
/**
 * `assignRole` refuses a role id nothing is stored under, so every adapter
 * below is built holding the role these cases grant.
 */
const ADMIN = { id: 'admin', name: 'Admin', permissions: [] }

describe('assignRole options are refused, not discarded', () => {
  // Only the drizzle schemas carry `starts_at`/`expires_at`; prisma has no such
  // columns at all. The other five took the argument and dropped it, so a
  // break-glass grant issued with `expiresAt` was permanent and the batch API
  // still reported `ok: true, applied: 1`.
  it.each(['startsAt', 'expiresAt', 'attributes'] as const)('refuses %s', (field) => {
    const opts = field === 'attributes' ? { attributes: { a: 1 } } : { [field]: new Date() }
    expect(() => iamAssertNoAssignOptions('memory', opts)).toThrow(new RegExp(field))
  })

  it('names every unsupported field it was given', () => {
    expect(() => iamAssertNoAssignOptions('memory', { expiresAt: new Date(), startsAt: new Date() })).toThrow(
      /startsAt, expiresAt/,
    )
  })

  // Controls: an absent `opts`, and one whose fields are all `undefined`, are
  // the ordinary call and must stay silent.
  it('allows an absent or empty options object', () => {
    expect(() => iamAssertNoAssignOptions('memory', undefined)).not.toThrow()
    expect(() => iamAssertNoAssignOptions('memory', {})).not.toThrow()
    expect(() => iamAssertNoAssignOptions('memory', { expiresAt: undefined })).not.toThrow()
  })

  it('reaches the caller through a real adapter', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await expect(adapter.assignRole('u1', 'admin', undefined, { expiresAt: new Date(0) })).rejects.toThrow(/expiresAt/)
    await expect(adapter.assignRole('u1', 'admin')).resolves.toBeUndefined()
    expect(await adapter.getSubjectRoles('u1')).toEqual(['admin'])
  })
})

/**
 * `iamAssertAttributesParam` exists to stop a non-object `attrs` spreading into
 * per-character keys. Prisma and Drizzle - the two SQL backends - never called
 * it, so `setSubjectAttributes(id, 'abc')` wrote `{0:'a',1:'b',2:'c'}` there and
 * threw on the other four.
 */
describe('setSubjectAttributes rejects a non-object payload', () => {
  it.each([
    ['a string', 'abc'],
    ['an array', [1, 2]],
    ['null', null],
    ['a number', 7],
  ])('rejects %s', (_label, value) => {
    for (const adapter of ['prisma', 'drizzle', 'memory', 'file', 'redis', 'http']) {
      expect(() => iamAssertAttributesParam(adapter, 'u1', value)).toThrow(/must be a plain object/)
    }
  })

  it('control: a plain object passes', () => {
    expect(() => iamAssertAttributesParam('prisma', 'u1', { tier: 'gold' })).not.toThrow()
  })
})

/**
 * `assignRole(u, r, '')` produced five different outcomes across six adapters:
 * memory / prisma / drizzle stored a grant scoped to a value nothing matches,
 * file stored one that became unreadable at the next restart, http accepted the
 * write and dropped the row on every read, and only redis refused it. An
 * operator submitting an empty form field got an error, a scoped grant, a
 * vanishing grant, or a grant with a shelf life, depending on the backend.
 *
 * Redis was right - its encoding spells "no scope" as the empty string, so
 * storing a literal one decodes as a *global* grant, strictly more power than
 * was asked for - but the decision belonged at the shared boundary.
 */
describe('an empty-string scope is refused by every adapter', () => {
  const ADAPTERS = ['memory', 'file', 'redis', 'prisma', 'drizzle', 'http'] as const

  it.each(ADAPTERS)('%s refuses it', (adapter) => {
    expect(() => iamAssertAssignableScope(adapter, '')).toThrow(/must not be an empty string/)
  })

  it('names the adapter, so the message says which backend refused', () => {
    expect(() => iamAssertAssignableScope('redis', '')).toThrow(/iam:redis/)
  })

  // Controls: `undefined` is how the contract spells "global" and must stay
  // silent, and an ordinary scope must pass. Without these the guard could be
  // "throw on everything" and the assertions above would still hold.
  it('allows an absent scope, which is the global grant', () => {
    expect(() => iamAssertAssignableScope('memory', undefined)).not.toThrow()
  })

  it('allows an ordinary scope', () => {
    expect(() => iamAssertAssignableScope('memory', 'org-1')).not.toThrow()
  })

  it('reaches the caller through a real adapter, on assign and on revoke', async () => {
    const adapter = new IamMemoryAdapter({ roles: [ADMIN] })
    await expect(adapter.assignRole('u1', 'admin', '')).rejects.toThrow(/must not be an empty string/)
    await expect(adapter.revokeRole('u1', 'admin', '')).rejects.toThrow(/must not be an empty string/)
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

/**
 * The http adapter capped id length on its five read methods and on none of
 * their sibling writes. A write for an over-long id succeeded and every read of
 * it then answered `null`, `[]` or `{}` with nothing logged - and the `{}` was
 * not fail-closed: an ABAC rule denying on `attributes.suspended === true`
 * evaluated as though the attribute were absent, so a guard meant to bound a
 * URL was quietly retiring deny rules.
 *
 * The cap now lives in `segment()`, the one function both paths call, and
 * `savePolicy` / `saveRole` - which PUT to a collection URL with the id in the
 * body and so never reach it - check the id explicitly.
 */
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

  // The sharp one: `{}` reads as "this subject has no attributes", which is the
  // answer an ABAC deny rule needs to *not* fire.
  it('does not answer `{}` for attributes, which would retire an attribute deny', async () => {
    const { adapter } = httpAdapter()
    await expect(adapter.getSubjectAttributes(OVERSIZED)).rejects.toThrow(/over the 1024/)
  })

  it('refuses a body-carried id that the read path could never fetch', async () => {
    const { adapter, fetchSpy } = httpAdapter()
    const policy = { algorithm: 'deny-overrides' as const, id: OVERSIZED, name: 'P', rules: [] }
    await expect(adapter.savePolicy(policy)).rejects.toThrow(/over the 1024/)
    await expect(adapter.saveRole({ id: OVERSIZED, name: 'R', permissions: [] })).rejects.toThrow(/over the 1024/)
    // Same guard, other class: a separator in a body-carried id was accepted by
    // the write and refused by every read of it.
    await expect(adapter.saveRole({ id: 'a/b', name: 'R', permissions: [] })).rejects.toThrow(/path separator/)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  // Controls: an id at the cap still works, and an empty id keeps its
  // long-standing "miss, never reaches the network" read behaviour.
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

/**
 * Deleting a row that is not there, and assigning a role twice, are both
 * idempotent on five adapters. Prisma used `delete` (which raises `P2025` on a
 * miss - the documented reason `deleteMany` exists) and a bare `create`
 * against `@@unique([subjectId, roleId, scope])`, so an admin retry that is
 * safe on five backends threw on one. Prisma's own suite pins the fixed
 * behaviour against a mock that models P2025/P2002; this states the contract
 * those adapters are all implementing, against the two that need no driver.
 */
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

/**
 * `IReadOptions.signal` is uniform in its *surface* and not in its *effect*,
 * and the interface doc used to blur the two - it named Redis as an adapter
 * that plumbs the signal through, which the shipped Redis adapter does not. An
 * operator reading that would expect an aborted request to stop the query.
 *
 * What is actually guaranteed: every adapter accepts the parameter, and
 * `Engine._withTimeout` races every adapter call against `adapterTimeoutMs`, so
 * the request thread is released whatever the adapter does. Only the HTTP
 * adapter cancels upstream.
 */
describe('read options are accepted by every adapter', () => {
  it('takes a signal on the reads the engine makes', async () => {
    // No seeded role here: this case asserts the empty answers, and it grants
    // nothing.
    const adapter = new IamMemoryAdapter({ roles: [] })
    const signal = new AbortController().signal
    // An ignoring adapter answers normally; it does not throw on the parameter
    // and does not mistake it for a filter.
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

  // The one adapter that does more than accept it. An already-aborted signal
  // must reach `fetch`, not be dropped in favour of the adapter's own timeout.
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

/**
 * `getSubjectGrantBoundary` and `assignRole`'s window options are two halves of
 * one feature, and they have to be present or absent together.
 *
 * The method tells the engine when to stop trusting a cached subject. An
 * adapter that cannot store `startsAt`/`expiresAt` has no boundary to report,
 * and one that reported `null` while refusing the options would be answering a
 * question about grants it does not have. The pairing is what keeps the engine
 * from having to know which backend it is talking to.
 */
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
    // Belt and braces: read both facts off the same list rather than trusting
    // the table above to have been kept in step with the guard.
    for (const [name, ctor, stores] of ADAPTERS) {
      const refuses = (() => {
        try {
          iamAssertNoAssignOptions(name, { expiresAt: new Date(0) })
          return false
        } catch {
          return true
        }
      })()
      // `iamAssertNoAssignOptions` is name-agnostic - it refuses for whatever
      // adapter calls it - so what this pins is that no adapter is exempt.
      expect(refuses).toBe(true)
      const hasMethod = typeof Reflect.get(ctor.prototype, 'getSubjectGrantBoundary') === 'function'
      expect(hasMethod, `${name} must ${stores ? 'implement' : 'omit'} getSubjectGrantBoundary`).toBe(stores)
    }
  })
})

/**
 * The window guard is drizzle-only in the same way, and for the same reason:
 * nowhere else can accept a window at all.
 */
describe('an empty window is refused before it reaches any driver', () => {
  it('names both fields and neither instant', () => {
    const startsAt = new Date('2030-01-01T00:00:00.000Z')
    try {
      iamAssertValidAssignWindow('drizzle', { expiresAt: new Date('2029-01-01T00:00:00.000Z'), startsAt })
      expect.unreachable('an empty window must not be accepted')
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      expect(message).toMatch(/startsAt >= expiresAt/)
      expect(message, 'an authorization error must not echo its input').not.toContain(startsAt.toISOString())
      expect(message).not.toContain('2029')
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
    expect(() => iamAssertValidAssignWindow('drizzle', { startsAt: new Date('nope') })).toThrow(/startsAt/)
    expect(() => iamAssertValidAssignWindow('drizzle', { expiresAt: new Date('nope') })).toThrow(/expiresAt/)
  })
})
