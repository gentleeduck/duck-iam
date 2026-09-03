import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../core/types'
import { iamAssertSavablePolicy, iamAssertSavableRole } from '../../shared/rows'
import { IamMemoryAdapter } from '../memory'

/**
 * Shape validation ran on the *read* path for four of the six adapters, never
 * for memory, and only-after-a-restart for file:
 *
 * ```
 * savePolicy(malformed: rules not array) -> getPolicy
 *     memory   {"algorithm":"deny-overrides","id":"p1","name":"P","rules":"nope"}
 *     file     {... "rules":"nope"}     (same process; `null` after a restart)
 *     redis/prisma/drizzle/http   null
 * ```
 *
 * Memory is the adapter every test suite and every prototype runs on, and it
 * was the one handing the engine a policy whose `rules` is a string. File gave
 * two different answers for one store depending on whether the process had
 * restarted - a dev-vs-prod split produced by a single deploy.
 */
const ADAPTERS = ['memory', 'file', 'redis', 'prisma', 'drizzle', 'http'] as const

/** `rules` is a string - the shape that arrives from an untyped source. */
const MALFORMED_POLICY: unknown = { algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: 'nope' }
/** `permissions` is a string, likewise. */
const MALFORMED_ROLE: unknown = { id: 'r1', name: 'R', permissions: 'nope' }

describe('every adapter refuses to save a row its reads would drop', () => {
  it.each(ADAPTERS)('%s refuses a policy whose rules is not an array', (adapter) => {
    expect(() => iamAssertSavablePolicy(adapter, MALFORMED_POLICY)).toThrow(/refusing to save invalid policy "p1"/)
  })

  it.each(ADAPTERS)('%s refuses a role whose permissions is not an array', (adapter) => {
    expect(() => iamAssertSavableRole(adapter, MALFORMED_ROLE)).toThrow(/refusing to save invalid role "r1"/)
  })

  it('names the adapter and carries the validator message', () => {
    expect(() => iamAssertSavablePolicy('redis', MALFORMED_POLICY)).toThrow(/iam:redis/)
  })

  // Controls: a well-formed row must save, and a *warning*-level issue must not
  // block a write - `valid` is defined as "no error-level issues", and an empty
  // role is a warning.
  it('control: a well-formed policy passes', () => {
    expect(() =>
      iamAssertSavablePolicy('memory', { algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] }),
    ).not.toThrow()
  })

  it('control: a warning-level issue does not block the write', () => {
    expect(() => iamAssertSavableRole('memory', { id: 'r1', name: 'R', permissions: [] })).not.toThrow()
  })
})

describe('the memory adapter refuses the write instead of storing it', () => {
  /**
   * A rule whose `actions` list is empty - `MISSING_FIELD`, an error-level
   * issue. Fully typed: the adapter's own `savePolicy` parameter is `IPolicy`,
   * so an end-to-end test cannot hand it `rules: 'nope'` without a cast, and
   * the untyped shapes are covered against the guard above. A rule that names
   * no action can never match a request, so this is the same class of dead row
   * by a different route.
   *
   * Duplicate rule ids and an unresolvable condition field were both tried
   * first and are *warnings*, which by design do not block a write.
   */
  const noActions: AccessControl.IPolicy = {
    algorithm: 'deny-overrides',
    id: 'p1',
    name: 'P',
    rules: [{ actions: [], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['post'] }],
  }

  it('refuses a policy the read path would drop, and stores nothing', async () => {
    const adapter = new IamMemoryAdapter({ roles: [] })
    await expect(adapter.savePolicy(noActions)).rejects.toThrow(/refusing to save invalid policy "p1"/)
    expect(await adapter.getPolicy('p1')).toBeNull()
    expect(await adapter.listPolicies()).toEqual([])
  })

  it('refuses an invalid role the same way', async () => {
    const adapter = new IamMemoryAdapter({ roles: [] })
    const emptyScope: AccessControl.IRole = { id: 'r1', name: 'R', permissions: [], scope: '' }
    await expect(adapter.saveRole(emptyScope)).rejects.toThrow(/refusing to save invalid role "r1"/)
    expect(await adapter.getRole('r1')).toBeNull()
  })

  it('control: a well-formed policy still round-trips', async () => {
    const adapter = new IamMemoryAdapter({ roles: [] })
    const policy: AccessControl.IPolicy = { algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: [] }
    await adapter.savePolicy(policy)
    expect((await adapter.getPolicy('p1'))?.id).toBe('p1')
  })

  it('control: a well-formed role still round-trips', async () => {
    const adapter = new IamMemoryAdapter({ roles: [] })
    await adapter.saveRole({ id: 'r1', name: 'R', permissions: [{ action: 'read', resource: 'post' }] })
    expect((await adapter.getRole('r1'))?.id).toBe('r1')
  })
})
