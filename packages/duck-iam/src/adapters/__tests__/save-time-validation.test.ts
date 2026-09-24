import { describe, expect, it } from 'vitest'
import { IamError, metaOf } from '../../core/errors'
import type { AccessControl } from '../../core/types'
import { iamAssertSavablePolicy, iamAssertSavableRole } from '../../shared/rows'
import { IamMemoryAdapter } from '../memory'

// Pins save-time shape validation: a row the read path would drop is refused on write by every adapter,
// so memory and file cannot hand the engine a row that redis/prisma/drizzle/http would read back as `null`.
const ADAPTERS = ['memory', 'file', 'redis', 'prisma', 'drizzle', 'http'] as const

/** `rules` is a string - the shape that arrives from an untyped source. */
const MALFORMED_POLICY: unknown = { algorithm: 'deny-overrides', id: 'p1', name: 'P', rules: 'nope' }
/** `permissions` is a string, likewise. */
const MALFORMED_ROLE: unknown = { id: 'r1', name: 'R', permissions: 'nope' }

describe('every adapter refuses to save a row its reads would drop', () => {
  it.each(ADAPTERS)('%s refuses a policy whose rules is not an array', (adapter) => {
    expect(() => iamAssertSavablePolicy(adapter, MALFORMED_POLICY)).toThrow('IAM_VALIDATION_FAILED')
  })

  it.each(ADAPTERS)('%s refuses a role whose permissions is not an array', (adapter) => {
    expect(() => iamAssertSavableRole(adapter, MALFORMED_ROLE)).toThrow('IAM_VALIDATION_FAILED')
  })

  it('carries the validator issues, regardless of which adapter name is passed', () => {
    try {
      iamAssertSavablePolicy('redis', MALFORMED_POLICY)
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_VALIDATION_FAILED'>, 'IAM_VALIDATION_FAILED').kind).toBe('policy')
    }
  })

  // Controls: a well-formed row saves, and a warning-level issue (an empty role) does not block the write.
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
   * An empty `actions` list is an error-level `MISSING_FIELD`, and stays typed so no cast is needed.
   * NOTE: duplicate rule ids or an unresolvable condition field are only warnings and would not block the write.
   */
  const noActions: AccessControl.IPolicy = {
    algorithm: 'deny-overrides',
    id: 'p1',
    name: 'P',
    rules: [{ actions: [], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['post'] }],
  }

  it('refuses a policy the read path would drop, and stores nothing', async () => {
    const adapter = new IamMemoryAdapter({ roles: [] })
    await expect(adapter.savePolicy(noActions)).rejects.toThrow('IAM_VALIDATION_FAILED')
    expect(await adapter.getPolicy('p1')).toBeNull()
    expect(await adapter.listPolicies()).toEqual([])
  })

  it('refuses an invalid role the same way', async () => {
    const adapter = new IamMemoryAdapter({ roles: [] })
    const emptyScope: AccessControl.IRole = { id: 'r1', name: 'R', permissions: [], scope: '' }
    await expect(adapter.saveRole(emptyScope)).rejects.toThrow('IAM_VALIDATION_FAILED')
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
