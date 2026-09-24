import { describe, expect, it } from 'vitest'
import { IamError, metaOf } from '../../core/errors'
import { iamAssertNoAssignOptions, iamAssertValidAssignWindow } from '../assign-options'
import { iamUnknownRoleError } from '../assignment-target'
import { iamAssertAttributesParam } from '../attributes'
import { iamAssertSavablePolicy, iamAssertSavableRole, iamUnreadablePolicy, iamUnreadableRole } from '../rows'
import { iamAssertAssignableScope } from '../scope'

describe('iamAssertAssignableScope', () => {
  it('IAM_SCOPE_INVALID reason "empty" for an empty string', () => {
    try {
      iamAssertAssignableScope('memory', '')
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_SCOPE_INVALID'>, 'IAM_SCOPE_INVALID')).toMatchObject({
        adapter: 'memory',
        reason: 'empty',
      })
    }
  })

  it('IAM_SCOPE_INVALID reason "wildcard-on-grant" for "*" on a grant', () => {
    try {
      iamAssertAssignableScope('memory', '*', 'grant')
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_SCOPE_INVALID'>, 'IAM_SCOPE_INVALID').reason).toBe('wildcard-on-grant')
    }
  })

  it('"*" is allowed on a lookup', () => {
    expect(() => iamAssertAssignableScope('memory', '*', 'lookup')).not.toThrow()
  })
})

describe('iamAssertAttributesParam', () => {
  it('IAM_ATTRIBUTES_INVALID reason "not-object" for a non-object', () => {
    try {
      iamAssertAttributesParam('memory', 'u1', 'not-an-object')
      expect.unreachable()
    } catch (err) {
      const meta = metaOf(err as IamError<'IAM_ATTRIBUTES_INVALID'>, 'IAM_ATTRIBUTES_INVALID')
      expect(meta).toMatchObject({ adapter: 'memory', subjectId: 'u1', reason: 'not-object' })
    }
  })

  it('IAM_ATTRIBUTES_INVALID reason "forbidden-key" for __proto__', () => {
    // An own `__proto__` property, as `JSON.parse` produces; the object-literal form (`{ __proto__: ... }`) sets the
    // prototype instead of creating an own key, so it would never reach `hasForbiddenAttributeKey`.
    const hostile: Record<string, unknown> = {}
    Object.defineProperty(hostile, '__proto__', {
      configurable: true,
      enumerable: true,
      value: { x: 1 },
      writable: true,
    })
    try {
      iamAssertAttributesParam('memory', 'u1', hostile)
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_ATTRIBUTES_INVALID'>, 'IAM_ATTRIBUTES_INVALID').reason).toBe('forbidden-key')
    }
  })
})

describe('iamAssertSavablePolicy / iamAssertSavableRole', () => {
  it('throws IAM_VALIDATION_FAILED (via the shared merge in Task 6) for an invalid policy', () => {
    expect(() => iamAssertSavablePolicy('memory', { id: 'p1' })).toThrow(IamError)
  })
})

describe('iamUnreadablePolicy / iamUnreadableRole', () => {
  it('returns (does not throw) an IamError the caller can throw or report', () => {
    const err = iamUnreadablePolicy('drizzle', 'p1', 'parse error')
    expect(err).toBeInstanceOf(IamError)
    expect(metaOf(err as IamError<'IAM_UNREADABLE_POLICY'>, 'IAM_UNREADABLE_POLICY')).toMatchObject({
      adapter: 'drizzle',
      policyId: 'p1',
      detail: 'parse error',
    })
  })

  it('role and policy stay distinct codes', () => {
    const err = iamUnreadableRole('drizzle', 'r1', 'parse error')
    expect((err as IamError).code).toBe('IAM_UNREADABLE_ROLE')
  })
})

describe('iamAssertNoAssignOptions / iamAssertValidAssignWindow', () => {
  it('IAM_ASSIGN_OPTIONS_UNSUPPORTED names every unsupported field', () => {
    try {
      iamAssertNoAssignOptions('memory', { startsAt: new Date(), expiresAt: new Date() })
      expect.unreachable()
    } catch (err) {
      expect(
        metaOf(err as IamError<'IAM_ASSIGN_OPTIONS_UNSUPPORTED'>, 'IAM_ASSIGN_OPTIONS_UNSUPPORTED').fields,
      ).toEqual(['startsAt', 'expiresAt'])
    }
  })

  it('IAM_ASSIGN_WINDOW_EMPTY for startsAt >= expiresAt', () => {
    const now = new Date()
    expect(() => iamAssertValidAssignWindow('drizzle', { startsAt: now, expiresAt: now })).toThrow(IamError)
  })

  it('IAM_ASSIGN_WINDOW_INVALID_DATE names the offending field', () => {
    try {
      iamAssertValidAssignWindow('drizzle', { startsAt: new Date('not-a-date') })
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_ASSIGN_WINDOW_INVALID_DATE'>, 'IAM_ASSIGN_WINDOW_INVALID_DATE').field).toBe(
        'startsAt',
      )
    }
  })
})

describe('iamUnknownRoleError preserves an optional cause', () => {
  it('with no cause', () => {
    const err = iamUnknownRoleError('memory') as IamError
    expect(err.cause).toBeUndefined()
    expect(metaOf(err as IamError<'IAM_ROLE_NOT_FOUND'>, 'IAM_ROLE_NOT_FOUND').adapter).toBe('memory')
  })

  it('with a driver cause, kept off the wire body', () => {
    const driverErr = new Error('FK violation: SQLSTATE 23503')
    const err = iamUnknownRoleError('drizzle', driverErr) as IamError
    expect(err.cause).toBe(driverErr)
    expect(JSON.stringify(err.toJSON())).not.toContain('23503')
    // An Error's message/.stack are non-enumerable, so JSON.stringify(driverErr) is always '{}' - the assertion
    // above would still pass even if toJSON() started spreading `cause` in next to code/status. Assert the key
    // itself is absent, not just that its text didn't happen to appear.
    expect(err.toJSON().error).not.toHaveProperty('cause')
  })
})
