import { describe, expect, it } from 'vitest'
import { BLOCKED_SEGMENTS, resolve } from '../../resolve/resolve'
import type { IamRequest } from '../../types'
import { validatePolicy } from '../validate'
import { isResolvablePath } from '../validate.libs'

// `isResolvablePath` flags conditions that can never fire, so it must refuse exactly what `resolve` refuses.
describe('isResolvablePath agrees with resolve about what will not resolve', () => {
  const REQUEST: IamRequest.IAccessRequest = {
    action: 'read',
    resource: { attributes: {}, type: 'doc' },
    subject: { attributes: {}, id: 'u', roles: [] },
  }

  const policyWith = (condition: Record<string, unknown>) => ({
    algorithm: 'deny-overrides',
    id: 'p',
    name: 'p',
    rules: [
      {
        actions: ['*'],
        conditions: { all: [condition] },
        effect: 'deny',
        id: 'd',
        priority: 100,
        resources: ['*'],
      },
    ],
  })

  const issuesFor = (condition: Record<string, unknown>, code: string) =>
    validatePolicy(policyWith(condition)).issues.filter((i) => i.code === code)

  const warnings = (field: string) => issuesFor({ field, operator: 'exists' }, 'UNRESOLVABLE_FIELD')

  it.each([...BLOCKED_SEGMENTS])('refuses %s at any segment', (segment) => {
    expect(isResolvablePath(`subject.${segment}`)).toBe(false)
    expect(isResolvablePath(`subject.${segment}.deeper`)).toBe(false)
    expect(isResolvablePath(`resource.attributes.${segment}`)).toBe(false)
  })

  it.each([...BLOCKED_SEGMENTS])('and resolve() answers null for %s, which is why', (segment) => {
    expect(resolve(REQUEST, `subject.${segment}`)).toBeNull()
    expect(resolve(REQUEST, `subject.${segment}.deeper`)).toBeNull()
  })

  it('validatePolicy now warns about a blocked segment, as it already did for a bad root', () => {
    expect(warnings('subject.__proto__.x')).toHaveLength(1)
    expect(warnings('subject.constructor.name')).toHaveLength(1)
    // The control that always worked.
    expect(warnings('sujbect.id')).toHaveLength(1)
  })

  it('the warning names the path and both reasons', () => {
    const message = warnings('subject.__proto__.x')[0]?.message ?? ''
    expect(message).toContain('subject.__proto__.x')
    expect(message).toContain('__proto__/constructor/prototype')
    expect(message).toContain('subject/resource/environment')
  })

  it('stays a warning, not an error - the policy is still storable', () => {
    const result = validatePolicy(policyWith({ field: 'subject.__proto__.x', operator: 'exists' }))
    expect(result.issues.find((i) => i.code === 'UNRESOLVABLE_FIELD')?.type).toBe('warning')
    expect(result.valid).toBe(true)
  })

  it('also covers a $-sourced comparison value, the other caller of the same predicate', () => {
    // A `$` operand runs through `isResolvablePath` too, but reports as `UNRESOLVABLE_VALUE`.
    const blocked = issuesFor(
      { field: 'subject.id', operator: 'eq', value: '$subject.__proto__.x' },
      'UNRESOLVABLE_VALUE',
    )
    expect(blocked).toHaveLength(1)
    expect(blocked[0]?.type).toBe('warning')

    // And the control: a $-value that does resolve stays quiet.
    expect(
      issuesFor({ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }, 'UNRESOLVABLE_VALUE'),
    ).toHaveLength(0)
  })

  it('still accepts every ordinary path, and the two shorthands', () => {
    for (const ok of [
      'subject.id',
      'subject.roles',
      'subject.attributes.dept',
      'resource.attributes.ownerId',
      'environment.ip',
      'action',
      'scope',
    ]) {
      expect({ ok, resolvable: isResolvablePath(ok) }).toEqual({ ok, resolvable: true })
      expect(warnings(ok)).toHaveLength(0)
    }
  })

  it('a segment that merely CONTAINS a blocked name is fine', () => {
    // Per whole segment, the way the resolver's `Set.has` is: `constructorName` is not `constructor`.
    expect(isResolvablePath('subject.attributes.constructorName')).toBe(true)
    expect(isResolvablePath('subject.attributes.my__proto__thing')).toBe(true)
  })
})
