import { describe, expect, it } from 'vitest'
import { rolesToPolicy } from '../../rbac'
import type { AccessControl } from '../../types'
import { validateRole } from '../../validate'
import { matchesScope } from '../resolve'

// `undefined` / `null` / `'*'` are global; every other string, `''` included, is an ordinary scope value.
describe('matchesScope treats an empty scope as a value, not a wildcard', () => {
  it.each([
    [undefined, 'org-1'],
    [null, 'org-1'],
    ['*', 'org-1'],
    [undefined, undefined],
    ['*', undefined],
  ])('global pattern %s matches scope %s', (pattern, scope) => {
    expect(matchesScope(pattern, scope)).toBe(true)
  })

  it('an empty pattern no longer matches every scope', () => {
    expect(matchesScope('', 'org-1')).toBe(false)
    expect(matchesScope('', 'org-2')).toBe(false)
    expect(matchesScope('', undefined)).toBe(false)
  })

  it('an empty pattern still matches an empty scope exactly', () => {
    expect(matchesScope('', '')).toBe(true)
  })

  it('a scoped pattern needs an exact scope', () => {
    expect(matchesScope('org-1', 'org-1')).toBe(true)
    expect(matchesScope('org-1', 'org-2')).toBe(false)
    expect(matchesScope('org-1', undefined)).toBe(false)
    expect(matchesScope('org-1', '')).toBe(false)
  })
})

// `matchesScope` only documents the contract; `rolesToPolicy`'s scope condition and the compiled table's
// comparison enforce it, so they are pinned too.
function scopeConditionValue(policy: AccessControl.IPolicy): string | undefined {
  const group = policy.rules[0]?.conditions
  if (group === undefined || !('all' in group)) throw new Error('expected an `all` group')
  for (const item of group.all) {
    if ('field' in item && item.field === 'scope') return typeof item.value === 'string' ? item.value : undefined
  }
  return undefined
}

const emptyScopedRole: AccessControl.IRole = {
  id: 'r',
  name: 'R',
  permissions: [{ action: 'read', resource: 'post' }],
  scope: '',
}

describe('rolesToPolicy enforces the same contract', () => {
  it('emits a scope condition for an empty role scope', () => {
    expect(scopeConditionValue(rolesToPolicy([emptyScopedRole]))).toBe('')
  })

  it('emits one for an empty permission scope too', () => {
    const role: AccessControl.IRole = {
      id: 'r',
      name: 'R',
      permissions: [{ action: 'read', resource: 'post', scope: '' }],
    }
    expect(scopeConditionValue(rolesToPolicy([role]))).toBe('')
  })

  // The two global markers, for contrast: these are the only values that mean
  // "every scope", and they emit no condition at all.
  it.each([undefined, '*'])('emits no scope condition for %s', (scope) => {
    const role: AccessControl.IRole = { id: 'r', name: 'R', permissions: [{ action: 'read', resource: 'post' }], scope }
    expect(scopeConditionValue(rolesToPolicy([role]))).toBeUndefined()
  })
})

describe('validateRole refuses an empty scope on either level', () => {
  it('rejects a role-level empty scope', () => {
    const result = validateRole(emptyScopedRole)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.path === 'scope' && i.type === 'error')).toBe(true)
  })

  it('rejects a permission-level empty scope', () => {
    const result = validateRole({
      id: 'r',
      name: 'R',
      permissions: [{ action: 'read', resource: 'post', scope: '' }],
    })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.path === 'permissions[0].scope' && i.type === 'error')).toBe(true)
  })

  // Control: the rejections above are about `''`, not scope validation refusing everything.
  it.each([undefined, '*'])('accepts %s', (scope) => {
    expect(validateRole({ id: 'r', name: 'R', permissions: [{ action: 'read', resource: 'post' }], scope }).valid).toBe(
      true,
    )
  })
})
