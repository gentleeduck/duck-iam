import { describe, expect, it } from 'vitest'
import { validateRole } from '../validate'

const base = { id: 'r1', name: 'R1' }
const bad = (permissions: unknown) => validateRole({ ...base, permissions })

describe('validateRole: permission entry shape', () => {
  it('accepts a well-formed permission', () => {
    expect(bad([{ action: 'read', resource: 'post' }]).valid).toBe(true)
    expect(bad([{ action: '*', resource: '*', scope: 'org-1' }]).valid).toBe(true)
    expect(bad([]).valid).toBe(true)
  })

  it.each([
    ['null entry', [null]],
    ['array entry', [['read', 'post']]],
    ['string entry', ['read:post']],
    ['empty object', [{}]],
    ['missing resource', [{ action: 'read' }]],
    ['missing action', [{ resource: 'post' }]],
    ['numeric action', [{ action: 1, resource: 'post' }]],
    ['empty-string action', [{ action: '', resource: 'post' }]],
    ['non-string scope', [{ action: 'read', resource: 'post', scope: 7 }]],
    ['empty-string scope', [{ action: 'read', resource: 'post', scope: '' }]],
    ['non-object conditions', [{ action: 'read', resource: 'post', conditions: 'yes' }]],
  ])('rejects %s', (_label, permissions) => {
    const result = bad(permissions)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.type === 'error' && i.path?.startsWith('permissions['))).toBe(true)
  })

  it('reports the offending index', () => {
    const result = bad([{ action: 'read', resource: 'post' }, { action: 'read' }])
    expect(result.issues.some((i) => i.path === 'permissions[1].resource')).toBe(true)
  })
})
