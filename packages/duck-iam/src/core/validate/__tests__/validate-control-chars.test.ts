import { describe, expect, it } from 'vitest'
import { validatePolicy, validateRole } from '../validate'

const NUL = String.fromCharCode(0)

function policyWith(actions: string[], resources: string[]): unknown {
  return {
    algorithm: 'deny-overrides',
    id: 'p1',
    name: 'p1',
    rules: [{ actions, conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 1, resources }],
  }
}

function actionIssues(result: ReturnType<typeof validatePolicy>): string[] {
  return result.issues.filter((i) => (i.path ?? '').startsWith('rules[0].actions')).map((i) => i.message)
}

function resourceIssues(result: ReturnType<typeof validatePolicy>): string[] {
  return result.issues.filter((i) => (i.path ?? '').startsWith('rules[0].resources')).map((i) => i.message)
}

// SECURITY: a control character is invisible in a UI, so a reviewer sees `read` while the engine matches another name.
describe('validatePolicy rejects control characters in action and resource names', () => {
  it('rejects a NUL in an action', () => {
    const result = validatePolicy(policyWith([`read${NUL}post`], ['post']))
    expect(result.valid).toBe(false)
    expect(actionIssues(result)).toContain('Action must not contain control characters')
  })

  it('rejects a NUL in a resource', () => {
    const result = validatePolicy(policyWith(['read'], [`post${NUL}x`]))
    expect(result.valid).toBe(false)
    expect(resourceIssues(result)).toContain('Resource must not contain control characters')
  })

  it.each([
    ['newline', '\n'],
    ['carriage return', '\r'],
    ['tab', '\t'],
    ['escape', String.fromCharCode(27)],
    ['delete', String.fromCharCode(127)],
  ])('rejects a %s in an action', (_label, ch) => {
    expect(validatePolicy(policyWith([`read${ch}`], ['post'])).valid).toBe(false)
  })

  it('reports the offending index', () => {
    const result = validatePolicy(policyWith(['read', `write${NUL}`], ['post']))
    expect(result.issues.some((i) => i.path === 'rules[0].actions[1]')).toBe(true)
    expect(result.issues.some((i) => i.path === 'rules[0].actions[0]')).toBe(false)
  })

  // Controls: the check must not reject the names real policies use, or every
  // assertion above would pass on a validator that rejects everything.
  it.each([['read'], ['*'], ['post.comment'], ['org:member'], ['@scope'], ['résumé'], ['読む']])(
    'still accepts %j',
    (name) => {
      expect(validatePolicy(policyWith([name], [name])).valid).toBe(true)
    },
  )
})

// The role path: NUL is redis's assignment separator, and permission names become rule `actions` / `resources`.
describe('validateRole rejects control characters too', () => {
  function roleWith(over: Record<string, unknown>): unknown {
    return { id: 'r1', name: 'R', permissions: [{ action: 'read', resource: 'post' }], ...over }
  }

  it('a clean role is accepted - the control', () => {
    expect(validateRole(roleWith({})).valid).toBe(true)
  })

  it('rejects a NUL in the role id', () => {
    const result = validateRole(roleWith({ id: `admin${NUL}` }))
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => (i.path ?? '') === 'id')).toBe(true)
  })

  it('rejects a NUL in a permission action', () => {
    const result = validateRole(roleWith({ permissions: [{ action: `read${NUL}`, resource: 'post' }] }))
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => (i.path ?? '').startsWith('permissions[0].action'))).toBe(true)
  })

  it('rejects a NUL in a permission resource', () => {
    const result = validateRole(roleWith({ permissions: [{ action: 'read', resource: `post${NUL}x` }] }))
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => (i.path ?? '').startsWith('permissions[0].resource'))).toBe(true)
  })

  it.each([1, 8, 9, 10, 13, 27, 31, 127])('rejects control character %i wherever it appears', (code) => {
    const ch = String.fromCharCode(code)
    expect(validateRole(roleWith({ id: `admin${ch}` })).valid).toBe(false)
    expect(validateRole(roleWith({ permissions: [{ action: `read${ch}`, resource: 'post' }] })).valid).toBe(false)
    expect(validateRole(roleWith({ permissions: [{ action: 'read', resource: `post${ch}` }] })).valid).toBe(false)
  })

  it('accepts ordinary names that merely look unusual', () => {
    // Anti-vacuity: a check that refused every id would satisfy the rows above.
    for (const name of ['admin', 'org:admin', 'a-b_c.d', 'rôle', '管理者']) {
      expect(validateRole(roleWith({ id: name })).valid).toBe(true)
      expect(validateRole(roleWith({ permissions: [{ action: name, resource: name }] })).valid).toBe(true)
    }
  })
})
