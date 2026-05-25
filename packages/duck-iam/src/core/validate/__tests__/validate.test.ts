import { describe, expect, it } from 'vitest'
import type { MAX_INHERITANCE_DEPTH } from '../..'
import type { AccessControl } from '../../types'
import { validatePolicy, validateRole, validateRoles } from '../validate'
import { detectCatastrophicRegex } from '../validate.libs'

describe('validateRoles()', () => {
  it('valid roles return valid=true', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
      { id: 'editor', name: 'Editor', inherits: ['viewer'], permissions: [{ action: 'write', resource: 'post' }] },
    ]
    const result = validateRoles(roles)
    expect(result.valid).toBe(true)
    expect(result.issues.filter((i) => i.type === 'error')).toHaveLength(0)
  })

  it('detects duplicate role IDs', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'viewer', name: 'Viewer', permissions: [] },
      { id: 'viewer', name: 'Viewer 2', permissions: [] },
    ]
    const result = validateRoles(roles)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'DUPLICATE_ROLE_ID')).toBe(true)
  })

  it('detects dangling inherits references', () => {
    const roles: AccessControl.IRole[] = [{ id: 'editor', name: 'Editor', inherits: ['nonexistent'], permissions: [] }]
    const result = validateRoles(roles)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'DANGLING_INHERIT')).toBe(true)
  })

  it('detects circular inheritance (warning)', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'a', name: 'A', inherits: ['b'], permissions: [{ action: 'read', resource: 'post' }] },
      { id: 'b', name: 'B', inherits: ['a'], permissions: [{ action: 'write', resource: 'post' }] },
    ]
    const result = validateRoles(roles)
    expect(result.valid).toBe(true) // warnings don't make it invalid
    expect(result.issues.some((i) => i.code === 'CIRCULAR_INHERIT')).toBe(true)
  })

  it('warns about empty roles (no permissions, no inheritance)', () => {
    const roles: AccessControl.IRole[] = [{ id: 'empty', name: 'Empty', permissions: [] }]
    const result = validateRoles(roles)
    expect(result.issues.some((i) => i.code === 'EMPTY_ROLE')).toBe(true)
  })

  it('does not warn about roles with inheritance but no permissions', () => {
    const roles: AccessControl.IRole[] = [
      { id: 'viewer', name: 'Viewer', permissions: [{ action: 'read', resource: 'post' }] },
      { id: 'inheritor', name: 'Inheritor', inherits: ['viewer'], permissions: [] },
    ]
    const result = validateRoles(roles)
    expect(result.issues.some((i) => i.code === 'EMPTY_ROLE')).toBe(false)
  })
})

describe('validatePolicy()', () => {
  const validPolicy = {
    id: 'p1',
    name: 'Test AccessControl.IPolicy',
    algorithm: 'deny-overrides',
    rules: [
      {
        id: 'r1',
        effect: 'allow',
        priority: 10,
        actions: ['read'],
        resources: ['post'],
        conditions: { all: [] },
      },
    ],
  }

  it('validates a correct policy', () => {
    const result = validatePolicy(validPolicy)
    expect(result.valid).toBe(true)
    expect(result.issues.filter((i) => i.type === 'error')).toHaveLength(0)
  })

  it('rejects non-object input', () => {
    expect(validatePolicy(null).valid).toBe(false)
    expect(validatePolicy('string').valid).toBe(false)
    expect(validatePolicy([]).valid).toBe(false)
    expect(validatePolicy(42).valid).toBe(false)
  })

  it('rejects missing id', () => {
    const result = validatePolicy({ ...validPolicy, id: '' })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'MISSING_FIELD' && i.path === 'id')).toBe(true)
  })

  it('rejects missing name', () => {
    const result = validatePolicy({ ...validPolicy, name: '' })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'MISSING_FIELD' && i.path === 'name')).toBe(true)
  })

  it('rejects invalid algorithm', () => {
    const result = validatePolicy({ ...validPolicy, algorithm: 'invalid' })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_ALGORITHM')).toBe(true)
  })

  it('accepts all valid algorithms', () => {
    for (const algo of ['deny-overrides', 'allow-overrides', 'first-match', 'highest-priority']) {
      const result = validatePolicy({ ...validPolicy, algorithm: algo })
      expect(result.valid).toBe(true)
    }
  })

  it('rejects missing rules', () => {
    const { rules, ...noRules } = validPolicy
    const result = validatePolicy(noRules)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'MISSING_FIELD' && i.path === 'rules')).toBe(true)
  })

  it('rejects invalid rule effect', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [{ ...validPolicy.rules[0], effect: 'maybe' }],
    })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_EFFECT')).toBe(true)
  })

  it('rejects invalid rule priority type', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [{ ...validPolicy.rules[0], priority: 'high' }],
    })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_TYPE' && i.path?.includes('priority'))).toBe(true)
  })

  it('rejects empty actions array', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [{ ...validPolicy.rules[0], actions: [] }],
    })
    expect(result.valid).toBe(false)
  })

  it('rejects non-string actions', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [{ ...validPolicy.rules[0], actions: [123] }],
    })
    expect(result.valid).toBe(false)
  })

  it('rejects empty resources array', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [{ ...validPolicy.rules[0], resources: [] }],
    })
    expect(result.valid).toBe(false)
  })

  it('validates condition operators', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [
        {
          ...validPolicy.rules[0],
          conditions: { all: [{ field: 'action', operator: 'invalid_op', value: 'x' }] },
        },
      ],
    })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_OPERATOR')).toBe(true)
  })

  it('validates condition group structure', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [
        {
          ...validPolicy.rules[0],
          conditions: { invalid: [] },
        },
      ],
    })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_CONDITION')).toBe(true)
  })

  it('warns about duplicate rule IDs', () => {
    const result = validatePolicy({
      ...validPolicy,
      rules: [validPolicy.rules[0], validPolicy.rules[0]],
    })
    expect(result.issues.some((i) => i.code === 'DUPLICATE_RULE_ID')).toBe(true)
  })

  it('validates targets if provided', () => {
    const result = validatePolicy({
      ...validPolicy,
      targets: 'invalid',
    })
    expect(result.valid).toBe(false)
  })

  it('validates targets.actions must be array', () => {
    const result = validatePolicy({
      ...validPolicy,
      targets: { actions: 'not-an-array' },
    })
    expect(result.valid).toBe(false)
  })

  it('rejects invalid version type', () => {
    const result = validatePolicy({ ...validPolicy, version: 'one' })
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_TYPE' && i.path === 'version')).toBe(true)
  })

  it('accepts numeric version', () => {
    const result = validatePolicy({ ...validPolicy, version: 2 })
    expect(result.valid).toBe(true)
  })

  it('warns on unresolvable condition field (silent-null at runtime)', () => {
    // A condition.field that doesn't start with subject/resource/environment
    // (or action/scope shorthand) silently resolves to null at runtime,
    // which means the rule never matches. Surface as warning at validate time.
    const policy = {
      ...validPolicy,
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [{ field: 'user.attributes.role', operator: 'eq', value: 'admin' }] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.issues.some((i) => i.code === 'UNRESOLVABLE_FIELD')).toBe(true)
  })

  it('warns on unresolvable $-prefixed condition value', () => {
    const policy = {
      ...validPolicy,
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$user.id' }] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.issues.some((i) => i.code === 'UNRESOLVABLE_VALUE')).toBe(true)
  })

  it('accepts resolvable shorthand condition fields (action, scope)', () => {
    const policy = {
      ...validPolicy,
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [{ field: 'action', operator: 'eq', value: 'read' }] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.issues.some((i) => i.code === 'UNRESOLVABLE_FIELD')).toBe(false)
  })

  it('rejects rule with too many actions (DoS bound)', () => {
    const policy = {
      ...validPolicy,
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: Array.from({ length: 101 }, (_, i) => `a${i}`),
          resources: ['post'],
          conditions: { all: [] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'LIMIT_EXCEEDED' && i.path?.endsWith('actions'))).toBe(true)
  })

  it('rejects rule with too many resources (DoS bound)', () => {
    const policy = {
      ...validPolicy,
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: Array.from({ length: 101 }, (_, i) => `r${i}`),
          conditions: { all: [] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'LIMIT_EXCEEDED' && i.path?.endsWith('resources'))).toBe(true)
  })

  it('rejects rule with too-large actionxresource cartesian', () => {
    // 50 x 50 = 2500 > 1000 cartesian cap.
    const policy = {
      ...validPolicy,
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: Array.from({ length: 50 }, (_, i) => `a${i}`),
          resources: Array.from({ length: 50 }, (_, i) => `r${i}`),
          conditions: { all: [] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'LIMIT_EXCEEDED' && i.message.includes('cartesian'))).toBe(true)
  })

  it('rejects policy with too many rules', () => {
    const policy = {
      ...validPolicy,
      rules: Array.from({ length: 1001 }, (_, i) => ({
        id: `r${i}`,
        effect: 'allow',
        priority: 10,
        actions: ['read'],
        resources: ['post'],
        conditions: { all: [] },
      })),
    }
    const result = validatePolicy(policy)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'LIMIT_EXCEEDED' && i.path === 'rules')).toBe(true)
  })

  it('warns on overly broad allow (*/*/no conditions)', () => {
    const policy = {
      ...validPolicy,
      rules: [
        {
          id: 'r-broad',
          effect: 'allow',
          priority: 10,
          actions: ['*'],
          resources: ['*'],
          conditions: { all: [] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.issues.some((i) => i.code === 'BROAD_ALLOW')).toBe(true)
    // Warning, not error - broad-allow may be intentional (super-admin).
    expect(result.valid).toBe(true)
  })

  it('does not warn on broad allow when conditions narrow it', () => {
    const policy = {
      ...validPolicy,
      rules: [
        {
          id: 'r-conditional-broad',
          effect: 'allow',
          priority: 10,
          actions: ['*'],
          resources: ['*'],
          conditions: { all: [{ field: 'subject.attributes.admin', operator: 'eq', value: true }] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.issues.some((i) => i.code === 'BROAD_ALLOW')).toBe(false)
  })
})

describe('validateRoles() - inheritance depth', () => {
  it('errors when inheritance chain exceeds MAX_INHERITANCE_DEPTH', async () => {
    const { MAX_INHERITANCE_DEPTH } = await import('../../rbac')
    const { validateRoles } = await import('../validate')
    const roles: AccessControl.IRole[] = []
    for (let i = 0; i <= MAX_INHERITANCE_DEPTH + 1; i++) {
      roles.push({
        id: `r${i}`,
        name: `R${i}`,
        permissions: [],
        ...(i > 0 ? { inherits: [`r${i - 1}`] } : {}),
      })
    }
    const result = validateRoles(roles)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INHERITANCE_TOO_DEEP')).toBe(true)
  })

  it('accepts inheritance chain at exactly MAX_INHERITANCE_DEPTH', async () => {
    const { MAX_INHERITANCE_DEPTH } = await import('../../rbac')
    const { validateRoles } = await import('../validate')
    const roles: AccessControl.IRole[] = []
    for (let i = 0; i <= MAX_INHERITANCE_DEPTH; i++) {
      roles.push({
        id: `r${i}`,
        name: `R${i}`,
        permissions: [],
        ...(i > 0 ? { inherits: [`r${i - 1}`] } : {}),
      })
    }
    const result = validateRoles(roles)
    expect(result.issues.some((i) => i.code === 'INHERITANCE_TOO_DEEP')).toBe(false)
  })
})

describe('condition validator bounds (H1, H2)', () => {
  it('refuses condition fields longer than MAX_FIELD_LENGTH', () => {
    const longField = `subject.${'a'.repeat(300)}`
    const policy: AccessControl.IPolicy = {
      id: 'p',
      name: 'P',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r',
          effect: 'allow',
          priority: 0,
          actions: ['read'],
          resources: ['post'],
          conditions: { all: [{ field: longField, operator: 'eq', value: 'x' }] },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.issues.some((i) => i.code === 'LIMIT_EXCEEDED' && (i.path ?? '').endsWith('.field'))).toBe(true)
  })

  it('refuses condition trees nested beyond MAX_CONDITION_DEPTH', () => {
    let group: AccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'eq', value: 'u' }],
    }
    for (let i = 0; i < 15; i++) group = { all: [group] }
    const policy: AccessControl.IPolicy = {
      id: 'p',
      name: 'P',
      algorithm: 'deny-overrides',
      rules: [{ id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['post'], conditions: group }],
    }
    const result = validatePolicy(policy)
    expect(result.issues.some((i) => i.code === 'LIMIT_EXCEEDED' && i.message.includes('nesting'))).toBe(true)
  })

  it('accepts trees at MAX_CONDITION_DEPTH', () => {
    let group: AccessControl.IConditionGroup = {
      all: [{ field: 'subject.id', operator: 'eq', value: 'u' }],
    }
    for (let i = 0; i < 5; i++) group = { all: [group] }
    const policy: AccessControl.IPolicy = {
      id: 'p',
      name: 'P',
      algorithm: 'deny-overrides',
      rules: [{ id: 'r', effect: 'allow', priority: 0, actions: ['read'], resources: ['post'], conditions: group }],
    }
    const result = validatePolicy(policy)
    expect(result.issues.some((i) => i.code === 'LIMIT_EXCEEDED' && i.message.includes('nesting'))).toBe(false)
  })
})

describe('validateRole() - single-row guard (P0)', () => {
  it('accepts a minimal valid role', () => {
    const result = validateRole({ id: 'viewer', name: 'Viewer', permissions: [] })
    expect(result.valid).toBe(true)
    expect(result.issues).toHaveLength(0)
  })

  it('accepts a role with inherits as an array of strings', () => {
    const result = validateRole({ id: 'editor', name: 'E', permissions: [], inherits: ['viewer'] })
    expect(result.valid).toBe(true)
  })

  it('rejects non-object input', () => {
    expect(validateRole(null).valid).toBe(false)
    expect(validateRole(42).valid).toBe(false)
    expect(validateRole([]).valid).toBe(false)
    expect(validateRole('string').valid).toBe(false)
  })

  it('rejects missing or empty id', () => {
    expect(validateRole({ permissions: [] }).valid).toBe(false)
    expect(validateRole({ id: '', permissions: [] }).valid).toBe(false)
    expect(validateRole({ id: 7, permissions: [] }).valid).toBe(false)
  })

  it('rejects missing permissions array', () => {
    const r = validateRole({ id: 'r' })
    expect(r.valid).toBe(false)
    expect(r.issues.some((i) => i.path === 'permissions')).toBe(true)
  })

  it('rejects non-string entries in inherits', () => {
    const r = validateRole({ id: 'r', permissions: [], inherits: ['ok', 5] })
    expect(r.valid).toBe(false)
    expect(r.issues.some((i) => i.path === 'inherits[1]')).toBe(true)
  })

  it('rejects non-array inherits', () => {
    const r = validateRole({ id: 'r', permissions: [], inherits: 'viewer' })
    expect(r.valid).toBe(false)
  })
})

describe('detectCatastrophicRegex() (P1)', () => {
  it('flags nested quantifier `(a+)+$`', () => {
    const r = detectCatastrophicRegex('(a+)+$')
    expect(r.safe).toBe(false)
    expect(r.reason).toMatch(/nested quantifier/i)
  })

  it('flags nested quantifier variants `(a*)*`, `(a+)*`, `(a*)+`', () => {
    for (const pat of ['(a*)*', '(a+)*', '(a*)+']) {
      expect(detectCatastrophicRegex(pat).safe).toBe(false)
    }
  })

  it('flags alternation inside a quantified group', () => {
    const r = detectCatastrophicRegex('(foo|bar)+')
    expect(r.safe).toBe(false)
    expect(r.reason).toMatch(/alternation/i)
  })

  it('flags patterns with more than 4 unbounded quantifiers', () => {
    const r = detectCatastrophicRegex('a+b+c+d+e+f+')
    expect(r.safe).toBe(false)
    expect(r.reason).toMatch(/unbounded quantifiers/i)
  })

  it('accepts safe anchored literals', () => {
    expect(detectCatastrophicRegex('^hello$').safe).toBe(true)
    expect(detectCatastrophicRegex('^[a-z0-9_-]+$').safe).toBe(true)
    expect(detectCatastrophicRegex('^user-\\d{1,8}$').safe).toBe(true)
  })

  it('accepts simple character-class patterns under quantifier limit', () => {
    // 3 unbounded quantifiers — under the limit of 4.
    expect(detectCatastrophicRegex('[a-z]+@[a-z]+\\.[a-z]+').safe).toBe(true)
  })

  it('rejects patterns exceeding MAX_REGEX_LENGTH', () => {
    const r = detectCatastrophicRegex('a'.repeat(200))
    expect(r.safe).toBe(false)
    expect(r.reason).toMatch(/MAX_REGEX_LENGTH/)
  })

  it('does not mistake escaped quantifiers in a group body for nested quantifiers', () => {
    // The body `\+` is a literal plus; the outer `+` quantifies the group.
    // No real nested quantifier here.
    expect(detectCatastrophicRegex('(\\+)+').safe).toBe(true)
  })

  it('flags backreference followed by `+` quantifier (SEC-020)', () => {
    const r = detectCatastrophicRegex('(\\w+)\\1+')
    expect(r.safe).toBe(false)
    expect(r.reason).toBe('backref-quantifier')
  })

  it('flags `(.*)\\1+` backreference + quantifier (SEC-020)', () => {
    const r = detectCatastrophicRegex('(.*)\\1+')
    expect(r.safe).toBe(false)
    expect(r.reason).toBe('backref-quantifier')
  })

  it('flags named backreference `(?<name>\\w+)\\k<name>+` (SEC-020)', () => {
    const r = detectCatastrophicRegex('(?<name>\\w+)\\k<name>+')
    expect(r.safe).toBe(false)
    expect(r.reason).toBe('backref-quantifier')
  })

  it('flags `a{1,1000000}` bounded-large quantifier (SEC-020)', () => {
    const r = detectCatastrophicRegex('a{1,1000000}')
    expect(r.safe).toBe(false)
    expect(r.reason).toBe('bounded-large-quantifier')
  })

  it('accepts `a{1,1000}` (at the threshold) (SEC-020)', () => {
    expect(detectCatastrophicRegex('a{1,1000}').safe).toBe(true)
  })

  it('flags `(?=(a+)+)` lookaround containing a quantifier (SEC-020)', () => {
    const r = detectCatastrophicRegex('(?=(a+)+)')
    expect(r.safe).toBe(false)
    expect(r.reason).toBe('lookaround-with-quantifier')
  })

  it('flags `(?<=(a*)*)` lookbehind containing a quantifier (SEC-020)', () => {
    const r = detectCatastrophicRegex('(?<=(a*)*)')
    expect(r.safe).toBe(false)
    expect(r.reason).toBe('lookaround-with-quantifier')
  })

  it('accepts `(?<=foo)` lookbehind without inner quantifier (SEC-020)', () => {
    expect(detectCatastrophicRegex('(?<=foo)').safe).toBe(true)
  })
})

describe('validatePolicy() rejects catastrophic matches patterns (P1)', () => {
  it('flags a rule whose `matches` condition is catastrophic', () => {
    const policy = {
      id: 'p-redos',
      name: 'ReDoS',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: {
            all: [{ field: 'subject.id', operator: 'matches', value: '(a+)+$' }],
          },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'ERR_REGEX_CATASTROPHIC')).toBe(true)
  })

  it('accepts a rule whose `matches` condition is a safe anchored literal', () => {
    const policy = {
      id: 'p-safe',
      name: 'Safe',
      algorithm: 'deny-overrides',
      rules: [
        {
          id: 'r1',
          effect: 'allow',
          priority: 10,
          actions: ['read'],
          resources: ['post'],
          conditions: {
            all: [{ field: 'subject.id', operator: 'matches', value: '^user-[a-z0-9]+$' }],
          },
        },
      ],
    }
    const result = validatePolicy(policy)
    expect(result.issues.filter((i) => i.code === 'ERR_REGEX_CATASTROPHIC')).toHaveLength(0)
  })
})
