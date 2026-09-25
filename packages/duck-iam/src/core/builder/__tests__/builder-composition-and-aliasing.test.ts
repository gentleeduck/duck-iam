import { describe, expect, it } from 'vitest'
import { type IamError, metaOf } from '../../errors'
import { evaluate } from '../../evaluate/evaluate'
import type { AccessControl, IamPrimitives, IamRequest } from '../../types'
import { definePolicy } from '../policy'
import { defineRole } from '../role'
import { defineRule } from '../rule'

// A second `.when()` must AND with the first, not replace it.
describe('RuleBuilder: repeated condition groups', () => {
  const rule = defineRule('post.update')
    .allow()
    .on('update')
    .of('post')
    .when((w) => w.attr('department', 'eq', 'engineering'))
    .when((w) => w.attr('level', 'gte', 5))
    .build()

  function decide(attributes: IamPrimitives.Attributes): boolean {
    const policy: AccessControl.IPolicy = {
      algorithm: 'first-match',
      id: 'p',
      name: 'p',
      rules: [rule],
    }
    const request: IamRequest.IAccessRequest = {
      action: 'update',
      resource: { attributes: {}, type: 'post' },
      subject: { attributes, id: 'u1', roles: [] },
    }
    return evaluate([policy], request, 'deny', 'and').allowed
  }

  it('keeps both groups instead of dropping the first', () => {
    expect(decide({ department: 'engineering', level: 7 })).toBe(true)
  })

  it('denies when only the second group holds', () => {
    expect(decide({ department: 'sales', level: 7 })).toBe(false)
  })

  it('denies when only the first group holds', () => {
    expect(decide({ department: 'engineering', level: 1 })).toBe(false)
  })

  it('nests the earlier group rather than replacing it', () => {
    expect(rule.conditions).toEqual({
      all: [
        { all: [expect.objectContaining({ field: 'subject.attributes.department' })] },
        { all: [expect.objectContaining({ field: 'subject.attributes.level' })] },
      ],
    })
  })

  it('ANDs a whenAny group onto an earlier when group', () => {
    const mixed = defineRule('r')
      .allow()
      .on('read')
      .of('post')
      .when((w) => w.attr('a', 'eq', 1))
      .whenAny((w) => w.attr('b', 'eq', 2).attr('c', 'eq', 3))
      .build()
    expect(mixed.conditions).toEqual({
      all: [{ all: [expect.anything()] }, { any: [expect.anything(), expect.anything()] }],
    })
  })

  // Control: a single `.when()` must stay a flat group, not gain a wrapper.
  it('leaves a single group unwrapped', () => {
    const one = defineRule('r')
      .allow()
      .on('read')
      .of('post')
      .when((w) => w.attr('a', 'eq', 1))
      .build()
    expect(one.conditions).toEqual({ all: [expect.objectContaining({ field: 'subject.attributes.a' })] })
  })
})

describe('RuleBuilder.build() validates', () => {
  it('rejects a rule with an empty id', () => {
    expect(() => defineRule('').allow().on('read').of('post').build()).toThrow('IAM_VALIDATION_FAILED')
  })

  it('rejects a non-finite priority', () => {
    expect(() => defineRule('r').allow().priority(Number.NaN).on('read').of('post').build()).toThrow(
      'IAM_VALIDATION_FAILED',
    )
  })

  it('reports kind "rule", so a caller can tell a rule build failed from a policy or role build', () => {
    try {
      defineRule('bad-rule').allow().priority(Number.NaN).build()
      expect.unreachable()
    } catch (err) {
      expect(metaOf(err as IamError<'IAM_VALIDATION_FAILED'>, 'IAM_VALIDATION_FAILED').kind).toBe('rule')
    }
  })

  // Control: the ordinary path still builds.
  it('accepts a well-formed rule', () => {
    expect(defineRule('ok').allow().on('read').of('post').build().id).toBe('ok')
  })
})

// An empty scope must reach the validator, not widen into a global permission.
describe('RoleBuilder.grant with an empty scope', () => {
  it('does not silently produce a global permission', () => {
    expect(() => defineRole('r').grant('read', 'post', '').build()).toThrow('IAM_VALIDATION_FAILED')
  })

  it('matches grantScoped, which already threw', () => {
    expect(() => defineRole('r').grantScoped('', 'read', 'post').build()).toThrow('IAM_VALIDATION_FAILED')
  })

  // Control: an omitted scope is still a global permission.
  it('still treats an omitted scope as global', () => {
    const role = defineRole('r').grant('read', 'post').build()
    expect(role.permissions[0]).toEqual({ action: 'read', resource: 'post' })
  })

  it('still honours a real scope', () => {
    const role = defineRole('r').grant('read', 'post', 'org-1').build()
    expect(role.permissions[0]).toEqual({ action: 'read', resource: 'post', scope: 'org-1' })
  })
})

// A builder kept alive after `build()` must not mutate the already-validated result.
describe('build() returns copies, not live builder state', () => {
  it('RoleBuilder: a later grant does not reach the built role', () => {
    const builder = defineRole('r').grant('read', 'post')
    const role = builder.build()
    builder.grant('delete', 'post')
    expect(role.permissions).toHaveLength(1)
  })

  it('RoleBuilder: a later inherits does not reach the built role', () => {
    const builder = defineRole('r').grant('read', 'post').inherits('base')
    const role = builder.build()
    builder.inherits('admin')
    expect(role.inherits).toEqual(['base'])
  })

  it('PolicyBuilder: a later addRule does not reach the built policy', () => {
    const rule = defineRule('a').allow().on('read').of('post').build()
    const extra = defineRule('b').deny().on('read').of('post').build()
    const builder = definePolicy('p').addRule(rule)
    const policy = builder.build()
    builder.addRule(extra)
    expect(policy.rules).toHaveLength(1)
  })

  // Control: the rules that were present at build time are still there.
  it('keeps the state that existed when build() ran', () => {
    const rule = defineRule('a').allow().on('read').of('post').build()
    expect(definePolicy('p').addRule(rule).build().rules[0]?.id).toBe('a')
  })
})
