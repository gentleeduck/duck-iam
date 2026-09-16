import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { MAX_CONDITION_DEPTH } from '../../conditions/conditions.libs'
import { IamEngine } from '../../engine/engine'
import { evaluatePolicy } from '../../evaluate/evaluate'
import { rolesToPolicy } from '../../rbac/rbac'
import type { AccessControl } from '../../types'
import { validatePolicy, validateRole } from '../validate'

// Boundary validators return `{ valid: false, issues }`; a throw would reach `admin.import` as a bare `TypeError`.
describe('validatePolicy never throws on a malformed rule row', () => {
  it.each([
    ['a null rule', '{"id":"p","name":"P","algorithm":"deny-overrides","rules":[null],"targets":{"actions":["read"]}}'],
    [
      'a string rule',
      '{"id":"p","name":"P","algorithm":"deny-overrides","rules":["x"],"targets":{"actions":["read"]}}',
    ],
    ['a number rule', '{"id":"p","name":"P","algorithm":"deny-overrides","rules":[7],"targets":{"resources":["a"]}}'],
    ['an array rule', '{"id":"p","name":"P","algorithm":"deny-overrides","rules":[[]],"targets":{"actions":["read"]}}'],
  ])('returns issues for %s', (_label, json) => {
    const result = validatePolicy(JSON.parse(json))
    expect(result.valid).toBe(false)
    expect(result.issues.length).toBeGreaterThan(0)
  })

  // `targets.actions: 'read'` already errors as INVALID_TYPE; it must not add one UNREACHABLE_TARGET per character.
  it('does not iterate a non-array target dimension character by character', () => {
    const result = validatePolicy(
      JSON.parse(
        '{"id":"p","name":"P","algorithm":"deny-overrides","targets":{"actions":"read"},' +
          '"rules":[{"id":"r","effect":"allow","priority":1,"actions":["write"],"resources":["post"],"conditions":{"all":[]}}]}',
      ),
    )
    expect(result.valid).toBe(false)
    expect(result.issues.filter((i) => i.code === 'UNREACHABLE_TARGET')).toHaveLength(0)
    expect(result.issues.some((i) => i.code === 'INVALID_TYPE' && i.path === 'targets.actions')).toBe(true)
  })

  // Control: the check still fires on a well-formed policy, so the tests above aren't passing on an inert check.
  it('control: still reports a genuinely unreachable target', () => {
    const result = validatePolicy({
      algorithm: 'deny-overrides',
      id: 'p',
      name: 'P',
      rules: [
        { actions: ['write'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 1, resources: ['post'] },
      ],
      targets: { actions: ['read'] },
    })
    expect(result.issues.some((i) => i.code === 'UNREACHABLE_TARGET')).toBe(true)
  })
})

/** A permission condition with an unknown operator, which only a contents check catches before evaluation throws. */
const rotten: AccessControl.IRole = JSON.parse(
  '{"id":"rotten","name":"Rotten","permissions":[{"action":"read","resource":"secret",' +
    '"conditions":{"all":[{"field":"subject.id","operator":"BOGUS","value":"u1"}]}}]}',
)

const good: AccessControl.IRole = {
  id: 'good',
  name: 'Good',
  permissions: [{ action: 'read', resource: 'secret' }],
}

describe('validateRole checks permission condition contents', () => {
  it('rejects an unknown operator', () => {
    const result = validateRole(rotten)
    expect(result.valid).toBe(false)
    expect(result.issues.some((i) => i.code === 'INVALID_OPERATOR')).toBe(true)
  })

  it('rejects a condition with no field', () => {
    const role = JSON.parse(
      '{"id":"r","name":"R","permissions":[{"action":"read","resource":"s","conditions":{"all":[{"operator":"eq","value":1}]}}]}',
    )
    expect(validateRole(role).valid).toBe(false)
  })

  // Controls: a well-formed condition and an absent one must still pass.
  it('accepts a well-formed condition and an absent one', () => {
    expect(
      validateRole({
        id: 'r',
        name: 'R',
        permissions: [
          {
            action: 'read',
            conditions: { all: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] },
            resource: 's',
          },
        ],
      }).valid,
    ).toBe(true)
    expect(validateRole(good).valid).toBe(true)
  })

  it('is refused by the validated write API', async () => {
    const adapter = new IamMemoryAdapter({ roles: [] })
    const engine = new IamEngine({ adapter, cacheTTL: 0 })
    await expect(engine.admin.saveRole(rotten)).rejects.toThrow()
    expect(await adapter.listRoles()).toHaveLength(0)
  })
})

// NOTE: a throwing rule in the allow-only `__rbac__` union abstains (`rulesAbstainOnThrow`), so `good` keeps its grant.
// That is safe only there: an authored policy still fails closed at whole-policy scope.
describe('residual: a throwing role permission no longer splits the two modes', () => {
  async function can(mode: 'development' | 'production') {
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['rotten', 'good'] }, roles: [rotten, good] })
    const engine = new IamEngine({ adapter, cacheTTL: 0, hooks: { onPolicyError: vi.fn() }, mode })
    return await engine.can('u1', 'read', { attributes: {}, type: 'secret' })
  }

  it('both modes keep the unrelated grant', async () => {
    expect(await can('production')).toBe(true)
    expect(await can('development')).toBe(true)
  })

  // Abstaining still reports the throw. Tested on `evaluatePolicy` because `engine.can` answers `good`'s unconditional
  // grant from the mask bit without reaching the throwing group.
  it('hands the throw to the error handler before abstaining', () => {
    const seen: Error[] = []
    const decision = evaluatePolicy(
      rolesToPolicy([rotten, good], 'flat'),
      {
        action: 'read',
        resource: { attributes: {}, type: 'secret' },
        subject: { attributes: {}, id: 'u1', roles: ['rotten', 'good'] },
      },
      'deny',
      undefined,
      (err) => seen.push(err),
    )
    expect(decision.allowed).toBe(true)
    expect(decision.rule?.id).toBe('__rbac__#1')
    expect(seen).toHaveLength(1)
    expect(seen[0]?.message).toContain('BOGUS')
  })
})

// `validateRole` must agree with what the evaluator matches for a permission condition, whatever its group key.
describe('permission condition depth matches what the evaluator accepts', () => {
  /** A group nested `levels` deep under `key`, with one leaf at the bottom. */
  function nest(key: 'all' | 'any', levels: number): unknown {
    let node: unknown = { [key]: [{ field: 'subject.id', operator: 'eq', value: 'u1' }] }
    for (let i = 1; i < levels; i++) node = { [key]: [node] }
    return node
  }

  async function grants(conditions: unknown): Promise<boolean> {
    const role = JSON.parse(
      JSON.stringify({ id: 'r', name: 'R', permissions: [{ action: 'read', conditions, resource: 'secret' }] }),
    )
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['r'] }, roles: [role] })
    // Pinned to development (the default is production): `validateRole` is written against the development evaluator.
    const engine = new IamEngine({ adapter, cacheTTL: 0, hooks: { onPolicyError: vi.fn() }, mode: 'development' })
    return await engine.can('u1', 'read', { attributes: {}, type: 'secret' })
  }

  it.each(['all', 'any'] as const)('for a %s group at and past the boundary', async (key) => {
    for (const levels of [MAX_CONDITION_DEPTH - 2, MAX_CONDITION_DEPTH - 1, MAX_CONDITION_DEPTH]) {
      const conditions = nest(key, levels)
      const role = JSON.parse(
        JSON.stringify({ id: 'r', name: 'R', permissions: [{ action: 'read', conditions, resource: 'secret' }] }),
      )
      expect(validateRole(role).valid, `${key} @ ${levels}`).toBe(await grants(conditions))
    }
  })
})
