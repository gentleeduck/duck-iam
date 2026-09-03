import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { MAX_CONDITION_DEPTH } from '../../conditions/conditions.libs'
import { IamEngine } from '../../engine/engine'
import type { AccessControl } from '../../types'
import { validatePolicy, validateRole } from '../validate'

/**
 * `validatePolicy` and `validateRole` are the boundary functions for untrusted
 * JSON: their contract is to *return* `{ valid: false, issues }`. Throwing means
 * `admin.import` and every adapter row loader propagate a raw `TypeError` with
 * no issue naming the bad row.
 */
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

  // `targets.actions: 'read'` already errors as INVALID_TYPE. Iterating it as a
  // list produced one UNREACHABLE_TARGET per character on top of that.
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

  // Control: the unreachable-target check still fires on a well-formed policy,
  // so the assertions above are not passing because the check is now inert.
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

/**
 * `validateRole` checked only that `perm.conditions` was an object. A permission
 * with an unknown operator therefore passed `admin.import` and threw at
 * evaluation - and the two engines catch that throw at different granularities,
 * so the same store denied in development and allowed in production.
 */
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

/**
 * OPEN, and deliberately not fixed here: validation closes the front door, but a
 * role reaching the engine through an adapter that does not validate - a
 * hand-edited file row, a redis or SQL row written by another service - still
 * decides differently in each mode. `safeEval` catches at whole-policy scope and
 * `rolesToPolicy` folds *every* role into the single `__rbac__` policy, so one
 * rotten permission drops every RBAC grant for that request; the compiled path
 * answers from the ROLE_MASK bit before it reaches the group that throws.
 *
 * Production is the one that is right: `good`'s grant is independent and should
 * not be voided by `rotten`'s malformed condition. Closing it means catching per
 * *rule* rather than per policy - the XACML Indeterminate-per-rule model - which
 * touches every policy and the `mayThrow` fast-path delegation, so it is its own
 * change. This test states the split rather than asserting a fix, so the day it
 * is closed this file goes red and gets updated.
 */
describe('residual: a throwing role permission is still handled at different granularities', () => {
  async function can(mode: 'development' | 'production') {
    const adapter = new IamMemoryAdapter({ assignments: { u1: ['rotten', 'good'] }, roles: [rotten, good] })
    const engine = new IamEngine({ adapter, cacheTTL: 0, hooks: { onPolicyError: vi.fn() }, mode })
    return await engine.can('u1', 'read', { attributes: {}, type: 'secret' })
  }

  it('production keeps the unrelated grant; development loses the whole RBAC policy', async () => {
    expect(await can('production')).toBe(true)
    expect(await can('development')).toBe(false)
  })
})

/**
 * `rolesToPolicy` splices an `all` body into the generated rule's own `all` but
 * nests any other group one level deeper, so the same tree crosses
 * `MAX_CONDITION_DEPTH` in one shape and not the other. `validateRole` must
 * agree with what the evaluator will actually match, in both shapes.
 */
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
    const engine = new IamEngine({ adapter, cacheTTL: 0, hooks: { onPolicyError: vi.fn() } })
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
