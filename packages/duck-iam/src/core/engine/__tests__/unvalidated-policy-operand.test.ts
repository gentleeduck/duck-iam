import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamOperandTypeError } from '../../conditions/conditions.libs'
import type { AccessControl } from '../../types'
import { IamEngine } from '../index'

// `loadPolicies` does not validate, so a policy seeded past `validatePolicy` reaches evaluation intact.
// Pins that such a policy still cannot over-grant; `validate/__tests__/operand-type-matrix` pins the operators.
type Action = 'read'
type Res = 'post'

/** `allow` unless the subject is on the denylist - with the operand typo. */
const TYPOED_DENYLIST = {
  algorithm: 'deny-overrides',
  id: 'p-denylist',
  name: 'allow unless banned',
  rules: [
    {
      actions: ['read'],
      // `'banned'`, not `['banned']`: an OPERAND_TYPE_MISMATCH the validator never sees on this path.
      conditions: { all: [{ field: 'subject.attributes.tier', operator: 'nin', value: 'banned' }] },
      effect: 'allow',
      id: 'r-allow-unless-banned',
      priority: 1,
      resources: ['post'],
    },
  ],
  // The cast is the point: the typed surface cannot express an operand the operator does not accept.
} as unknown as AccessControl.IPolicy<Action, Res, string>

/** The same policy, authored correctly. */
const CORRECT_DENYLIST: AccessControl.IPolicy<Action, Res, string> = {
  algorithm: 'deny-overrides',
  id: 'p-denylist',
  name: 'allow unless banned',
  rules: [
    {
      actions: ['read'],
      conditions: { all: [{ field: 'subject.attributes.tier', operator: 'nin', value: ['banned'] }] },
      effect: 'allow',
      id: 'r-allow-unless-banned',
      priority: 1,
      resources: ['post'],
    },
  ],
}

function engineWith(
  policy: AccessControl.IPolicy<Action, Res, string>,
  onPolicyError?: (e: Error, id: string) => void,
): IamEngine<Action, Res, string, string> {
  return new IamEngine<Action, Res, string, string>({
    adapter: new IamMemoryAdapter<Action, Res, string, string>({
      attributes: { banned: { tier: 'banned' }, ok: { tier: 'gold' } },
      policies: [policy],
    }),
    ...(onPolicyError ? { hooks: { onPolicyError } } : {}),
  })
}

describe('a policy that never passed the validator still cannot over-grant', () => {
  it('a seeded denylist with a non-array operand does not admit the banned subject', async () => {
    // Reachable from the documented seeding API alone, with nothing hand-edited.
    const engine = engineWith(TYPOED_DENYLIST)
    expect(await engine.can('banned', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('and does not admit the subject the denylist was not about either', async () => {
    // The rule is the only grant, so once it cannot be evaluated nobody gets through: Indeterminate fails closed.
    const engine = engineWith(TYPOED_DENYLIST)
    expect(await engine.can('ok', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('reports the refusal rather than swallowing it', async () => {
    const onPolicyError = vi.fn()
    const engine = engineWith(TYPOED_DENYLIST, onPolicyError)
    await engine.can('banned', 'read', { attributes: {}, type: 'post' })
    expect(onPolicyError).toHaveBeenCalled()
    const [err, policyId] = onPolicyError.mock.calls[0] ?? []
    expect(err).toBeInstanceOf(IamOperandTypeError)
    expect(policyId).toBe('p-denylist')
    expect(String(err)).toContain('subject.attributes.tier')
  })

  it('control: the same denylist authored correctly still allows and still denies', async () => {
    // Guard against an engine that denies everything passing the clauses above vacuously.
    const engine = engineWith(CORRECT_DENYLIST)
    expect(await engine.can('ok', 'read', { attributes: {}, type: 'post' })).toBe(true)
    expect(await engine.can('banned', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('control: the write path still refuses the same policy, so the two gates agree', async () => {
    const engine = engineWith(CORRECT_DENYLIST)
    await expect(engine.admin.savePolicy(TYPOED_DENYLIST)).rejects.toThrow()
  })
})

/** An allow plus a deny with a non-scalar operand, which reference comparison (`f === v`) could never fire. */
const UNFIREABLE_DENY = (operator: string, value: unknown) => ({
  algorithm: 'deny-overrides',
  id: 'p-unfireable',
  name: 'deny the banned tier',
  rules: [
    {
      actions: ['read'],
      conditions: { all: [] },
      effect: 'allow',
      id: 'r-allow',
      priority: 1,
      resources: ['post'],
    },
    {
      actions: ['read'],
      conditions: { all: [{ field: 'subject.attributes.tier', operator, value }] },
      effect: 'deny',
      id: 'r-deny',
      priority: 2,
      resources: ['post'],
    },
  ],
})

const NON_SCALAR_OPERANDS: readonly [string, string, unknown][] = [
  ['eq', 'an object', { tier: 'banned' }],
  ['in', 'an array of objects', [{ tier: 'banned' }]],
  ['superset_of', 'an array of arrays', [['banned']]],
]

describe('a non-scalar operand cannot retire a deny rule', () => {
  it.each(NON_SCALAR_OPERANDS)('%s with %s is refused on the write path', async (operator, _label, value) => {
    const engine = engineWith(CORRECT_DENYLIST)
    // biome-ignore lint/suspicious/noExplicitAny: a deliberately malformed operand is the subject of the test
    await expect(engine.admin.savePolicy(UNFIREABLE_DENY(operator, value) as any)).rejects.toThrow()
  })

  it.each(NON_SCALAR_OPERANDS)(
    '%s with %s still denies when seeded past the validator',
    async (operator, _l, value) => {
      // The throwing deny-bearing policy is Indeterminate and votes deny, so the rule is not retired.
      // biome-ignore lint/suspicious/noExplicitAny: as above
      const engine = engineWith(UNFIREABLE_DENY(operator, value) as any)
      expect(await engine.can('banned', 'read', { attributes: {}, type: 'post' })).toBe(false)
    },
  )

  it('control: the same deny authored with a scalar operand fires, and spares everyone else', async () => {
    // Guard against an engine that denies everything passing the clauses above vacuously.
    // biome-ignore lint/suspicious/noExplicitAny: shape matches the fixtures above
    const engine = engineWith(UNFIREABLE_DENY('eq', 'banned') as any)
    expect(await engine.can('banned', 'read', { attributes: {}, type: 'post' })).toBe(false)
    expect(await engine.can('ok', 'read', { attributes: {}, type: 'post' })).toBe(true)
  })
})
