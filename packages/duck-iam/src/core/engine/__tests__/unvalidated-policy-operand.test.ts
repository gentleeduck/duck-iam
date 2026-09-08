import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamOperandTypeError } from '../../conditions/conditions.libs'
import type { AccessControl } from '../../types'
import { IamEngine } from '../index'

/**
 * The validator is a gate on two doors, and policies come in through more than
 * two.
 *
 * `admin.savePolicy` and `admin.import` both run `validatePolicy`, and the
 * operand-type matrix leaned entirely on that: a wrongly-typed operand makes
 * `nin` return `true`, so `allow if tier nin 'banned'` - the author meant
 * `['banned']` - admits every subject the denylist was written to exclude, and
 * the argument for why that could never happen was "the validator refuses it
 * first".
 *
 * `loadPolicies` does not validate. So the rule reaches evaluation intact when
 * it arrives any other way, and the adapter constructor below is a documented,
 * supported way for it to arrive - as is an operator's `INSERT`, a seed script,
 * a migration, and a row written by a version that predates the rule.
 *
 * This file is the reachability half. `validate/__tests__/operand-type-matrix`
 * pins the operator behaviour; what is pinned here is that the door exists.
 */
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
      // `'banned'`, not `['banned']`. The validator calls this
      // OPERAND_TYPE_MISMATCH; nothing on this path asks it.
      conditions: { all: [{ field: 'subject.attributes.tier', operator: 'nin', value: 'banned' }] },
      effect: 'allow',
      id: 'r-allow-unless-banned',
      priority: 1,
      resources: ['post'],
    },
  ],
  // The cast manufactures the malformed policy on purpose: the typed surface
  // cannot express an operand the operator does not accept, which is the whole
  // reason this shape only ever arrives from outside the package.
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
    // Before the evaluator applied the matrix this was `true`, from the
    // documented seeding API, with no database and nothing hand-edited.
    const engine = engineWith(TYPOED_DENYLIST)
    expect(await engine.can('banned', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('and does not admit the subject the denylist was not about either', async () => {
    // The rule is the only thing granting here, so once it cannot be evaluated
    // nobody gets through. That is the cost of Indeterminate, and it is the
    // direction that does not hand out access nobody authored.
    const engine = engineWith(TYPOED_DENYLIST)
    expect(await engine.can('ok', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('reports the refusal rather than swallowing it', async () => {
    // A deny nobody can explain is its own outage. The operator has to be able
    // to find the malformed rule.
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
    // Without this the three clauses above are satisfied by an engine that
    // denies everything, which would prove nothing about the operand at all.
    const engine = engineWith(CORRECT_DENYLIST)
    expect(await engine.can('ok', 'read', { attributes: {}, type: 'post' })).toBe(true)
    expect(await engine.can('banned', 'read', { attributes: {}, type: 'post' })).toBe(false)
  })

  it('control: the write path still refuses the same policy, so the two gates agree', async () => {
    const engine = engineWith(CORRECT_DENYLIST)
    await expect(engine.admin.savePolicy(TYPOED_DENYLIST)).rejects.toThrow()
  })
})
