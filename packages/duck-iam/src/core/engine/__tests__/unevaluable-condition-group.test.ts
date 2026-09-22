import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../index'

// The group counterpart of `unvalidated-policy-operand.test.ts`: `false` for an unevaluable group retires a deny.
// `savePolicy` refuses these, but seeded adapters and the `evaluate` / `evaluateFast` exports skip validation.
type A = 'read'
type R = 'doc'

/** `{ all: [ ... ] }` nested `levels` deep around a leaf naming the banned tier. */
function nest(levels: number): unknown {
  let group: unknown = { all: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'banned' }] }
  for (let i = 0; i < levels; i++) group = { all: [group] }
  return group
}

/** Allow everything, then deny the banned tier - with the group under test. */
const denyWith = (conditions: unknown) => ({
  algorithm: 'deny-overrides',
  id: 'p1',
  name: 'deny the banned tier',
  rules: [
    { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 1, resources: ['doc'] },
    { actions: ['read'], conditions, effect: 'deny', id: 'r-deny', priority: 2, resources: ['doc'] },
  ],
})

function seededEngine(conditions: unknown): IamEngine<A, R, string, string> {
  return new IamEngine<A, R, string, string>({
    adapter: new IamMemoryAdapter({
      attributes: { banned: { tier: 'banned' }, ok: { tier: 'gold' } },
      // biome-ignore lint/suspicious/noExplicitAny: a deliberately unevaluable group is the subject of the test
      policies: [denyWith(conditions) as any],
    }),
  })
}

const UNEVALUABLE: readonly [string, unknown][] = [
  ['nesting past the depth bound', nest(12)],
  ["a typo'd `all` key", { AND: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'banned' }] }],
  ['an unrelated key', { foo: 1 }],
]

describe('a condition group nobody can evaluate does not retire the deny holding it', () => {
  it.each(UNEVALUABLE)('%s still denies when seeded past the validator', async (_label, conditions) => {
    const engine = seededEngine(conditions)
    expect(await engine.can('banned', 'read', { attributes: {}, type: 'doc' })).toBe(false)
  })

  it.each(UNEVALUABLE)('%s is refused on the write path', async (_label, conditions) => {
    const engine = seededEngine({ all: [] })
    // biome-ignore lint/suspicious/noExplicitAny: as above
    await expect(engine.admin.savePolicy(denyWith(conditions) as any)).rejects.toThrow()
  })

  it('control: the same deny with an evaluable group denies the banned tier and spares everyone else', async () => {
    // Without this, an engine that denies everything would satisfy the clauses above.
    const engine = seededEngine({ all: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'banned' }] })
    expect(await engine.can('banned', 'read', { attributes: {}, type: 'doc' })).toBe(false)
    expect(await engine.can('ok', 'read', { attributes: {}, type: 'doc' })).toBe(true)
  })
})
