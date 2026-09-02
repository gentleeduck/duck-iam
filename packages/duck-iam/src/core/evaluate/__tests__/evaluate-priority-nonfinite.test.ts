import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { combiners } from '../evaluate.libs'
import type { Evaluate } from '../evaluate.types'

/**
 * A rule whose `priority` is NaN or missing (an adapter row that bypassed
 * validation) must not silently lose every `>` comparison. Before the fix the
 * combiners seeded from `matched[0]`, so the winner depended on source order.
 */
function rule(id: string, effect: AccessControl.Effect, priority: number): AccessControl.IRule {
  return { id, effect, priority, actions: ['read'], resources: ['post'], conditions: { all: [] } }
}

function matched(...rules: AccessControl.IRule[]): Parameters<Evaluate.Combiner>[0] {
  return rules.map((r) => ({ rule: r, effect: r.effect }))
}

const NON_FINITE: [string, number][] = [
  ['NaN', Number.NaN],
  ['undefined', undefined as unknown as number],
]

describe.each(NON_FINITE)('combiners with a %s priority', (_label, bad) => {
  it('first-match: outcome is independent of source order', () => {
    const deny = rule('deny', 'deny', bad)
    const allow = rule('allow', 'allow', 1)
    const a = combiners['first-match'](matched(deny, allow), 'allow')
    const b = combiners['first-match'](matched(allow, deny), 'allow')
    expect(a.effect).toBe(b.effect)
  })

  it('highest-priority: outcome is independent of source order', () => {
    const deny = rule('deny', 'deny', bad)
    const allow = rule('allow', 'allow', 1)
    const a = combiners['highest-priority'](matched(deny, allow), 'allow')
    const b = combiners['highest-priority'](matched(allow, deny), 'allow')
    expect(a.effect).toBe(b.effect)
  })

  it('a lone deny with a non-finite priority still denies', () => {
    for (const algo of ['first-match', 'highest-priority'] as const) {
      expect(combiners[algo](matched(rule('deny', 'deny', bad)), 'allow').effect, algo).toBe('deny')
    }
  })

  it('non-finite ranks as 0: loses to a positive priority, beats a negative one', () => {
    const bad0 = rule('bad', 'deny', bad)
    expect(combiners['highest-priority'](matched(bad0, rule('pos', 'allow', 1)), 'deny').effect).toBe('allow')
    expect(combiners['highest-priority'](matched(bad0, rule('neg', 'allow', -1)), 'allow').effect).toBe('deny')
  })
})
