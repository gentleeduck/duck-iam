import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../types'
import { combiners } from '../evaluate.libs'
import type { Evaluate } from '../evaluate.types'

// A NaN or missing `priority` (an unvalidated adapter row) is Indeterminate under the two ranking algorithms,
// and invisible to the other two, which never read it.
function rule(id: string, effect: AccessControl.Effect, priority: number): AccessControl.IRule {
  return { id, effect, priority, actions: ['read'], resources: ['post'], conditions: { all: [] } }
}

function matched(...rules: AccessControl.IRule[]): Parameters<Evaluate.Combiner>[0] {
  return rules.map((r) => ({ rule: r, effect: r.effect }))
}

const NON_FINITE: [string, number][] = [
  ['NaN', Number.NaN],
  ['undefined', undefined as unknown as number],
  ['Infinity', Number.POSITIVE_INFINITY],
]

const RANKING = ['first-match', 'highest-priority'] as const
const UNRANKED = ['deny-overrides', 'allow-overrides'] as const

describe.each(NON_FINITE)('combiners with a %s priority', (_label, bad) => {
  it.each(RANKING)('%s: refuses it whatever the source order', (algo) => {
    const deny = rule('deny', 'deny', bad)
    const allow = rule('allow', 'allow', 1)
    expect(() => combiners[algo](matched(deny, allow), 'allow')).toThrow(/priority must be a finite number/)
    expect(() => combiners[algo](matched(allow, deny), 'allow')).toThrow(/priority must be a finite number/)
  })

  // The compiled fast path ranks every candidate, so a lone rule left unchecked here made the two disagree.
  // The 6000-catalog differential caught exactly that.
  it.each(RANKING)('%s: refuses a lone rule too, not just one it compares against', (algo) => {
    expect(() => combiners[algo](matched(rule('deny', 'deny', bad)), 'allow')).toThrow(
      /priority must be a finite number/,
    )
  })

  it.each(UNRANKED)('%s never reads priority, so it is unaffected', (algo) => {
    const bogus = rule('deny', 'deny', bad)
    expect(combiners[algo](matched(bogus, rule('allow', 'allow', 1)), 'allow').effect).toBe(
      algo === 'deny-overrides' ? 'deny' : 'allow',
    )
  })
})

describe('CONTROL: a finite priority still ranks', () => {
  it.each(RANKING)('%s: the higher priority wins, whatever the order', (algo) => {
    const deny = rule('deny', 'deny', 9)
    const allow = rule('allow', 'allow', 1)
    expect(combiners[algo](matched(allow, deny), 'allow').effect).toBe('deny')
    expect(combiners[algo](matched(deny, allow), 'allow').effect).toBe('deny')
    expect(combiners[algo](matched(rule('d', 'deny', 0), rule('a', 'allow', 1)), 'deny').effect).toBe('allow')
  })

  it.each(RANKING)('%s: a tie keeps source order', (algo) => {
    expect(combiners[algo](matched(rule('a', 'allow', 2), rule('d', 'deny', 2)), 'deny').effect).toBe('allow')
    expect(combiners[algo](matched(rule('d', 'deny', 2), rule('a', 'allow', 2)), 'deny').effect).toBe('deny')
  })
})
