import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

/**
 * A rule whose `priority` is NaN or absent (a row that bypassed validation -
 * memory and HTTP adapters used to let these through) must rank as 0 rather
 * than silently losing every `>` comparison.
 *
 * Production: the compiled engine handles flat policies itself; a *residual*
 * policy (`post.*`) routes through `evaluatePolicyFast`, where `NaN > -Infinity`
 * was always false, so a lone deny vanished and a fail-open engine allowed.
 * Development: the combiners seeded from `matched[0]`, so the verdict depended
 * on rule order.
 */
type A = 'read'
type R = 'post' | 'post.draft'
type Ro = 'viewer'
type S = 'org-1'
type Mode = 'development' | 'production'

const viewer: AccessControl.IRole<A, R, Ro, S> = {
  id: 'viewer',
  name: 'Viewer',
  permissions: [{ action: 'read', resource: 'post' }],
}

function rule(id: string, effect: AccessControl.Effect, priority: number | undefined): AccessControl.IRule<A, R> {
  const base = { id, effect, actions: ['read' as const], resources: ['post.*' as R], conditions: { all: [] } }
  return (priority === undefined ? base : { ...base, priority }) as AccessControl.IRule<A, R>
}

function engineWith(
  mode: Mode,
  algorithm: AccessControl.CombiningAlgorithm,
  rules: AccessControl.IRule<A, R>[],
  failOpen = false,
) {
  const adapter = new IamMemoryAdapter<A, R, Ro, S>({
    roles: [viewer],
    assignments: { u1: ['viewer'] },
    policies: [{ id: 'p', name: 'p', algorithm, rules }],
  })
  return new IamEngine<A, R, Ro, S, Mode>({
    adapter,
    cacheTTL: 0,
    mode,
    ...(failOpen ? { defaultEffect: 'allow' as const, allowFailOpen: true } : {}),
  })
}

const draft = { type: 'post.draft' as const, attributes: {} }
const BAD: [string, number | undefined][] = [
  ['NaN', Number.NaN],
  ['absent', undefined],
]

describe.each(['first-match', 'highest-priority'] as const)('%s', (algo) => {
  describe.each(BAD)('production, fail-open engine, lone deny with %s priority', (_label, bad) => {
    it('control: deny@99 denies', async () => {
      expect(await engineWith('production', algo, [rule('deny', 'deny', 99)], true).can('u1', 'read', draft)).toBe(
        false,
      )
    })

    it('the deny still fires instead of falling through to defaultEffect: allow', async () => {
      expect(await engineWith('production', algo, [rule('deny', 'deny', bad)], true).can('u1', 'read', draft)).toBe(
        false,
      )
    })
  })

  describe.each(BAD)('development, deny with %s priority vs allow@1', (_label, bad) => {
    it('verdict does not depend on rule order', async () => {
      const denyFirst = await engineWith('development', algo, [
        rule('deny', 'deny', bad),
        rule('allow', 'allow', 1),
      ]).can('u1', 'read', draft)
      const allowFirst = await engineWith('development', algo, [
        rule('allow', 'allow', 1),
        rule('deny', 'deny', bad),
      ]).can('u1', 'read', draft)
      expect(denyFirst).toBe(allowFirst)
    })

    it('ranks as 0, so it loses to allow@1 and beats allow@-1', async () => {
      expect(
        await engineWith('development', algo, [rule('deny', 'deny', bad), rule('allow', 'allow', 1)]).can(
          'u1',
          'read',
          draft,
        ),
      ).toBe(true)
      expect(
        await engineWith('development', algo, [rule('allow', 'allow', -1), rule('deny', 'deny', bad)]).can(
          'u1',
          'read',
          draft,
        ),
      ).toBe(false)
    })
  })
})
