import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// A NaN or absent `priority` (a row that skipped validation) is Indeterminate under the two ranking algorithms.
// Production reaches `evaluatePolicyFast` through a residual `post.*` policy; development checks rule order.
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

    // This used to expect `true`: the bad priority ranked as 0 and lost to allow@1, which is the deny being
    // dropped by another name. It is Indeterminate now, and the policy carries a deny, so it fails closed.
    it('no longer loses to allow@1, and still beats allow@-1', async () => {
      expect(
        await engineWith('development', algo, [rule('deny', 'deny', bad), rule('allow', 'allow', 1)]).can(
          'u1',
          'read',
          draft,
        ),
      ).toBe(false)
      expect(
        await engineWith('development', algo, [rule('allow', 'allow', -1), rule('deny', 'deny', bad)]).can(
          'u1',
          'read',
          draft,
        ),
      ).toBe(false)
    })

    it('CONTROL: a finite priority still ranks, so the assertion above is not vacuous', async () => {
      expect(
        await engineWith('development', algo, [rule('deny', 'deny', 0), rule('allow', 'allow', 1)]).can(
          'u1',
          'read',
          draft,
        ),
      ).toBe(true)
      expect(
        await engineWith('development', algo, [rule('allow', 'allow', -1), rule('deny', 'deny', 0)]).can(
          'u1',
          'read',
          draft,
        ),
      ).toBe(false)
    })

    it('production agrees with development, so the table cannot allow what the interpreter refuses', async () => {
      const rules = [rule('deny', 'deny', bad), rule('allow', 'allow', 1)]
      expect({
        development: await engineWith('development', algo, rules).can('u1', 'read', draft),
        production: await engineWith('production', algo, rules).can('u1', 'read', draft),
      }).toEqual({ development: false, production: false })
    })

    it('the other two algorithms never rank, so the same rows still decide normally', async () => {
      const rules = [rule('deny', 'deny', bad), rule('allow', 'allow', 1)]
      expect({
        allowOverrides: await engineWith('development', 'allow-overrides', rules).can('u1', 'read', draft),
        denyOverrides: await engineWith('development', 'deny-overrides', rules).can('u1', 'read', draft),
      }).toEqual({ allowOverrides: true, denyOverrides: false })
    })
  })
})
