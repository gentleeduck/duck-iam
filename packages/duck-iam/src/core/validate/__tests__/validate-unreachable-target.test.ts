import { describe, expect, it } from 'vitest'
import { validatePolicy } from '../validate'

/** A matched target with no matching rule folds `defaultEffect`, which is `deny`. */
const unreachable = (policy: unknown) =>
  validatePolicy(policy).issues.filter((issue) => issue.code === 'UNREACHABLE_TARGET')

const rule = (id: string, effect: 'allow' | 'deny', actions: string[], resources: string[]) => ({
  id,
  effect,
  priority: 10,
  actions,
  resources,
  conditions: { all: [] },
})

describe('validatePolicy() - unreachable targets', () => {
  it('warns when the target names a pair no allow rule covers', () => {
    const issues = unreachable({
      id: 'p',
      name: 'p',
      algorithm: 'deny-overrides',
      targets: { actions: ['create', 'update'], resources: ['post'] },
      rules: [rule('r1', 'allow', ['create'], ['post'])],
    })

    expect(issues).toHaveLength(1)
    expect(issues[0]?.message).toContain('"update" on "post"')
  })

  it('stays quiet when every targeted pair is covered', () => {
    expect(
      unreachable({
        id: 'p',
        name: 'p',
        algorithm: 'deny-overrides',
        targets: { actions: ['create', 'update'], resources: ['post'] },
        rules: [rule('r1', 'allow', ['create', 'update'], ['post'])],
      }),
    ).toEqual([])
  })

  it('treats a wildcard allow as covering everything the target names', () => {
    expect(
      unreachable({
        id: 'p',
        name: 'p',
        algorithm: 'deny-overrides',
        targets: { actions: ['create', 'delete'], resources: ['post', 'comment'] },
        rules: [rule('r1', 'allow', ['*'], ['*'])],
      }),
    ).toEqual([])
  })

  it('leaves a purely restrictive policy alone', () => {
    expect(
      unreachable({
        id: 'immutable-log',
        name: 'immutable-log',
        algorithm: 'deny-overrides',
        targets: { actions: ['update', 'delete'], resources: ['events'] },
        rules: [rule('r1', 'deny', ['update', 'delete'], ['events'])],
      }),
    ).toEqual([])
  })

  it('warns once per uncovered pair, not once per policy', () => {
    const issues = unreachable({
      id: 'p',
      name: 'p',
      algorithm: 'deny-overrides',
      targets: { actions: ['create', 'delete'], resources: ['post', 'comment'] },
      rules: [rule('r1', 'allow', ['create'], ['post'])],
    })

    expect(issues).toHaveLength(3)
  })

  it('is a warning, so a policy carrying one still validates', () => {
    const result = validatePolicy({
      id: 'p',
      name: 'p',
      algorithm: 'deny-overrides',
      targets: { actions: ['create', 'update'], resources: ['post'] },
      rules: [rule('r1', 'allow', ['create'], ['post'])],
    })

    expect(result.valid).toBe(true)
  })

  it('says nothing about a policy with no target at all', () => {
    expect(
      unreachable({
        id: 'p',
        name: 'p',
        algorithm: 'deny-overrides',
        rules: [rule('r1', 'allow', ['create'], ['post'])],
      }),
    ).toEqual([])
  })
})
