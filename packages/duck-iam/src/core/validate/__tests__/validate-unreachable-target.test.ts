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
  it('reports when the target names a pair no allow rule covers', () => {
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

  it('reports once per uncovered pair, not once per policy', () => {
    const issues = unreachable({
      id: 'p',
      name: 'p',
      algorithm: 'deny-overrides',
      targets: { actions: ['create', 'delete'], resources: ['post', 'comment'] },
      rules: [rule('r1', 'allow', ['create'], ['post'])],
    })

    expect(issues).toHaveLength(3)
  })

  /**
   * An error rather than a warning, so `PolicyBuilder.build()` throws where the policy is
   * written. A warning was not enough: the symptom is a denial, which reads as the
   * permission system working, and it cost five separate incidents to recognise.
   */
  it('fails validation, so build() refuses the policy', () => {
    const result = validatePolicy({
      id: 'p',
      name: 'p',
      algorithm: 'deny-overrides',
      targets: { actions: ['create', 'update'], resources: ['post'] },
      rules: [rule('r1', 'allow', ['create'], ['post'])],
    })

    expect(result.valid).toBe(false)
    expect(result.issues.find((i) => i.code === 'UNREACHABLE_TARGET')?.type).toBe('error')
  })

  /**
   * A dimension the target omits is one it does not constrain. Expanding it to a literal
   * '*' demanded that every rule be a wildcard, so a target naming only an action was
   * called unreachable whenever its allow rule named a specific resource.
   */
  it('does not require a wildcard rule when the target names no resources', () => {
    expect(
      unreachable({
        id: 'impersonation-gate',
        name: 'impersonation-gate',
        algorithm: 'deny-overrides',
        targets: { actions: ['impersonate'] },
        rules: [rule('r1', 'allow', ['impersonate'], ['users'])],
      }),
    ).toEqual([])
  })

  it('still reports an uncovered action when the target names no resources', () => {
    const issues = unreachable({
      id: 'p',
      name: 'p',
      algorithm: 'deny-overrides',
      targets: { actions: ['create', 'manageRoles'] },
      rules: [rule('r1', 'allow', ['create'], ['*'])],
    })

    expect(issues).toHaveLength(1)
    expect(issues[0]?.message).toContain('"manageRoles"')
  })

  it('does not require a wildcard rule when the target names no actions', () => {
    expect(
      unreachable({
        id: 'p',
        name: 'p',
        algorithm: 'deny-overrides',
        targets: { resources: ['post'] },
        rules: [rule('r1', 'allow', ['create'], ['post'])],
      }),
    ).toEqual([])
  })

  it('says nothing when the target constrains neither dimension', () => {
    expect(
      unreachable({
        id: 'p',
        name: 'p',
        algorithm: 'deny-overrides',
        targets: { roles: ['admin'] },
        rules: [rule('r1', 'allow', ['create'], ['post'])],
      }),
    ).toEqual([])
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
