/**
 * `createIam` constrains `engine.check` to the declared unions, so a rule naming an action outside them
 * matches nothing. `validateRoles` reported that for grants; `validatePolicy` did not report it for rules.
 */
import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { createIam } from '../../config'
import type { AccessControl } from '../../types'
import { validatePolicy } from '../validate'

const access = createIam({
  actions: ['read', 'delete', 'post:create'] as const,
  resources: ['post', 'doc', 'org.team'] as const,
  roles: ['editor', 'viewer'] as const,
})

/** Allows everything on `post`, then denies `delete` - except the deny's action is mistyped. */
function policy(denyAction: string): Record<string, unknown> {
  return {
    algorithm: 'deny-overrides',
    id: 'p-posts',
    name: 'posts',
    rules: [
      { actions: ['*'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 0, resources: ['post'] },
      {
        actions: [denyAction],
        conditions: { all: [] },
        effect: 'deny',
        id: 'r-deny',
        priority: 10,
        resources: ['post'],
      },
    ],
  }
}

/** Only the vocabulary pass, so `checkTargetIsReachable`'s own `UNREACHABLE_TARGET` cannot be mistaken for it. */
function vocabularyIssues(result: { issues: readonly { code: string; path?: string }[] }) {
  return result.issues.filter((i) => i.code === 'UNREACHABLE_TARGET' && i.path !== 'targets').map((i) => i.path)
}

describe('a rule action outside the declared vocabulary', () => {
  it('is reported, with the path of the offending entry', () => {
    const result = access.validatePolicy(policy('delet'))
    expect({ paths: vocabularyIssues(result), valid: result.valid }).toEqual({
      paths: ['rules[1].actions[0]'],
      valid: false,
    })
  })

  it('CONTROL: the same policy spelled correctly is clean', () => {
    const result = access.validatePolicy(policy('delete'))
    expect({ paths: vocabularyIssues(result), valid: result.valid }).toEqual({ paths: [], valid: true })
  })

  it('is the difference between a deny that fires and one that does not', async () => {
    type TAction = 'read' | 'delete' | 'post:create'
    type TResource = 'doc' | 'org.team' | 'post'
    const engineFor = async (denyAction: string) => {
      const adapter = new IamMemoryAdapter<TAction, TResource, 'editor' | 'viewer'>()
      // The mistyped action is the point, so the stored row is off-contract on purpose.
      await adapter.savePolicy(
        policy(denyAction) as unknown as AccessControl.IPolicy<TAction, TResource, 'editor' | 'viewer'>,
      )
      return access.createEngine({ adapter, cacheTTL: 0, mode: 'development' })
    }
    const typo = await engineFor('delet')
    const fixed = await engineFor('delete')
    expect({
      deleteFixed: await fixed.can('u1', 'delete', { attributes: {}, type: 'post' }),
      deleteTypo: await typo.can('u1', 'delete', { attributes: {}, type: 'post' }),
      readTypo: await typo.can('u1', 'read', { attributes: {}, type: 'post' }),
    }).toEqual({ deleteFixed: false, deleteTypo: true, readTypo: true })
  })

  it('reports a mistyped resource the same way', () => {
    const p = policy('delete')
    const rules = p.rules as Record<string, unknown>[]
    rules[1] = { ...rules[1], resources: ['psot'] }
    expect(vocabularyIssues(access.validatePolicy(p))).toEqual(['rules[1].resources[0]'])
  })
})

describe('wildcard patterns are cleared on what they would actually match', () => {
  const withActions = (actions: string[]) => ({
    algorithm: 'deny-overrides',
    id: 'p',
    name: 'p',
    rules: [{ actions, conditions: { all: [] }, effect: 'allow', id: 'r', priority: 0, resources: ['post'] }],
  })
  const withResources = (resources: string[]) => ({
    algorithm: 'deny-overrides',
    id: 'p',
    name: 'p',
    rules: [{ actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 0, resources }],
  })

  it('clears `*` and a prefix that reaches a declared action', () => {
    expect(vocabularyIssues(access.validatePolicy(withActions(['*', 'post:*'])))).toEqual([])
  })

  it('flags a prefix that reaches nothing', () => {
    expect(vocabularyIssues(access.validatePolicy(withActions(['user:*'])))).toEqual(['rules[0].actions[0]'])
  })

  it('flags a dot pattern on the action axis, which matchesAction reads as a literal', () => {
    expect(vocabularyIssues(access.validatePolicy(withActions(['post.*'])))).toEqual(['rules[0].actions[0]'])
  })

  it('clears a dot pattern on the resource axis, which matchesResource honours', () => {
    expect(vocabularyIssues(access.validatePolicy(withResources(['org.*'])))).toEqual([])
  })

  it('flags a colon pattern the declared resources do not reach', () => {
    expect(vocabularyIssues(access.validatePolicy(withResources(['org:*'])))).toEqual(['rules[0].resources[0]'])
  })
})

describe('policy targets', () => {
  const targeted = (targets: Record<string, unknown>) => ({
    algorithm: 'deny-overrides',
    id: 'p',
    name: 'p',
    rules: [{ actions: ['*'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 0, resources: ['*'] }],
    targets,
  })

  it('reports an undeclared target action, resource and role', () => {
    const result = access.validatePolicy(
      targeted({ actions: ['raed'], resources: ['psot'], roles: ['editr', 'editor'] }),
    )
    expect({ paths: vocabularyIssues(result), valid: result.valid }).toEqual({
      paths: ['targets.actions[0]', 'targets.resources[0]', 'targets.roles[0]'],
      valid: false,
    })
  })

  it('CONTROL: the declared spellings are clean', () => {
    const result = access.validatePolicy(targeted({ actions: ['read'], resources: ['post'], roles: ['editor'] }))
    expect({ paths: vocabularyIssues(result), valid: result.valid }).toEqual({ paths: [], valid: true })
  })
})

describe('the pass only runs when a vocabulary is supplied', () => {
  it('the bare export is unchanged', () => {
    const result = validatePolicy(policy('delet'))
    expect({ paths: vocabularyIssues(result), valid: result.valid }).toEqual({ paths: [], valid: true })
  })

  it('an omitted or empty axis leaves that axis unconstrained', () => {
    expect(vocabularyIssues(validatePolicy(policy('delet'), {}))).toEqual([])
    expect(vocabularyIssues(validatePolicy(policy('delet'), { actions: [] }))).toEqual([])
    expect(vocabularyIssues(validatePolicy(policy('delet'), { resources: ['post'] }))).toEqual([])
  })

  it('a config with no roles leaves targets.roles unconstrained', () => {
    const roleless = createIam({ actions: ['read'] as const, resources: ['post'] as const })
    const result = roleless.validatePolicy({
      algorithm: 'deny-overrides',
      id: 'p',
      name: 'p',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r', priority: 0, resources: ['post'] },
      ],
      targets: { roles: ['anything'] },
    })
    expect(vocabularyIssues(result)).toEqual([])
  })
})

describe('malformed input is reported, never thrown', () => {
  const declared = { actions: ['read'], resources: ['post'], roles: ['editor'] }

  it('survives rules that are not an array, not objects, or carry non-string lists', () => {
    expect(() =>
      validatePolicy({ algorithm: 'deny-overrides', id: 'p', name: 'p', rules: 'all' }, declared),
    ).not.toThrow()
    expect(() =>
      validatePolicy({ algorithm: 'deny-overrides', id: 'p', name: 'p', rules: [null, 7, 'x'] }, declared),
    ).not.toThrow()
    const result = validatePolicy(
      {
        algorithm: 'deny-overrides',
        id: 'p',
        name: 'p',
        rules: [{ actions: 'read', conditions: { all: [] }, effect: 'allow', id: 'r', priority: 0, resources: [1] }],
      },
      declared,
    )
    // A non-string list already errored as `INVALID_RULE`; one issue per character would be noise.
    expect(vocabularyIssues(result)).toEqual([])
  })

  it('survives a targets object that is not an object or carries non-string lists', () => {
    expect(() =>
      validatePolicy({ algorithm: 'deny-overrides', id: 'p', name: 'p', rules: [], targets: 'all' }, declared),
    ).not.toThrow()
    expect(() =>
      validatePolicy(
        { algorithm: 'deny-overrides', id: 'p', name: 'p', rules: [], targets: { roles: 'editor' } },
        declared,
      ),
    ).not.toThrow()
  })
})
