import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// The mirror of a dead policy target. When the targets admit *some* request the policy is reachable and stays
// quiet, but a rule whose own actions/resources the targets never admit still cannot fire. Its policy works, so
// nothing looks wrong - and the deny it holds is gone.

const POST = { attributes: {}, id: 'p1', type: 'post' } as const
const ROLES: AccessControl.IRole[] = [{ id: 'editor', name: 'E', permissions: [] }]

function build(policy: AccessControl.IPolicy, mode: 'production' | 'development' = 'production') {
  const reported: string[] = []
  const engine = new IamEngine({
    adapter: new IamMemoryAdapter({ assignments: { u1: ['editor'] }, policies: [policy], roles: ROLES }),
    hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
    mode,
  })
  return { engine, reported }
}

/** Allow and deny live in one policy, so the verdict distinguishes a deny that fired from one that did not. */
function policy(
  targets: AccessControl.IPolicy['targets'],
  denyActions: string[] = ['delete'],
  denyResources: string[] = ['post'],
): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    id: 'guard',
    name: 'g',
    rules: [
      { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 0, resources: ['post'] },
      {
        actions: denyActions,
        conditions: { all: [] },
        effect: 'deny',
        id: 'd',
        priority: 10,
        resources: denyResources,
      },
    ],
    targets,
  }
}

describe('a rule its own policy’s targets never admit is reported', () => {
  it('CONTROL: a live deny under live targets fires, and is silent', async () => {
    for (const targets of [undefined, { actions: ['delete'] }, { resources: ['post'] }]) {
      const { engine, reported } = build(policy(targets))
      expect(await engine.can('u1', 'delete', POST)).toBe(false)
      expect(reported).toEqual([])
    }
  })

  for (const mode of ['production', 'development'] as const) {
    it(`reports a deny the targets exclude by action in ${mode} mode`, async () => {
      const { engine, reported } = build(policy({ actions: ['delete'] }, ['delte']), mode)

      // The policy still fires - its allow rule matches - so nothing else in the engine notices.
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      expect(reported).toHaveLength(1)
      expect(reported[0]).toContain('guard|')
      expect(reported[0]).toContain('rule "d"')
      expect(reported[0]).toContain('["delte"]')
      expect(reported[0]).toMatch(/never admits/)
      expect(reported[0]).toMatch(/a deny written this way is dead on its own/)
    })
  }

  it('reports a deny the targets exclude by resource', async () => {
    const { engine, reported } = build(policy({ resources: ['post'] }, ['delete'], ['psot']))
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('targets.resources')
  })

  it('says "an allow" for an allow rule, and the policy still denies', async () => {
    const p: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'guard',
      name: 'g',
      rules: [
        { actions: ['delte'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 0, resources: ['post'] },
        { actions: ['delete'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 10, resources: ['post'] },
      ],
      targets: { actions: ['delete'] },
    }
    const { engine, reported } = build(p)
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toMatch(/an allow written this way is dead on its own/)
  })

  it('stays quiet when a wildcard target admits every rule', async () => {
    // `*` admits anything, so even the misspelled deny is in range and there is nothing to report.
    const star = build(policy({ actions: ['*'] }, ['delte']))
    await star.engine.can('u1', 'delete', POST)
    expect(star.reported).toEqual([])

    // A prefix target with both rules inside it: the wildcard is not treated as a literal.
    const prefixed: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'guard',
      name: 'g',
      rules: [
        {
          actions: ['post:delete'],
          conditions: { all: [] },
          effect: 'allow',
          id: 'a',
          priority: 0,
          resources: ['post'],
        },
        {
          actions: ['post:archive'],
          conditions: { all: [] },
          effect: 'deny',
          id: 'd',
          priority: 10,
          resources: ['post'],
        },
      ],
      targets: { actions: ['post:*'] },
    }
    const { engine, reported } = build(prefixed)
    await engine.can('u1', 'delete', POST)
    expect(reported).toEqual([])
  })

  it('does not double-report when the whole policy is dead', async () => {
    // Every rule excluded: that is the policy-level report, and the per-rule ones would only repeat it.
    const { engine, reported } = build(policy({ actions: ['archive'] }, ['delte']))
    await engine.can('u1', 'delete', POST)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toMatch(/no rule in the policy can match/)
  })

  it('stays quiet with no targets at all, having nothing to judge the rule against', async () => {
    const { engine, reported } = build(policy(undefined, ['delte']))
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toEqual([])
  })

  it('reports once per policy, rule and dimension across invalidations', async () => {
    const { engine, reported } = build(policy({ actions: ['delete'] }, ['delte']))
    await engine.can('u1', 'delete', POST)
    engine.cache.invalidate()
    await engine.can('u1', 'delete', POST)
    await engine.can('u2', 'delete', POST)
    expect(reported).toHaveLength(1)
  })

  it('falls back to console.warn when no hook is wired', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const engine = new IamEngine({
        adapter: new IamMemoryAdapter({
          assignments: { u1: ['editor'] },
          policies: [policy({ actions: ['delete'] }, ['delte'])],
          roles: ROLES,
        }),
        mode: 'production',
      })
      await engine.can('u1', 'delete', POST)
      expect(warn).toHaveBeenCalledTimes(1)
      expect(warn.mock.calls[0]?.[0]).toMatch(/rule "d"/)
    } finally {
      warn.mockRestore()
    }
  })
})
