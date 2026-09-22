import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// The sibling of the unreachable role target, one dimension over. `targets.actions` and `targets.resources` are
// matched against the request, not against a catalogue, so an entry no rule of the policy could ever match makes
// the policy NotApplicable for every request. No catalogue is needed to see it: the rules are the vocabulary.

const POST = { attributes: {}, id: 'p1', type: 'post' } as const

const ROLES: AccessControl.IRole[] = [
  { id: 'editor', name: 'E', permissions: [{ action: 'delete', resource: 'post' }] },
]

function guard(targets: AccessControl.IPolicy['targets'], actions = ['delete'], resources = ['post']) {
  return {
    algorithm: 'deny-overrides',
    id: 'guard',
    name: 'no deleting',
    rules: [{ actions, conditions: { all: [] }, effect: 'deny', id: 'd', priority: 0, resources }],
    targets,
  } satisfies AccessControl.IPolicy
}

function build(policy: AccessControl.IPolicy, mode: 'production' | 'development' = 'production') {
  const reported: string[] = []
  const engine = new IamEngine({
    adapter: new IamMemoryAdapter({ assignments: { u1: ['editor'] }, policies: [policy], roles: ROLES }),
    hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
    mode,
  })
  return { engine, reported }
}

describe('a policy whose action/resource targets no rule can match is reported', () => {
  for (const mode of ['production', 'development'] as const) {
    it(`reports a misspelled targets.actions in ${mode} mode`, async () => {
      const { engine, reported } = build(guard({ actions: ['delte'] }), mode)

      // The deny is gone: the behaviour the report exists to explain, not one the report changes.
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      expect(reported).toHaveLength(1)
      expect(reported[0]).toContain('guard|')
      expect(reported[0]).toContain('targets.actions')
      expect(reported[0]).toMatch(/no rule in the policy can match/)
    })

    it(`reports a misspelled targets.resources in ${mode} mode`, async () => {
      const { engine, reported } = build(guard({ resources: ['psot'] }), mode)
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      expect(reported).toHaveLength(1)
      expect(reported[0]).toContain('targets.resources')
    })
  }

  it('CONTROL: stays silent, and the deny fires, when the targets match the rules', async () => {
    for (const targets of [undefined, { actions: ['delete'] }, { resources: ['post'] }, { actions: ['*'] }]) {
      const { engine, reported } = build(guard(targets))
      expect(await engine.can('u1', 'delete', POST)).toBe(false)
      expect(reported).toEqual([])
    }
  })

  it('reports a target that is spelled right but names a different operation than the rules', async () => {
    // Not a typo: `targets.actions` narrows the policy to `read`, while its only rule denies `delete`.
    const { engine, reported } = build(guard({ actions: ['read'] }))
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toHaveLength(1)
  })

  it('treats a wildcard target and a wildcard rule as reachable', async () => {
    for (const [targets, actions] of [
      [{ actions: ['post:*'] }, ['post:delete']],
      [{ actions: ['post:delete'] }, ['post:*']],
      [{ actions: ['post:*'] }, ['post:*']],
      [{ actions: ['*'] }, ['delte']],
    ] as const) {
      const { engine, reported } = build(guard(targets, [...actions]))
      // Building alone does not load, so each row has to drive a request or it asserts on an empty engine.
      await engine.can('u1', 'delete', POST)
      expect(reported).toEqual([])
    }
  })

  it('reports two disjoint wildcard prefixes', async () => {
    const { engine, reported } = build(guard({ actions: ['post:*'] }, ['comment:*']))
    await engine.can('u1', 'delete', POST)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('targets.actions')
  })

  it('separator style is part of the prefix, so `a:*` and `a.*` do not intersect', async () => {
    const { engine, reported } = build(guard({ resources: ['post:*'] }, ['delete'], ['post.*']))
    await engine.can('u1', 'delete', POST)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('targets.resources')
  })

  it('one live rule among dead ones keeps the policy reachable, and names the dead one', async () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'guard',
      name: 'mixed',
      rules: [
        { actions: ['read'], conditions: { all: [] }, effect: 'deny', id: 'r1', priority: 0, resources: ['post'] },
        { actions: ['delete'], conditions: { all: [] }, effect: 'deny', id: 'r2', priority: 0, resources: ['post'] },
      ],
      targets: { actions: ['delete'] },
    }
    const { engine, reported } = build(policy)
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    // No policy-level report: the policy fires. `r1` cannot, though, and only this says so.
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('rule "r1"')
    expect(reported[0]).toMatch(/never admits/)
    expect(reported[0]).toMatch(/dead on its own/)
  })

  it('reports both dimensions of one policy separately', async () => {
    const { engine, reported } = build(guard({ actions: ['delte'], resources: ['psot'] }))
    await engine.can('u1', 'delete', POST)
    expect(reported).toHaveLength(2)
    expect(reported.some((r) => r.includes('targets.actions'))).toBe(true)
    expect(reported.some((r) => r.includes('targets.resources'))).toBe(true)
  })

  it('reports once per policy and dimension across invalidations', async () => {
    const { engine, reported } = build(guard({ actions: ['delte'] }))
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
          policies: [guard({ actions: ['delte'] })],
          roles: ROLES,
        }),
        mode: 'production',
      })
      await engine.can('u1', 'delete', POST)
      expect(warn).toHaveBeenCalledTimes(1)
      expect(warn.mock.calls[0]?.[0]).toMatch(/targets\.actions/)
    } finally {
      warn.mockRestore()
    }
  })

  it('the interpreter-only path reports it too', async () => {
    // No compiled table under `first-applicable`, so `loadAllPolicies` is the only route in.
    const reported: string[] = []
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter({
        assignments: { u1: ['editor'] },
        policies: [guard({ actions: ['delte'] })],
        roles: ROLES,
      }),
      hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
      mode: 'development',
      policyCombine: 'first-applicable',
    })
    await engine.can('u1', 'delete', POST)
    expect(reported).toHaveLength(1)
  })
})
