import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// `policyApplies` matches `targets.roles` by equality against the subject's effective roles. An entry naming a
// role nothing defines therefore matches nobody, and the policy is skipped for every request. For a deny policy
// that is a retired deny, and a typo is enough to cause it - so the engine says so once per bad target.

const POST = { attributes: {}, id: 'p1', type: 'post' } as const

const ROLES: AccessControl.IRole[] = [
  { id: 'editor', name: 'Editor', permissions: [{ action: 'delete', resource: 'post' }] },
  { id: 'contractor', name: 'Contractor', permissions: [] },
]

function guard(targetRole: string): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    id: 'guard',
    name: 'Contractors may not delete',
    rules: [
      { actions: ['delete'], conditions: { all: [] }, effect: 'deny', id: 'd', priority: 0, resources: ['post'] },
    ],
    targets: { roles: [targetRole] },
  }
}

const MIXED_TARGETS: AccessControl.IPolicy = {
  ...guard('contractor'),
  targets: { roles: ['contractor', 'ghost', 'phantom'] },
}

function build(policy: AccessControl.IPolicy, mode: 'production' | 'development') {
  const reported: string[] = []
  const engine = new IamEngine({
    adapter: new IamMemoryAdapter({
      assignments: { u1: ['editor', 'contractor'] },
      policies: [policy],
      roles: ROLES,
    }),
    hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
    mode,
  })
  return { engine, reported }
}

describe('a policy targeting a role nothing defines is reported, not silent', () => {
  for (const mode of ['production', 'development'] as const) {
    it(`reports the unreachable target in ${mode} mode`, async () => {
      const { engine, reported } = build(guard('contarctor'), mode)

      // The deny is gone: this is the behaviour the report exists to explain, not a verdict the report changes.
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      expect(reported).toHaveLength(1)
      expect(reported[0]).toContain('guard|')
      expect(reported[0]).toContain('"contarctor"')
      expect(reported[0]).toMatch(/no stored role defines/)
    })

    it(`stays silent when the target resolves in ${mode} mode`, async () => {
      const { engine, reported } = build(guard('contractor'), mode)

      expect(await engine.can('u1', 'delete', POST)).toBe(false)
      expect(reported).toEqual([])
    })
  }

  it('reports each bad pair once, not once per cache fill', async () => {
    const { engine, reported } = build(guard('contarctor'), 'production')

    await engine.can('u1', 'delete', POST)
    engine.cache.invalidate()
    await engine.can('u1', 'delete', POST)
    engine.cache.invalidate()
    await engine.can('u1', 'delete', POST)

    expect(reported).toHaveLength(1)
  })

  it('falls back to a warning when no hook is installed', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const engine = new IamEngine({
        adapter: new IamMemoryAdapter({
          assignments: { u1: ['editor', 'contractor'] },
          policies: [guard('contarctor')],
          roles: ROLES,
        }),
        mode: 'production',
      })
      await engine.can('u1', 'delete', POST)
      expect(warn).toHaveBeenCalledTimes(1)
      expect(warn.mock.calls[0]?.[0]).toMatch(/no stored role defines/)
    } finally {
      warn.mockRestore()
    }
  })

  it('a role deleted after the policy was written becomes an unreachable target', async () => {
    const adapter = new IamMemoryAdapter({
      assignments: { u1: ['editor', 'contractor'] },
      policies: [guard('contractor')],
      roles: ROLES,
    })
    const reported: string[] = []
    const engine = new IamEngine({
      adapter,
      hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
      mode: 'production',
    })

    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(reported).toEqual([])

    // `deleteRole` sweeps the grants and the `inherits` edges; the policy target is the carrier it cannot sweep,
    // because emptying `targets.roles` would widen the policy to every subject rather than narrow it to none.
    await adapter.deleteRole('contractor')
    engine.cache.invalidate()

    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('"contractor"')
  })

  // `first-applicable` keeps `_getCompiledTable` at `null`, so the interpreter answers alone and the
  // compiled-table build never runs. Both paths have to carry the check for the same reason.
  it('reports from the interpreter when no compiled table is built', async () => {
    const reported: string[] = []
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter({
        assignments: { u1: ['editor', 'contractor'] },
        policies: [guard('contarctor')],
        roles: ROLES,
      }),
      hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
      mode: 'development',
      policyCombine: 'first-applicable',
    })

    await engine.can('u1', 'delete', POST)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('"contarctor"')
  })

  it('reports only the entries that do not resolve', async () => {
    const reported: string[] = []
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter({
        assignments: { u1: ['editor', 'contractor'] },
        policies: [MIXED_TARGETS],
        roles: ROLES,
      }),
      hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
      mode: 'production',
    })

    // One live entry is enough for the policy to apply, so the deny still fires.
    expect(await engine.can('u1', 'delete', POST)).toBe(false)
    expect(reported).toHaveLength(2)
    expect(reported.join('\n')).toContain('"ghost"')
    expect(reported.join('\n')).toContain('"phantom"')
  })
})
