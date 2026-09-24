import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// `resolve` answers `null` for a path whose root is not subject/resource/environment, or whose segments include a
// prototype key - on every request, for every input. A rule reading one can never match, so a deny written that
// way never fires. An absent *attribute* is not the same thing and stays silent: only the request knows that.

const POST = { attributes: { sensitive: true }, id: 'p1', type: 'post' } as const
const ROLES: AccessControl.IRole[] = [{ id: 'editor', name: 'E', permissions: [] }]

/** The deny gets a companion allow in the same policy, or the verdict is `deny` whether the deny fired or not. */
function policyFor(field: string, effect: 'allow' | 'deny' = 'deny'): AccessControl.IPolicy {
  return {
    algorithm: 'deny-overrides',
    id: 'guard',
    name: 'banned may not delete',
    rules: [
      { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 0, resources: ['post'] },
      {
        actions: ['delete'],
        conditions: { all: [{ field, operator: 'eq', value: true }] },
        effect,
        id: 'd',
        priority: 10,
        resources: ['post'],
      },
    ],
  }
}

async function build(policy: AccessControl.IPolicy, banned = true, mode: 'production' | 'development' = 'production') {
  const reported: string[] = []
  const adapter = new IamMemoryAdapter({ assignments: { u1: ['editor'] }, policies: [policy], roles: ROLES })
  await adapter.setSubjectAttributes('u1', { banned })
  const engine = new IamEngine({
    adapter,
    hooks: { onPolicyError: (e: Error, id: string) => reported.push(`${id}|${e.message}`) },
    mode,
  })
  return { engine, reported }
}

describe('a condition reading a path that can never resolve is reported', () => {
  it('CONTROL: the deny fires on a path that resolves, and the allow stands when it does not hold', async () => {
    const hit = await build(policyFor('subject.attributes.banned'), true)
    expect(await hit.engine.can('u1', 'delete', POST)).toBe(false)
    expect(hit.reported).toEqual([])

    const miss = await build(policyFor('subject.attributes.banned'), false)
    expect(await miss.engine.can('u1', 'delete', POST)).toBe(true)
    expect(miss.reported).toEqual([])

    // A second resolvable path, on the other root, so the control is not one lucky field.
    const viaResource = await build(policyFor('resource.attributes.sensitive'))
    expect(await viaResource.engine.can('u1', 'delete', POST)).toBe(false)
    expect(viaResource.reported).toEqual([])
  })

  for (const mode of ['production', 'development'] as const) {
    it(`reports a root outside the contract in ${mode} mode`, async () => {
      const { engine, reported } = await build(policyFor('user.banned'), true, mode)

      // The deny is gone: the behaviour the report explains, not one it changes.
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      expect(reported).toHaveLength(1)
      expect(reported[0]).toContain('guard|')
      expect(reported[0]).toContain('"user.banned"')
      expect(reported[0]).toMatch(/resolves to null on every request/)
      expect(reported[0]).toMatch(/a deny written this way never fires/)
    })
  }

  it('reports a capitalised root, which is not the same root', async () => {
    const { engine, reported } = await build(policyFor('Subject.attributes.banned'))
    expect(await engine.can('u1', 'delete', POST)).toBe(true)
    expect(reported).toHaveLength(1)
  })

  it('reports a prototype key at any segment', async () => {
    for (const field of ['subject.__proto__.banned', 'subject.constructor.banned', 'resource.prototype.x']) {
      const { engine, reported } = await build(policyFor(field))
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      expect(reported).toHaveLength(1)
      expect(reported[0]).toContain(JSON.stringify(field))
    }
  })

  it('says "an allow" for an allow rule', async () => {
    const { engine, reported } = await build(policyFor('user.banned', 'allow'))
    await engine.can('u1', 'delete', POST)
    expect(reported[0]).toMatch(/an allow written this way never fires/)
  })

  it('stays silent for a merely absent attribute, which only the request can know', async () => {
    for (const field of ['subject.attributes.bannd', 'subject.banned', 'environment.ip']) {
      const { engine, reported } = await build(policyFor(field))
      expect(await engine.can('u1', 'delete', POST)).toBe(true)
      expect(reported).toEqual([])
    }
  })

  it('reaches a path nested inside any/none groups', async () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'guard',
      name: 'nested',
      rules: [
        { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 0, resources: ['post'] },
        {
          actions: ['delete'],
          conditions: { any: [{ none: [{ field: 'user.banned', operator: 'eq', value: true }] }] },
          effect: 'deny',
          id: 'd',
          priority: 10,
          resources: ['post'],
        },
      ],
    }
    const { engine, reported } = await build(policy)
    await engine.can('u1', 'delete', POST)
    expect(reported).toHaveLength(1)
    expect(reported[0]).toContain('"user.banned"')
  })

  it('leaves a `$`-prefixed value operand to the report that already covers it', async () => {
    const policy: AccessControl.IPolicy = {
      algorithm: 'deny-overrides',
      id: 'guard',
      name: 'operand',
      rules: [
        { actions: ['delete'], conditions: { all: [] }, effect: 'allow', id: 'a', priority: 0, resources: ['post'] },
        {
          actions: ['delete'],
          conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$owner.id' }] },
          effect: 'deny',
          id: 'd',
          priority: 10,
          resources: ['post'],
        },
      ],
    }
    const { engine, reported } = await build(policy)
    await engine.can('u1', 'delete', POST)
    // `evalCondition` reports it per evaluation and answers Indeterminate, which is the stronger signal of the two.
    expect(reported).toHaveLength(1)
    expect(reported[0]).toBe('guard|IAM_CONDITION_OPERAND_TYPE')
  })

  it('reports once per policy, rule and path across invalidations', async () => {
    const { engine, reported } = await build(policyFor('user.banned'))
    await engine.can('u1', 'delete', POST)
    engine.cache.invalidate()
    await engine.can('u1', 'delete', POST)
    await engine.can('u2', 'delete', POST)
    expect(reported).toHaveLength(1)
  })

  it('falls back to console.warn when no hook is wired', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const adapter = new IamMemoryAdapter({
        assignments: { u1: ['editor'] },
        policies: [policyFor('user.banned')],
        roles: ROLES,
      })
      const engine = new IamEngine({ adapter, mode: 'production' })
      await engine.can('u1', 'delete', POST)
      expect(warn).toHaveBeenCalledTimes(1)
      expect(warn.mock.calls[0]?.[0]).toMatch(/"user\.banned"/)
    } finally {
      warn.mockRestore()
    }
  })
})
