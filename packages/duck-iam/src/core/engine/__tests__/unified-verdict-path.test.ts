import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

// The compiled table supplies the verdict in every mode; development also runs the interpreter for provenance
// (the table erases policy identity) and throws if the two disagree.

const roles: AccessControl.IRole[] = [
  { id: 'editor', name: 'Editor', permissions: [{ action: 'update', resource: 'post' }] },
]
const policies: AccessControl.IPolicy[] = [
  {
    algorithm: 'deny-overrides',
    id: 'ownership',
    name: 'Ownership',
    rules: [
      {
        actions: ['read'],
        conditions: { all: [{ field: 'subject.id', operator: 'eq', value: '$resource.attributes.ownerId' }] },
        effect: 'allow',
        id: 'r',
        priority: 0,
        resources: ['post'],
      },
    ],
  },
]
const adapterOf = () =>
  new IamMemoryAdapter({ assignments: { 'user-1': ['editor'] }, attributes: { 'user-1': {} }, policies, roles })

const devEngine = (hooks?: IamEngineTypes.IHooks) =>
  new IamEngine({ adapter: adapterOf(), defaultEffect: 'deny', hooks, mode: 'development' })
const prodEngine = () => new IamEngine({ adapter: adapterOf(), defaultEffect: 'deny', mode: 'production' })

describe('development keeps the rich decision while the table supplies the verdict', () => {
  it('check() still returns provenance the compiled table cannot produce', async () => {
    const decision = await devEngine().check('user-1', 'update', { attributes: {}, type: 'post' })
    expect(decision.allowed).toBe(true)
    // The table erases policy identity; the reason comes from the interpreter run alongside it.
    expect(decision.reason).toBeTruthy()
    expect(typeof decision.reason).toBe('string')
  })

  it('explain() and the verdict path agree over a condition-carrying policy', async () => {
    const engine = devEngine()
    const owned = { attributes: { ownerId: 'user-1' }, type: 'post' }
    const notOwned = { attributes: { ownerId: 'someone-else' }, type: 'post' }
    expect((await engine.check('user-1', 'read', owned)).allowed).toBe(true)
    expect((await engine.check('user-1', 'read', notOwned)).allowed).toBe(false)
  })

  it('a rotten policy is reported once per check, not once per evaluator', async () => {
    // Development runs two evaluators; `onPolicyError` does not affect the verdict, so the explanatory run gets
    // `undefined` and one bad policy reports once.
    const rotten: AccessControl.IPolicy = {
      algorithm: 'first-match',
      id: 'rotten',
      name: 'Rotten',
      rules: [
        {
          actions: ['update'],
          // `matches` over an oversized field throws, which routes the policy to `onPolicyError`.
          conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'curl' }] },
          effect: 'deny',
          id: 'r',
          priority: 0,
          resources: ['post'],
        },
      ],
    }
    const oversized = 'curl'.padEnd(MAX_REGEX_INPUT_LENGTH + 1, 'x')
    const seen: string[] = []
    const engine = new IamEngine({
      adapter: new IamMemoryAdapter({
        assignments: { 'user-1': ['editor'] },
        attributes: { 'user-1': {} },
        policies: [rotten],
        roles,
      }),
      defaultEffect: 'deny',
      hooks: { onPolicyError: (_err, id) => seen.push(id) },
      mode: 'development',
    })
    await engine.check('user-1', 'update', { attributes: {}, type: 'post' }, { userAgent: oversized })
    // Exactly one: zero would mean the test no longer exercises the double-fire.
    expect(seen).toEqual(['rotten'])
  })
})

describe('a table/interpreter disagreement is a loud development failure', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doUnmock('../compiled/compiled.lookup')
  })

  // Reload the engine with `lookup` forced to a fixed verdict, to manufacture a divergence.
  // NOTE: split per mode; a union-typed `mode` widens `TMode` and loses `check()`'s `IDecision` return type.
  const reloadEngine = async () => {
    const { IamEngine: Reloaded } = await import('../engine')
    return Reloaded
  }
  const forceLookup = (verdict: boolean) => {
    vi.resetModules()
    vi.doMock('../compiled/compiled.lookup', () => ({ lookup: () => verdict }))
  }
  const devWithForcedLookup = async (verdict: boolean, hooks?: IamEngineTypes.IHooks) => {
    forceLookup(verdict)
    const Reloaded = await reloadEngine()
    return new Reloaded({ adapter: adapterOf(), defaultEffect: 'deny', hooks, mode: 'development' })
  }
  const prodWithForcedLookup = async (verdict: boolean) => {
    forceLookup(verdict)
    const Reloaded = await reloadEngine()
    return new Reloaded({ adapter: adapterOf(), defaultEffect: 'deny', mode: 'production' })
  }

  it('development denies fail-closed and reports both verdicts', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const seen: Error[] = []
    try {
      const engine = await devWithForcedLookup(false, {
        onError: (err) => {
          seen.push(err)
        },
      })
      // The interpreter allows `update post` (editor grants it); the forced table denies. `authorize()` fails
      // closed with a generic deny, so the diagnostic must still reach both console and `onError`.
      const decision = await engine.check('user-1', 'update', { attributes: {}, type: 'post' })
      expect(decision.allowed).toBe(false)
      expect(String(error.mock.calls[0]?.[0])).toMatch(
        /compiled table and interpreter disagree on update post for roles \[editor\]: table=deny, interpreter=allow/,
      )
      expect(seen).toHaveLength(1)
      expect(seen[0]?.message).toMatch(/table=deny, interpreter=allow/)
    } finally {
      error.mockRestore()
    }
  })

  it('reports the allow-in-production direction too', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const engine = await devWithForcedLookup(true)
      // The dangerous direction: production would allow while this development run denies.
      expect((await engine.check('user-1', 'delete', { attributes: {}, type: 'post' })).allowed).toBe(false)
      expect(String(error.mock.calls[0]?.[0])).toMatch(/table=allow, interpreter=deny/)
    } finally {
      error.mockRestore()
    }
  })

  it('production does not run the interpreter, so it cannot throw on a disagreement', async () => {
    // PERF: production trusts the table; skipping the second evaluator is the point of the fast path.
    const engine = await prodWithForcedLookup(true)
    await expect(engine.can('user-1', 'delete', { attributes: {}, type: 'post' })).resolves.toBe(true)
  })
})

describe('production and development answer identically', () => {
  it.each([
    ['update', {}, 'role grant, static cell'],
    ['read', { ownerId: 'user-1' }, 'condition holds, dynamic cell'],
    ['read', { ownerId: 'someone-else' }, 'condition fails, dynamic cell'],
    ['delete', {}, 'nothing grants it'],
  ])('%s post (%s)', async (action, attributes, _label) => {
    const resource = { attributes, type: 'post' }
    const prod = await prodEngine().can('user-1', action, resource)
    const dev = await devEngine().check('user-1', action, resource)
    expect(prod).toBe(dev.allowed)
  })

  it('permissions() batches go through the same path in both modes', async () => {
    const checks = [
      { action: 'update', resource: 'post' },
      { action: 'read', resource: 'post' },
      { action: 'delete', resource: 'post' },
    ] as const
    const prod: Record<string, unknown> = await prodEngine().permissions('user-1', checks)
    const dev: Record<string, unknown> = await devEngine().permissions('user-1', checks)
    expect(Object.keys(prod)).toHaveLength(checks.length)
    for (const [key, prodAllowed] of Object.entries(prod)) {
      // Production returns booleans, development returns decisions carrying the same verdict.
      const devEntry = dev[key]
      const devAllowed =
        typeof devEntry === 'object' && devEntry !== null && 'allowed' in devEntry ? devEntry.allowed : devEntry
      expect(devAllowed).toBe(prodAllowed)
    }
  })
})
