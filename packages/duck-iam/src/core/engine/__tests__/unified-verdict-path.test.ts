import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { MAX_REGEX_INPUT_LENGTH } from '../../conditions/conditions.libs'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'
import type { IamEngineTypes } from '../engine.types'

/**
 * The verdict comes from the compiled table in every mode.
 *
 * Round 3's largest defect family was a single shape: production evaluated
 * through the compiled table, development through the interpreter, so a
 * disagreement between the two was invisible until it reached production - and
 * it reached production as an *allow* against a development run that denied.
 * Patching each instance never addressed why they kept arriving.
 *
 * The table now answers in both modes. Development additionally runs the
 * interpreter, because the table cannot explain itself - `CONST_ALLOW`/
 * `CONST_DENY` cells are one `kind` byte and `allow` is a raw bitmask, so
 * policy identity is erased at compile time and that erasure *is* the
 * optimisation. So: table for the verdict, interpreter for the provenance, and
 * a throw if they disagree.
 *
 * These tests pin that arrangement rather than any one instance of the bug.
 */

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
    // The table erases policy identity; every one of these comes from the
    // interpreter run alongside it.
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
    // Two evaluators run in development. `onPolicyError` is notification-only -
    // `safeEval` branches on whether the policy carries a deny rule, with or
    // without a handler - so the explanatory run is passed `undefined`. Without
    // that, a handler wired to an alerting pipeline pages twice for one bad
    // policy, in development only.
    const rotten: AccessControl.IPolicy = {
      algorithm: 'first-match',
      id: 'rotten',
      name: 'Rotten',
      rules: [
        {
          actions: ['update'],
          // A `matches` operator over an oversized field throws when the rule
          // runs, which is what routes it to `onPolicyError`.
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
    // Exactly one, not "at most one": a zero here would mean the test stopped
    // exercising the double-fire it exists to pin.
    expect(seen).toEqual(['rotten'])
  })
})

describe('a table/interpreter disagreement is a loud development failure', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doUnmock('../compiled/compiled.lookup')
  })

  /**
   * Reload the engine with `lookup` forced to a fixed verdict, to manufacture a
   * divergence.
   *
   * Split per mode rather than parameterised over it: a `mode` typed as the
   * union widens `TMode`, and `check()`'s development-only `IDecision` return
   * type goes with it.
   */
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
      // The interpreter allows `update post` (the editor role grants it); the
      // forced table denies. That is exactly the shape that used to ship.
      //
      // `authorize()` catches the throw and fails closed, which is the right
      // verdict - but on its own it is a generic `Evaluation error` deny that
      // says nothing. The diagnostic has to survive that, on both channels.
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
      // Production would allow, this development run denies. Under the old
      // split this was the invisible one: dev denied, prod allowed, and nothing
      // said so until it was live.
      expect((await engine.check('user-1', 'delete', { attributes: {}, type: 'post' })).allowed).toBe(false)
      expect(String(error.mock.calls[0]?.[0])).toMatch(/table=allow, interpreter=deny/)
    } finally {
      error.mockRestore()
    }
  })

  it('production does not run the interpreter, so it cannot throw on a disagreement', async () => {
    // Production trusts the table by design: the second evaluator is the cost
    // the fast path exists to avoid. The check is that development catches it
    // first, not that production second-guesses itself.
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
      // Production returns booleans, development returns decisions - same
      // verdict, different amount of provenance attached to it.
      const devEntry = dev[key]
      const devAllowed =
        typeof devEntry === 'object' && devEntry !== null && 'allowed' in devEntry ? devEntry.allowed : devEntry
      expect(devAllowed).toBe(prodAllowed)
    }
  })
})
