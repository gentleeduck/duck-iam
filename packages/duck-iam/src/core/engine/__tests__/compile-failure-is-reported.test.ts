import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

/**
 * A compiled table that cannot be built has two very different causes, and the
 * engine now answers them differently.
 *
 * Too many roles is a capacity limit of one representation, not a bug: the
 * 32-bit grant mask cannot address a 33rd role without aliasing. The
 * interpreter answers the same questions correctly, so the engine falls back to
 * it and warns once. A silent fall would be a performance cliff with no
 * diagnostic, which is the same shape of defect as the dev/prod divergence the
 * unified verdict path exists to remove.
 *
 * Anything else - a malformed policy, say - is a bug. It still fails closed,
 * and it is still reported, because the deny was always correct and only the
 * silence was the problem.
 */
const rolesOf = (n: number): AccessControl.IRole[] =>
  Array.from({ length: n }, (_, i) => ({
    id: `role-${i}`,
    name: `Role ${i}`,
    permissions: [{ action: 'read', resource: 'post' }],
  }))

const engineOf = (roleCount: number, mode: 'development' | 'production' = 'production') =>
  new IamEngine({
    adapter: new IamMemoryAdapter({ assignments: { u1: ['role-0'] }, policies: [], roles: rolesOf(roleCount) }),
    mode,
  })

const spyWarn = () => vi.spyOn(console, 'warn').mockImplementation(() => {})
const spyError = () => vi.spyOn(console, 'error').mockImplementation(() => {})

describe('a role count past the compiled table capacity falls back and says so', () => {
  it('warns once when the first check trips the limit, and still answers the check', async () => {
    const warn = spyWarn()
    try {
      const engine = engineOf(33)
      // role-0 really does grant read/post, and the interpreter says so. The
      // old behaviour - deny every request in the deployment - was the outage
      // this fallback exists to prevent.
      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
      expect(warn).toHaveBeenCalledOnce()
      expect(String(warn.mock.calls[0]?.[0])).toMatch(/32-role limit/)
      expect(String(warn.mock.calls[0]?.[0])).toMatch(/falls back to the interpreter/)
    } finally {
      warn.mockRestore()
    }
  })

  it('does not repeat the line on every subsequent request', async () => {
    const warn = spyWarn()
    try {
      const engine = engineOf(33)
      await engine.can('u1', 'read', { attributes: {}, type: 'post' })
      await engine.can('u1', 'read', { attributes: {}, type: 'post' })
      await engine.can('u1', 'read', { attributes: {}, type: 'post' })
      expect(warn).toHaveBeenCalledOnce()
    } finally {
      warn.mockRestore()
    }
  })

  it('warns once even when concurrent checks trip the limit together', async () => {
    const warn = spyWarn()
    try {
      // The `_roleLimitExceeded` short-circuit only helps checks that arrive
      // after one has already failed. Callers that race in before any of them
      // has caught the throw all reach the catch, so the report needs its own
      // guard. Without one, an over-limit engine under load warns per
      // concurrent request at boot.
      const engine = engineOf(33)
      const resource = { attributes: {}, type: 'post' }
      const verdicts = await Promise.all([
        engine.can('u1', 'read', resource),
        engine.can('u1', 'read', resource),
        engine.can('u1', 'read', resource),
        engine.can('u1', 'read', resource),
      ])
      expect(verdicts).toEqual([true, true, true, true])
      expect(warn).toHaveBeenCalledOnce()
    } finally {
      warn.mockRestore()
    }
  })

  it('does not route the fallback through the total-deny console.error', async () => {
    const warn = spyWarn()
    const error = spyError()
    try {
      await engineOf(33).can('u1', 'read', { attributes: {}, type: 'post' })
      // That message says every request will be denied, which is now false for
      // this cause. Emitting it would send an operator hunting an outage that
      // is not happening.
      expect(error).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
      error.mockRestore()
    }
  })

  it('falls back in development too, so both modes take the same path', async () => {
    const warn = spyWarn()
    try {
      // Built inline rather than through `engineOf`: a helper parameterised
      // over the mode widens `TMode` to a union, and `check()`'s development-only
      // `IDecision` return type goes with it.
      const engine = new IamEngine({
        adapter: new IamMemoryAdapter({ assignments: { u1: ['role-0'] }, policies: [], roles: rolesOf(33) }),
        mode: 'development',
      })
      const decision = await engine.check('u1', 'read', { attributes: {}, type: 'post' })
      expect(decision.allowed).toBe(true)
      expect(warn).toHaveBeenCalledOnce()
    } finally {
      warn.mockRestore()
    }
  })

  // Controls: a table that fits must neither warn nor deny.
  it('stays silent for a role count that fits', async () => {
    const warn = spyWarn()
    const error = spyError()
    try {
      const engine = engineOf(32)
      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(true)
      expect(warn).not.toHaveBeenCalled()
      expect(error).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
      error.mockRestore()
    }
  })
})

describe('every other compile failure still fails closed and is still reported', () => {
  // `rules` missing entirely - the shape the compiler walks, which the type
  // promises and an adapter row cannot guarantee. The cast is the point of the
  // test: it manufactures the value a database or hand-written config can
  // deliver but the type system says is impossible.
  const malformed = (): AccessControl.IPolicy[] => [
    { algorithm: 'deny-overrides', id: 'bad', name: 'bad' } as unknown as AccessControl.IPolicy,
  ]

  const brokenEngine = (hooks?: { onPolicyError?: (err: Error, policyId: string) => void }) =>
    new IamEngine({
      adapter: new IamMemoryAdapter({ assignments: { u1: ['role-0'] }, policies: malformed(), roles: rolesOf(1) }),
      hooks,
      mode: 'production',
    })

  it('denies rather than falling back to the interpreter', async () => {
    const error = spyError()
    try {
      expect(await brokenEngine().can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
    } finally {
      error.mockRestore()
    }
  })

  it('names the offending policy through onPolicyError', async () => {
    const error = spyError()
    const seen: Array<{ id: string; msg: string }> = []
    try {
      await brokenEngine({ onPolicyError: (err, id) => seen.push({ id, msg: err.message }) }).can('u1', 'read', {
        attributes: {},
        type: 'post',
      })
      expect(seen).toHaveLength(1)
      expect(seen[0]?.id).toBe('bad')
      expect(seen[0]?.msg).toMatch(/`rules` is missing or not an array/)
    } finally {
      error.mockRestore()
    }
  })

  it.each([
    [
      'a rule with no `actions`',
      { conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 0, resources: ['post'] },
      /rule "r1": `actions` is not an array/,
    ],
    [
      'a rule with no `resources`',
      { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r1', priority: 0 },
      /rule "r1": `resources` is not an array/,
    ],
    ['a rule that is not an object at all', null, /rule at index 0 is not an object/],
  ])('names the policy and the rule for %s', async (_label, rule, expected) => {
    const error = spyError()
    const seen: Array<{ id: string; msg: string }> = []
    try {
      const engine = new IamEngine({
        adapter: new IamMemoryAdapter({
          assignments: { u1: ['role-0'] },
          policies: [
            { algorithm: 'deny-overrides', id: 'bad', name: 'bad', rules: [rule] } as unknown as AccessControl.IPolicy,
          ],
          roles: rolesOf(1),
        }),
        hooks: {
          onPolicyError: (err, id) => {
            seen.push({ id, msg: err.message })
          },
        },
        mode: 'production',
      })
      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
      expect(seen[0]?.id).toBe('bad')
      expect(seen[0]?.msg).toMatch(expected)
    } finally {
      error.mockRestore()
    }
  })

  it('does not let a throwing onPolicyError hook replace the deny', async () => {
    const error = spyError()
    try {
      const engine = brokenEngine({
        onPolicyError: () => {
          throw new Error('operator hook is buggy')
        },
      })
      expect(await engine.can('u1', 'read', { attributes: {}, type: 'post' })).toBe(false)
    } finally {
      error.mockRestore()
    }
  })
})
