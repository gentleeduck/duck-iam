import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// Over 32 roles overflows the compiled grant mask: the engine falls back to the interpreter and warns once.
// Any other compile failure is a bug, and it fails closed and is reported.
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
      // role-0 really grants read/post; the fallback answers rather than denying every request.
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
      // Racing checks all reach the catch before `_roleLimitExceeded` is set, so the warning needs its own guard.
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
      // That message says every request is denied, which is false for this cause.
      expect(error).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
      error.mockRestore()
    }
  })

  it('falls back in development too, so both modes take the same path', async () => {
    const warn = spyWarn()
    try {
      // Inline, not `engineOf`: a mode parameter widens `TMode` to a union and loses `check()`'s `IDecision` type.
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
  // `rules` missing: impossible by type but possible from a stored row, which is what the cast manufactures.
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
