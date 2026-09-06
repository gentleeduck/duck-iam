import { describe, expect, it, vi } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

/**
 * Production does not run `evaluateFast` - it runs the compiled table, which
 * carries its own copy of the vote logic. The `failOpen` metric therefore has
 * to be threaded through `abacFlatVote`/`rbacVote`/`evaluateDynamicCell` as
 * well, or the signal an operator alerts on moves in development and stays flat
 * in the mode that actually serves traffic.
 */
type Action = 'read'
type ResourceType = 'doc'
type RoleId = 'reader'

/** Applicable to the request; its only rule's condition does not hold. */
const denyBanned: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'deny-overrides',
  id: 'p-deny-banned',
  name: 'deny banned',
  rules: [
    {
      actions: ['read'],
      conditions: { all: [{ field: 'subject.attributes.tier', operator: 'eq', value: 'banned' }] },
      effect: 'deny',
      id: 'r-deny',
      priority: 1,
      resources: ['doc'],
    },
  ],
}

const allowRule: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  algorithm: 'first-match',
  id: 'p-allow',
  name: 'allow',
  rules: [
    { actions: ['read'], conditions: { all: [] }, effect: 'allow', id: 'r-allow', priority: 1, resources: ['doc'] },
  ],
}

async function check(
  policies: Array<AccessControl.IPolicy<Action, ResourceType, RoleId>>,
  mode: AccessControl.Mode,
): Promise<{ allowed: boolean; failOpen: boolean }> {
  const onMetrics = vi.fn()
  const engine = new IamEngine<Action, ResourceType, RoleId, string, AccessControl.Mode>({
    adapter: new IamMemoryAdapter<Action, ResourceType, RoleId>({
      assignments: { u1: ['reader'] },
      policies,
      roles: [{ id: 'reader', name: 'Reader', permissions: [] }],
    }),
    allowFailOpen: true,
    cacheTTL: 0,
    defaultEffect: 'allow',
    hooks: { onMetrics },
    mode,
  })
  await engine.can('u1', 'read', { attributes: {}, type: 'doc' })
  // Read both off the metrics event: `can()`'s return type is mode-conditional
  // and `mode` is only known at runtime here, and the event's `allowed` is the
  // same verdict. The control below asserts the boolean return directly.
  const event = onMetrics.mock.calls[0]?.[0]
  return { allowed: event?.allowed === true, failOpen: event?.failOpen === true }
}

describe('failOpen metric: development and production agree', () => {
  it.each([
    ['an applicable policy whose rules all evaluated false', [denyBanned], true],
    ['an explicit allow rule', [allowRule], false],
    ['the defaulting policy alongside an explicit allow', [denyBanned, allowRule], true],
    ['no policies at all', [], true],
  ] as const)('%s', async (_name, policies, expected) => {
    const dev = await check([...policies], 'development')
    const prod = await check([...policies], 'production')
    expect(dev.allowed).toBe(true)
    expect(prod.allowed).toBe(true)
    expect(dev.failOpen).toBe(expected)
    expect(prod.failOpen).toBe(expected)
  })

  // Control: with `defaultEffect: 'deny'` there is no fallback allow to report,
  // so nothing above can be passing because the flag is simply always set.
  it('control: never raised when the fallback is a deny', async () => {
    const onMetrics = vi.fn()
    const engine = new IamEngine<Action, ResourceType, RoleId>({
      adapter: new IamMemoryAdapter<Action, ResourceType, RoleId>({
        assignments: { u1: ['reader'] },
        policies: [denyBanned],
        roles: [{ id: 'reader', name: 'Reader', permissions: [] }],
      }),
      cacheTTL: 0,
      defaultEffect: 'deny',
      hooks: { onMetrics },
    })
    expect(await engine.can('u1', 'read', { attributes: {}, type: 'doc' })).toBe(false)
    expect(onMetrics.mock.calls[0]?.[0].failOpen).toBe(false)
  })
})
