import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import type { AccessControl } from '../../types'
import { IamEngine } from '../engine'

// Proves the engine auto-injects `environment.now` so temporal policies work
// without the caller threading a clock through every request.

type Action = 'sendMessages'
type ResourceType = 'message'
type RoleId = 'member'

const NOW = Date.now()
const FUTURE_ISO = new Date(NOW + 60_000).toISOString()
const PAST_ISO = new Date(NOW - 60_000).toISOString()

const memberRole: AccessControl.IRole<Action, ResourceType, RoleId> = {
  id: 'member',
  name: 'Member',
  permissions: [{ action: 'sendMessages', resource: 'message' }],
}

// Mirrors the app's guild `timeoutMute`: deny while `timedOutUntil` is still in
// the future, with an always-true passthrough allow so the policy never blocks
// under the default `and` combine when the member is not timed out.
const timeoutPolicy: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  id: 'timeout-mute',
  name: 'Timeout Mute',
  algorithm: 'deny-overrides',
  targets: { actions: ['sendMessages'] },
  rules: [
    {
      id: 'deny-while-timed-out',
      effect: 'deny',
      priority: 10,
      actions: ['sendMessages'],
      resources: ['*'],
      conditions: {
        all: [{ field: 'subject.attributes.timedOutUntil', operator: 'after', value: '$environment.now' }],
      },
    },
    {
      id: 'passthrough',
      effect: 'allow',
      priority: 1,
      actions: ['sendMessages'],
      resources: ['*'],
      conditions: { all: [{ field: 'subject.attributes.timedOutUntil', operator: 'neq', value: true }] },
    },
  ],
}

function makeEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId>({
    policies: [timeoutPolicy],
    roles: [memberRole],
    assignments: { 'u-future': ['member'], 'u-past': ['member'], 'u-none': ['member'] },
    attributes: {
      'u-future': { timedOutUntil: FUTURE_ISO },
      'u-past': { timedOutUntil: PAST_ISO },
      'u-none': {},
    },
  })
  return new IamEngine<Action, ResourceType, RoleId>({ adapter })
}

describe('engine auto-injects environment.now for temporal policies', () => {
  const msg = { type: 'message' as const, id: 'm-1', attributes: {} }

  it('denies a still-timed-out member without any caller-supplied clock', async () => {
    const engine = makeEngine()
    expect(await engine.can('u-future', 'sendMessages', msg)).toBe(false)
  })

  it('allows a member whose timeout has already expired', async () => {
    const engine = makeEngine()
    expect(await engine.can('u-past', 'sendMessages', msg)).toBe(true)
  })

  it('allows a member who was never timed out', async () => {
    const engine = makeEngine()
    expect(await engine.can('u-none', 'sendMessages', msg)).toBe(true)
  })

  it('lets an explicit environment.now win over the injected clock', async () => {
    const engine = makeEngine()
    // Pin the clock far in the future so u-future's timeout is now in the past.
    const farFuture = { now: Date.parse(FUTURE_ISO) + 60_000 }
    expect(await engine.can('u-future', 'sendMessages', msg, farFuture)).toBe(true)
  })
})
