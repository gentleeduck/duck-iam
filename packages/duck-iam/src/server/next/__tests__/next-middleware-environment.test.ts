import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import { createIamNextMiddleware, withIamAccess } from '../index'

// SECURITY: `createIamNextMiddleware` must populate the environment like every other integration, or a deny rule on
// `environment.userAgent`, `.ip` or `.hour` is inert where a Next app guards `/admin`.
type Action = 'read'
type ResourceType = 'admin'
type RoleId = 'staff'

const staffRole: AccessControl.IRole<Action, ResourceType, RoleId> = {
  id: 'staff',
  name: 'Staff',
  permissions: [{ action: 'read', resource: 'admin' }],
}

/** Blocklist polarity: allow, except when the environment says otherwise. */
const blockBots: AccessControl.IPolicy<Action, ResourceType, RoleId> = {
  id: 'p-block-bots',
  name: 'block bots',
  algorithm: 'deny-overrides',
  rules: [
    {
      id: 'r-allow',
      effect: 'allow',
      priority: 1,
      actions: ['read'],
      resources: ['admin'],
      conditions: { all: [] },
    },
    {
      id: 'r-deny-bot',
      effect: 'deny',
      priority: 10,
      actions: ['read'],
      resources: ['admin'],
      conditions: { all: [{ field: 'environment.userAgent', operator: 'matches', value: 'evilbot' }] },
    },
  ],
}

function makeEngine() {
  const adapter = new IamMemoryAdapter<Action, ResourceType, RoleId>({
    roles: [staffRole],
    policies: [blockBots],
    assignments: { 'user-staff': ['staff'] },
  })
  return new IamEngine<Action, ResourceType, RoleId>({ adapter, cacheTTL: 0 })
}

function request(userAgent: string): Request {
  return new Request('https://example.com/admin', { headers: { 'user-agent': userAgent } })
}

describe('createIamNextMiddleware environment', () => {
  it('enforces a deny rule keyed on the environment', async () => {
    const mw = createIamNextMiddleware(makeEngine(), {
      getUserId: () => 'user-staff',
      rules: [{ pattern: '/admin', action: 'read', resource: 'admin' }],
    })
    expect((await mw(request('evilbot/1')))?.status).toBe(403)
  })

  // Control: a user agent the rule does not match, so a middleware that denied everything would fail.
  it('still allows a request the rule does not match', async () => {
    const mw = createIamNextMiddleware(makeEngine(), {
      getUserId: () => 'user-staff',
      rules: [{ pattern: '/admin', action: 'read', resource: 'admin' }],
    })
    expect(await mw(request('Mozilla/5.0'))).toBeNull()
  })

  it('honours an explicit getEnvironment override', async () => {
    const mw = createIamNextMiddleware(makeEngine(), {
      getEnvironment: () => ({ userAgent: 'evilbot/spoofed' }),
      getUserId: () => 'user-staff',
      rules: [{ pattern: '/admin', action: 'read', resource: 'admin' }],
    })
    // The real header is benign; the override is what the engine must see.
    expect((await mw(request('Mozilla/5.0')))?.status).toBe(403)
  })

  // Two exports of one integration must agree on identical input.
  it('agrees with withIamAccess on the same request', async () => {
    const engine = makeEngine()
    const handler = withIamAccess(engine, 'read', 'admin', async () => Response.json({ ok: true }), {
      getUserId: () => 'user-staff',
    })
    const viaWith = await handler(request('evilbot/1'), { params: {} })
    const mw = createIamNextMiddleware(engine, {
      getUserId: () => 'user-staff',
      rules: [{ pattern: '/admin', action: 'read', resource: 'admin' }],
    })
    const viaMiddleware = await mw(request('evilbot/1'))
    expect(viaWith.status).toBe(403)
    expect(viaMiddleware?.status).toBe(403)
  })
})
