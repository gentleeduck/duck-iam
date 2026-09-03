import { describe, expect, it } from 'vitest'
import { IamMemoryAdapter } from '../../../adapters/memory'
import { IamEngine } from '../../../core/engine'
import type { AccessControl } from '../../../core/types'
import { createIamNextMiddleware, withIamAccess } from '../index'

/**
 * `createIamNextMiddleware` passed `undefined` as the request environment while
 * express, hono, nest and next's own `withIamAccess` all populate one. A deny
 * rule keyed on `environment.userAgent` / `.ip` / `.hour` was therefore inert in
 * exactly the integration that guards `/admin` in a Next app, where such a rule
 * is most likely to be the only control.
 */
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

  // Control: the same route, same user, a user agent the rule does not match.
  // Without this the test above would pass on a middleware that denied
  // everything.
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

  // The sibling export in this same module always populated an environment.
  // Two exports of one integration disagreeing on identical input is the
  // inconsistency the fix removes, so pin them together.
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
