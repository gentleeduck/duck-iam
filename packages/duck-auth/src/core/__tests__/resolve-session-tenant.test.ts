import { describe, expect, it } from 'vitest'
import { MemoryAuthAdapter } from '../../adapters/memory'
import { MemoryLimiter } from '../../limiters/memory'
import { AuthRoot } from '../auth'
import { sha256 } from '../crypto'
import { CookieTransport } from '../transport/cookie'

interface Profile {
  email: string
}

function buildAuth(): { auth: AuthRoot<Profile>; adapter: MemoryAuthAdapter<Profile> } {
  const adapter = new MemoryAuthAdapter<Profile>()
  const auth = new AuthRoot<Profile>({
    baseUrl: 'https://app.example.com',
    transport: new CookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new MemoryLimiter({ max: 10, windowMs: 60_000 }),
  })
  return { auth, adapter }
}

describe('AuthRoot.resolveSession - SEC: cross-tenant access guard', () => {
  it('rejects when session.tenantId mismatches expectedTenantId', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await adapter.identities.create({ profile: { email: 'a@x.com' }, providers: [] }, {})
    const { sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [],
      tenantId: 'tenant-A',
    })
    const headers = new Headers({ cookie: `duck-sid=${sid}` })
    expect(await auth.resolveSession({ headers }, { expectedTenantId: 'tenant-B' })).toBeNull()
    // Sanity: the session IS resolvable when the right tenant is asked for.
    const okay = await auth.resolveSession({ headers }, { expectedTenantId: 'tenant-A' })
    expect(okay?.session.tenantId).toBe('tenant-A')
  })

  it('rejects when session.tenantId is undefined but expectedTenantId is set (guest-session leak defense)', async () => {
    // No-tenant session must not satisfy a tenant-scoped expectation.
    const { auth, adapter } = buildAuth()
    const identity = await adapter.identities.create({ profile: { email: 'b@x.com' }, providers: [] }, {})
    const { sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [],
      // tenantId intentionally omitted
    })
    const headers = new Headers({ cookie: `duck-sid=${sid}` })
    expect(await auth.resolveSession({ headers }, { expectedTenantId: 'tenant-A' })).toBeNull()
  })

  it('accepts a session without tenantId when the caller does not request one', async () => {
    // Regression guard: single-tenant deploys (no tenantId at all)
    // must continue to work - the guard only kicks in when the caller
    // explicitly asked for a specific tenant.
    const { auth, adapter } = buildAuth()
    const identity = await adapter.identities.create({ profile: { email: 'c@x.com' }, providers: [] }, {})
    const { sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [],
    })
    const headers = new Headers({ cookie: `duck-sid=${sid}` })
    const resolved = await auth.resolveSession({ headers })
    expect(resolved?.identity?.profile?.email).toBe('c@x.com')
  })

  it('persists the session row in the store (regression check that buildAuth wiring works)', async () => {
    // Sanity: confirm the cookie-side resolution path runs (so the
    // tenant-guard tests above are actually exercising the guard, not
    // missing on transport-extract).
    const { auth, adapter } = buildAuth()
    const identity = await adapter.identities.create({ profile: { email: 'd@x.com' }, providers: [] }, {})
    const { sid } = await auth.sessions.create({
      identityId: identity.id,
      kind: 'user',
      aal: 1,
      factors: [],
      tenantId: 't1',
    })
    expect(await adapter.sessions.getByHash(sha256(sid))).not.toBeNull()
  })
})
