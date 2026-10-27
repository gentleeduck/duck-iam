/**
 * `createAuth` is the documented entry point, so anything its config type
 * accepts and its body does not forward is a setting an operator believes they
 * turned on. That failure is silent by construction: the key type-checks, the
 * engine builds, and nothing reports the drop. These cases enumerate the surface.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { JwtTransport } from '~/core/transport/jwt.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { createAuth } from '../config'
import type { AuthDefine } from '../config.types'

const stores = () => {
  const adapter = new MemoryAdapter()
  return { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions }
}

const base = (): AuthDefine.Cfg => ({ baseUrl: 'https://app.test', stores: stores() })

describe('every knob the config type accepts reaches the engine', () => {
  it('forwards the stores, the transport, the limiter and the bus', () => {
    const transport = new JwtTransport({
      issuer: 'https://app.test',
      signKey: { key: 'secret-32-bytes-of-test-material', kid: 'k1' },
      ttlMs: 60_000,
      verifyKeys: [{ key: 'secret-32-bytes-of-test-material', kid: 'k1' }],
    })
    const events = new InMemoryEvents()
    const limiter = new MemoryLimiter()
    const auth = createAuth({ ...base(), events, limiter, transport })

    expect(auth.transport).toBe(transport)
    expect(auth.cfg.limiter).toBe(limiter)
  })

  it('wraps the supplied bus in the audit stamper rather than holding it directly', async () => {
    // Worth pinning: `auth.events` is not the object that was passed in, so a
    // caller comparing identities sees a different bus. Emissions still reach the
    // listeners registered on the original.
    const events = new InMemoryEvents()
    const seen: unknown[] = []
    events.on('authz.revoked', (p) => {
      seen.push(p)
    })
    const auth = createAuth({ ...base(), events })

    expect(auth.events).not.toBe(events)
    await auth.events.emit('authz.revoked', { at: 0, identityId: 'u' })
    expect(seen).toHaveLength(1)
  })

  it('forwards the session windows and the identity limits to the facets that enforce them', async () => {
    const auth = createAuth({
      ...base(),
      identities: { profileMaxBytes: 512 },
      session: { absoluteTtlMs: 120_000, freshnessMs: 1_000, ttlMs: 60_000 },
    })
    const { session } = await auth.sessions.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
    expect(session.expiresAt.getTime() - session.createdAt.getTime()).toBe(60_000)
    expect(session.absoluteExpiresAt.getTime() - session.createdAt.getTime()).toBe(120_000)
    await expect(
      auth.identities.create({ profile: { bio: 'x'.repeat(600), email: 'a@x.test', username: 'a' } }),
    ).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })

  it.each([
    ['the engine', (auth: ReturnType<typeof createAuth>) => auth],
    ['a transaction', (auth: ReturnType<typeof createAuth>) => auth.withTransaction({})],
  ])('caps the sessions one identity holds, on %s', async (_, scope) => {
    const mintThree = async (session: AuthDefine.Cfg['session']) => {
      const s = stores()
      const auth = createAuth({ ...base(), session, stores: { ...s, withClient: () => s } })
      const ids: string[] = []
      for (let i = 0; i < 3; i++) {
        const minted = await scope(auth).sessions.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
        ids.push(minted.session.id)
      }
      const held = await auth.sessions.listForIdentity('user-1')
      return { held: held.map((h) => h.id).sort(), ids }
    }
    const capped = await mintThree({ maxSessionsPerIdentity: 2 })
    expect(capped.held).toEqual(capped.ids.slice(1).sort())
    const uncapped = await mintThree(undefined)
    expect(uncapped.held).toEqual([...uncapped.ids].sort())
  })

  it('refuses a window or a limit that a variable left unset turned into NaN', () => {
    for (const cfg of [{ session: { ttlMs: Number.NaN } }, { identities: { profileMaxBytes: Number.NaN } }]) {
      expect(() => createAuth({ ...base(), ...cfg }), Object.keys(cfg)[0]).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('forwards the hijack policy', () => {
    const auth = createAuth({ ...base(), hijack: { onIpChange: 'revoke' } })
    expect(auth.cfg.hijack).toMatchObject({ onIpChange: 'revoke' })
  })

  it('applies a compliance preset: its session windows, and its checks at strict()', async () => {
    const auth = createAuth({ ...base(), compliance: 'hipaa', strict: false })
    const { session } = await auth.sessions.create({ aal: 1, factors: [], identityId: 'user-1', kind: 'user' })
    expect(session.expiresAt.getTime() - session.createdAt.getTime()).toBe(60 * 60 * 1000)
    expect(() => auth.strict()).toThrow(
      expect.objectContaining({ meta: { detail: expect.stringContaining('mfa provider') } }),
    )
    expect(() => createAuth({ ...base(), strict: false }).strict()).not.toThrow()
  })

  it('registers providers, and skips the falsy entries', () => {
    const auth = createAuth({
      ...base(),
      providers: [passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }), false, null, undefined, ''],
    })
    expect(auth.providers.has('password')).toBe(true)
    expect(auth.providers.list()).toHaveLength(1)
  })

  it('resolves a provider thunk against the constructed engine and the host deliver', () => {
    const seen: Array<{ deliver: unknown; sameEngine: boolean }> = []
    const deliver = async (): Promise<void> => {}
    const auth = createAuth({
      ...base(),
      deliver,
      providers: [
        (engine, send) => {
          seen.push({ deliver: send, sameEngine: engine instanceof Object })
          return passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) })
        },
      ],
    })
    expect(auth.providers.has('password')).toBe(true)
    expect(seen[0]?.deliver).toBe(deliver)
  })

  it.each([
    ['plugins', '[]'],
    ['plugins', '[{"id":"my-plugin"}]'],
    ['oauth', '{}'],
    ['oauth', '{"stateSigningSecret":"top-level-secret"}'],
  ])('refuses %s: %s, which it has no way to apply', (key, value) => {
    // Plugin installation is async and this factory is not, and each oauth provider takes its own
    // state secret at construction. Both keys were typed as accepted and then refused or dropped.
    expect(() => createAuth({ ...base(), [key]: JSON.parse(value) })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED', meta: { detail: expect.stringContaining(`"${key}"`) } }),
    )
  })

  it('a plugin installed through the engine does reach the registry', async () => {
    const auth = createAuth(base())
    await auth.use({ id: 'my-plugin', install: async () => undefined })
    expect(auth.plugins.installed.has('my-plugin')).toBe(true)
  })

  it('names a key it does not know rather than accepting the typo', () => {
    // `sessions` for `session` is the one a caller is most likely to write, and accepting it left
    // them believing they had shortened the window it names.
    // @ts-expect-error `sessions` is not a key of the config
    expect(() => createAuth({ ...base(), sessions: { ttlMs: 1_000 } })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: expect.stringContaining('"sessions"') },
      }),
    )
  })
})

describe('the defaults it picks when a knob is omitted', () => {
  it('defaults to a __Host-duck-sid cookie in production, which no subdomain can set', () => {
    vi.stubEnv('NODE_ENV', 'production')
    const auth = createAuth({ ...base(), strict: false })
    expect(auth.transport).toBeInstanceOf(CookieTransport)
    const [sid] = auth.transport.revoke()
    expect(sid).toMatchObject({ name: '__Host-duck-sid', options: { path: '/', secure: true } })
    expect(sid).not.toHaveProperty('options.domain')
  })

  it('drops the prefix with Secure outside production, so the default cookie is duck-sid', () => {
    vi.stubEnv('NODE_ENV', 'development')
    const [sid] = createAuth(base()).transport.revoke()
    expect(sid).toMatchObject({ name: 'duck-sid', options: { secure: false } })
  })

  it('builds without a limiter, an events bus or any provider', () => {
    const auth = createAuth(base())
    expect(auth.providers.list()).toEqual([])
    expect(auth.events).toBeDefined()
  })

  it('falls back to an in-process limiter, which production refuses', () => {
    // Not "no throttle": the engine defaults to a MemoryLimiter, so sign-in is limited per process.
    // What production refuses is that it is per process, and `cfg.limiter` staying undefined is how
    // strict tells a default apart from a limiter the operator chose.
    const auth = createAuth(base())
    expect(auth.cfg.limiter).toBeUndefined()
    expect(auth.limiter).toBeInstanceOf(MemoryLimiter)
    vi.stubEnv('NODE_ENV', 'production')
    expect(() => auth.strict()).toThrow(
      expect.objectContaining({ meta: { detail: expect.stringContaining('Limiter adapter required') } }),
    )
  })
})

describe('the strict checks createAuth runs, which follow NODE_ENV', () => {
  const failed = expect.objectContaining({
    meta: { detail: expect.stringContaining('production strict() checks failed') },
  })

  it.each(['production', undefined, '', 'staging'])('runs the production checks with NODE_ENV=%o', (env) => {
    vi.stubEnv('NODE_ENV', env)
    expect(() => createAuth(base())).toThrow(failed)
  })

  it.each(['development', 'test'])('runs none of them with NODE_ENV=%s', (env) => {
    vi.stubEnv('NODE_ENV', env)
    expect(() => createAuth(base())).not.toThrow()
  })

  it('defers them on `strict: false`, to the auth.strict() an app calls once its listeners exist', () => {
    vi.stubEnv('NODE_ENV', 'production')
    const auth = createAuth({ ...base(), strict: false })
    expect(() => auth.strict()).toThrow(failed)
  })

  it.each(['production', 'development', 'test', true, 'false', ''])(
    'refuses strict: %o, since only false means anything',
    (strict) => {
      expect(() => createAuth(Object.assign(base(), { strict }))).toThrow(
        expect.objectContaining({
          code: 'AUTH_MISCONFIGURED',
          meta: {
            detail: `strict takes only false, to defer the checks to auth.strict(); got ${JSON.stringify(strict)}`,
          },
        }),
      )
    },
  )
})

describe('the store triple', () => {
  it('forwards an org store when one is supplied and tolerates its absence', () => {
    const adapter = new MemoryAdapter()
    const withOrgs = createAuth({ ...base(), stores: { ...stores(), orgs: adapter.orgs } })
    expect(withOrgs.cfg.stores.orgs).toBe(adapter.orgs)
    expect(createAuth(base()).cfg.stores.orgs).toBeUndefined()
  })

  it('names the stores a runtime-assembled config is missing, rather than dereferencing undefined', () => {
    // @ts-expect-error no stores
    expect(() => createAuth({ baseUrl: 'https://app.test' })).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: expect.stringContaining('missing: identities, sessions, credentials') },
      }),
    )
    // @ts-expect-error no session store
    expect(() => createAuth({ ...base(), stores: { ...stores(), sessions: undefined } })).toThrow(
      expect.objectContaining({ meta: { detail: expect.stringContaining('missing: sessions') } }),
    )
  })

  it('refuses a base url that is not an absolute http(s) origin, and drops the trailing slash', () => {
    // It is the origin every redirect and cookie decision is measured against, so it is parsed here
    // rather than by each facet that compares against it.
    for (const baseUrl of ['', 'app.test', 'javascript:alert(1)', '//app.test']) {
      expect(() => createAuth({ ...base(), baseUrl })).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
    expect(createAuth({ ...base(), baseUrl: 'https://app.test/' }).cfg.baseUrl).toBe('https://app.test')
  })
})
