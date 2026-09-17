/**
 * `createAuth` is the documented entry point, so anything its config type
 * accepts and its body does not forward is a setting an operator believes they
 * turned on. That failure is silent by construction: the key type-checks, the
 * engine builds, and nothing reports the drop. One instance of it has already
 * been fixed here (idempotency, which fell back to the memory store and made
 * strict refuse to boot). These cases enumerate the surface and check the rest.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import { idempotency } from '~/core/idempotency'
import { MemoryIdempotency } from '~/core/idempotency/idempotency.memory'
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
    events.on('maintenance.off', (p) => {
      seen.push(p)
    })
    const auth = createAuth({ ...base(), events })

    expect(auth.events).not.toBe(events)
    await auth.events.emit('maintenance.off', {})
    expect(seen).toHaveLength(1)
  })

  it('forwards the idempotency store rather than falling back to the memory one', () => {
    // The regression this pins: dropping the key here made strict() refuse to
    // boot production, because the engine had quietly substituted the in-memory
    // implementation that cannot dedupe across instances.
    const store = idempotency(new MemoryIdempotency({ development: true }))
    const auth = createAuth({ ...base(), idempotency: store })
    expect(auth.idempotency).toBe(store)
  })

  it('forwards the session windows and the identity limits', () => {
    const auth = createAuth({
      ...base(),
      identities: { profileMaxBytes: 512 },
      session: { absoluteTtlMs: 120_000, freshnessMs: 1_000, ttlMs: 60_000 },
    })
    expect(auth.cfg.session).toMatchObject({ ttlMs: 60_000 })
    expect(auth.cfg.identities).toMatchObject({ profileMaxBytes: 512 })
  })

  it('forwards the hijack policy', () => {
    const auth = createAuth({ ...base(), hijack: { onIpChange: 'revoke' } })
    expect(auth.cfg.hijack).toMatchObject({ onIpChange: 'revoke' })
  })

  it('registers providers, and skips the falsy entries', () => {
    const auth = createAuth({
      ...base(),
      providers: [passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }), false, null, undefined, ''],
    })
    expect(auth.providers.has('password')).toBe(true)
    expect(auth.providers.list()).toHaveLength(1)
  })

  it('resolves a provider thunk against the constructed engine and the channels bundle', () => {
    const seen: Array<{ channels: unknown; sameEngine: boolean }> = []
    const channels = { email: { id: 'email', send: async () => undefined } as never }
    const auth = createAuth({
      ...base(),
      channels,
      providers: [
        (engine, chans) => {
          seen.push({ channels: chans, sameEngine: engine instanceof Object })
          return passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) })
        },
      ],
    })
    expect(auth.providers.has('password')).toBe(true)
    expect(seen[0]?.channels).toBe(channels)
  })

  it('refuses a plugins array rather than accepting one it cannot install', () => {
    // Installation is async and this factory is not, so the key used to be
    // accepted and dropped: an engine with an empty registry and no error.
    // It now names the call that does work.
    let installed = false
    expect(() =>
      createAuth({
        ...base(),
        plugins: [
          {
            id: 'my-plugin',
            install: async () => {
              installed = true
            },
          } as never,
        ],
      }),
    ).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    expect(installed).toBe(false)
  })

  it('an empty or absent plugins array is not an error', () => {
    expect(() => createAuth({ ...base(), plugins: [] })).not.toThrow()
    expect(() => createAuth(base())).not.toThrow()
  })

  it('a plugin installed through the engine does reach the registry', async () => {
    const auth = createAuth(base())
    await auth.use({ id: 'my-plugin', install: async () => undefined } as never)
    expect(auth.plugins.installed.has('my-plugin')).toBe(true)
  })

  it('refuses an oauth-wide state signing secret it has no way to apply', () => {
    // Each oauth provider takes its own `stateSigningSecret` at construction, so
    // a value set once at the top could never be applied. It used to be accepted
    // and ignored, which left the operator believing state was signed.
    expect(() => createAuth({ ...base(), oauth: { stateSigningSecret: 'top-level-secret' } })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('an oauth block without the secret is not an error', () => {
    expect(() => createAuth({ ...base(), oauth: {} })).not.toThrow()
  })

  it('names a key it does not know rather than accepting the typo', () => {
    // `sessions` for `session` is the one a caller is most likely to write, and accepting it left
    // them believing they had shortened the window it names.
    expect(() => createAuth({ ...base(), sessions: { ttlMs: 1_000 } } as never)).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: expect.stringContaining('"sessions"') },
      }),
    )
  })
})

describe('the defaults it picks when a knob is omitted', () => {
  it('defaults to a secure cookie transport', () => {
    const auth = createAuth(base())
    expect(auth.transport).toBeInstanceOf(CookieTransport)
    expect((auth.transport as CookieTransport).secure).toBe(true)
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
    expect(() => auth.strict({ env: 'production' })).toThrow()
  })
})

describe('the strict flag', () => {
  it('runs at construction and refuses a production config that is not production ready', () => {
    expect(() => createAuth({ ...base(), strict: 'production' })).toThrow()
  })

  it('a development or test env is permissive', () => {
    expect(() => createAuth({ ...base(), strict: 'development' })).not.toThrow()
    expect(() => createAuth({ ...base(), strict: 'test' })).not.toThrow()
  })

  it('follows NODE_ENV when nothing is said, so a production deploy is checked without being asked', () => {
    // The idempotency store is supplied because the engine's own fallback refuses to construct
    // under production, and that error would pass this test without strict having run at all.
    const cfg = (): AuthDefine.Cfg => ({
      ...base(),
      idempotency: idempotency(new MemoryIdempotency({ development: true })),
    })
    vi.stubEnv('NODE_ENV', 'production')
    try {
      expect(() => createAuth(cfg())).toThrow(
        expect.objectContaining({ meta: { detail: expect.stringContaining('production strict() checks failed') } }),
      )
      expect(() => createAuth({ ...cfg(), strict: false })).not.toThrow()
    } finally {
      vi.unstubAllEnvs()
    }
  })

  it('is permissive under a NODE_ENV that names no environment it knows', () => {
    vi.stubEnv('NODE_ENV', 'staging')
    try {
      expect(() => createAuth(base())).not.toThrow()
    } finally {
      vi.unstubAllEnvs()
    }
  })

  it('refuses an env it does not know rather than reading it as truthy', () => {
    // It used to be `if (config.strict)` and then handed straight to `strict({ env })`, so a
    // misspelled environment ran no checks at all under a flag that says it did.
    expect(() => createAuth({ ...base(), strict: 'prod' as never })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('refuses the string "false", which a flag threaded from an environment variable arrives as', () => {
    // `'false'` is a non-empty string, so the truthiness test it used to meet turned strict on.
    // `false` is the way to say no.
    expect(() => createAuth({ ...base(), strict: 'false' as never })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
    expect(() => createAuth({ ...base(), strict: '' as never })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })
})

describe('the store triple', () => {
  it('forwards an org store when one is supplied and tolerates its absence', () => {
    const adapter = new MemoryAdapter()
    const withOrgs = createAuth({ ...base(), stores: { ...stores(), orgs: adapter.orgs } })
    expect(withOrgs.cfg.stores.orgs).toBe(adapter.orgs)
    expect(createAuth(base()).cfg.stores.orgs).toBeUndefined()
  })

  it('names the stores a runtime-assembled config is missing, rather than dereferencing undefined', () => {
    expect(() => createAuth({ baseUrl: 'https://app.test' } as never)).toThrow(
      expect.objectContaining({
        code: 'AUTH_MISCONFIGURED',
        meta: { detail: expect.stringContaining('missing: identities, sessions, credentials') },
      }),
    )
    expect(() => createAuth({ ...base(), stores: { ...stores(), sessions: undefined } } as never)).toThrow(
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
